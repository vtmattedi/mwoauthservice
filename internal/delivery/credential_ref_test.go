package delivery

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/vtmattedi/mw-oauth-service/internal/domain"
	"github.com/vtmattedi/mw-oauth-service/internal/oauth"
)

// deliverAndCapture delivers one transaction and returns the raw signed body
// plus the headers the project received.
func deliverAndCapture(
	t *testing.T,
	credentialID string,
) (body []byte, header http.Header, callbackSecret string) {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		body = raw
		header = r.Header.Clone()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	projectService, projectRow, secret := newDeliveryTestProject(t)

	deliverer, err := NewSignedDeliverer(projectService, Options{
		HTTPClient: server.Client(),
		Now:        func() time.Time { return time.Unix(1786570000, 0).UTC() },
		Sleep:      func(context.Context, time.Duration) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := deliverer.Deliver(
		context.Background(),
		domain.OAuthTransaction{
			ID:                  "oauth_txn_ref",
			ProjectID:           projectRow.ID,
			Provider:            "google",
			ClientReference:     "client-ref",
			CallbackURL:         server.URL,
			RequestedScopesJSON: `["scope-a"]`,
			GoogleCredentialID:  credentialID,
		},
		oauth.TokenSet{AccessToken: "access", RefreshToken: "refresh", TokenType: "Bearer", ExpiresIn: 3599},
	); err != nil {
		t.Fatal(err)
	}

	return body, header, secret
}

func TestSignedPayloadCarriesCredentialRefForPerProjectClients(t *testing.T) {
	body, header, secret := deliverAndCapture(t, "gcred_example")

	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatal(err)
	}
	if payload["credential_ref"] != "gcred_example" {
		t.Fatalf("credential_ref = %v", payload["credential_ref"])
	}

	// credential_ref is covered by the signature, so it cannot be swapped.
	want := "v1=" + signatureHex([]byte(secret), header.Get("X-MW-Webhook-Id"), header.Get("X-MW-Timestamp"), body)
	if header.Get("X-MW-Signature") != want {
		t.Fatal("signature does not cover the payload including credential_ref")
	}
	tampered := strings.Replace(string(body), "gcred_example", "gcred_attacker", 1)
	if header.Get("X-MW-Signature") == "v1="+signatureHex([]byte(secret), header.Get("X-MW-Webhook-Id"), header.Get("X-MW-Timestamp"), []byte(tampered)) {
		t.Fatal("a swapped credential_ref must invalidate the signature")
	}
}

func TestSignedPayloadAlwaysCarriesCredentialRefAndKeepsV1Fields(t *testing.T) {
	body, header, secret := deliverAndCapture(t, "gcred_abc123")

	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatal(err)
	}
	if payload["credential_ref"] != "gcred_abc123" {
		t.Fatalf("credential_ref = %v", payload["credential_ref"])
	}

	// The documented v1 fields and the signature format are untouched.
	for _, field := range []string{"event", "transaction_id", "client_reference", "provider", "token"} {
		if _, ok := payload[field]; !ok {
			t.Fatalf("missing v1 field %q", field)
		}
	}
	if !strings.HasPrefix(header.Get("X-MW-Signature"), "v1=") {
		t.Fatalf("signature header = %q", header.Get("X-MW-Signature"))
	}
	want := "v1=" + signatureHex([]byte(secret), header.Get("X-MW-Webhook-Id"), header.Get("X-MW-Timestamp"), body)
	if header.Get("X-MW-Signature") != want {
		t.Fatal("signature input (delivery_id.timestamp.raw_body) must stay unchanged")
	}
}
