package delivery

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vtmattedi/mw-oauth-service/internal/domain"
	"github.com/vtmattedi/mw-oauth-service/internal/oauth"
	"github.com/vtmattedi/mw-oauth-service/internal/project"
	"github.com/vtmattedi/mw-oauth-service/internal/secretbox"
	"github.com/vtmattedi/mw-oauth-service/internal/store/sqlite"
)

func TestSignedDeliveryRetriesWithStableWebhookIdentity(t *testing.T) {
	var mu sync.Mutex
	attempts := 0
	var bodies [][]byte
	var webhookIDs []string
	var timestamps []string
	var signatures []string

	var callbackSecret string

	server := httptest.NewServer(
		http.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Fatal(err)
				}

				mu.Lock()
				defer mu.Unlock()

				attempts++
				bodies = append(bodies, append([]byte(nil), body...))
				webhookIDs = append(
					webhookIDs,
					r.Header.Get("X-MW-Webhook-Id"),
				)
				timestamps = append(
					timestamps,
					r.Header.Get("X-MW-Timestamp"),
				)
				signatures = append(
					signatures,
					r.Header.Get("X-MW-Signature"),
				)

				if attempts < 3 {
					w.WriteHeader(http.StatusBadGateway)
					return
				}

				secret := []byte(callbackSecret)
				expected := "v1=" + signatureHex(
					secret,
					webhookIDs[len(webhookIDs)-1],
					timestamps[len(timestamps)-1],
					body,
				)
				clearBytes(secret)

				if signatures[len(signatures)-1] != expected {
					t.Fatalf(
						"signature = %q; want %q",
						signatures[len(signatures)-1],
						expected,
					)
				}

				w.WriteHeader(http.StatusNoContent)
			},
		),
	)
	defer server.Close()

	projectService, projectRow, secret := newDeliveryTestProject(t)
	callbackSecret = secret

	deliverer, err := NewSignedDeliverer(
		projectService,
		Options{
			HTTPClient: server.Client(),
			Now: func() time.Time {
				return time.Unix(1786570000, 0).UTC()
			},
			Sleep: func(
				ctx context.Context,
				delay time.Duration,
			) error {
				return nil
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	err = deliverer.Deliver(
		context.Background(),
		domain.OAuthTransaction{
			ID:                  "oauth_txn_test",
			ProjectID:           projectRow.ID,
			Provider:            "google",
			ClientReference:     "oauth_pending_test",
			CallbackURL:         server.URL,
			RequestedScopesJSON: `["scope-a","scope-b"]`,
		},
		oauth.TokenSet{
			AccessToken:  "access-token",
			RefreshToken: "refresh-token",
			TokenType:    "Bearer",
			ExpiresIn:    3599,
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	mu.Lock()
	defer mu.Unlock()

	if attempts != 3 {
		t.Fatalf("attempts = %d; want 3", attempts)
	}

	for i := 1; i < len(bodies); i++ {
		if !bytes.Equal(bodies[0], bodies[i]) {
			t.Fatal("retry body changed")
		}
		if webhookIDs[0] != webhookIDs[i] {
			t.Fatal("webhook id changed across retries")
		}
		if timestamps[0] != timestamps[i] {
			t.Fatal("timestamp changed across retries")
		}
		if signatures[0] != signatures[i] {
			t.Fatal("signature changed across retries")
		}
	}

	var payload successPayload
	if err := json.Unmarshal(bodies[0], &payload); err != nil {
		t.Fatal(err)
	}

	if payload.Event != "oauth.authorization.completed" {
		t.Fatalf("event = %q", payload.Event)
	}
	if payload.Token.AccessToken != "access-token" {
		t.Fatal("missing access token in callback payload")
	}
	if payload.Token.RefreshToken != "refresh-token" {
		t.Fatal("missing refresh token in callback payload")
	}
	if len(payload.Token.Scope) != 2 {
		t.Fatalf(
			"scope count = %d; want 2",
			len(payload.Token.Scope),
		)
	}
}

func TestSignedDeliveryNeverFollowsRedirect(t *testing.T) {
	redirected := false

	target := httptest.NewServer(
		http.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				redirected = true
				w.WriteHeader(http.StatusNoContent)
			},
		),
	)
	defer target.Close()

	source := httptest.NewServer(
		http.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(
					w,
					r,
					target.URL,
					http.StatusFound,
				)
			},
		),
	)
	defer source.Close()

	projectService, projectRow, _ := newDeliveryTestProject(t)

	deliverer, err := NewSignedDeliverer(
		projectService,
		Options{
			HTTPClient: source.Client(),
			Sleep: func(
				ctx context.Context,
				delay time.Duration,
			) error {
				return nil
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	err = deliverer.Deliver(
		context.Background(),
		domain.OAuthTransaction{
			ID:                  "oauth_txn_redirect",
			ProjectID:           projectRow.ID,
			Provider:            "google",
			ClientReference:     "ref",
			CallbackURL:         source.URL,
			RequestedScopesJSON: `["scope"]`,
		},
		oauth.TokenSet{
			AccessToken: "access",
		},
	)
	if err == nil {
		t.Fatal("expected redirect delivery to fail")
	}

	if redirected {
		t.Fatal(
			"HTTP client followed callback redirect and leaked the request",
		)
	}

	deliveryErr, ok := err.(*DeliveryError)
	if !ok {
		t.Fatalf("error type = %T", err)
	}
	if deliveryErr.Attempts != 3 {
		t.Fatalf(
			"attempts = %d; want 3",
			deliveryErr.Attempts,
		)
	}
	if deliveryErr.LastStatus != http.StatusFound {
		t.Fatalf(
			"last status = %d; want 302",
			deliveryErr.LastStatus,
		)
	}
}

func TestSignatureCanonicalFormat(t *testing.T) {
	secret := []byte("secret")
	webhookID := "oauth_delivery_123"
	timestamp := "1786570000"
	body := []byte(`{"hello":"world"}`)

	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write(
		[]byte(
			webhookID +
				"." +
				timestamp +
				"." +
				string(body),
		),
	)
	expected := hex.EncodeToString(mac.Sum(nil))

	actual := signatureHex(
		secret,
		webhookID,
		timestamp,
		body,
	)

	if actual != expected {
		t.Fatalf(
			"signature = %q; want %q",
			actual,
			expected,
		)
	}
}

func newDeliveryTestProject(
	t *testing.T,
) (
	*project.Service,
	domain.Project,
	string,
) {
	t.Helper()

	store, err := sqlite.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = store.Close()
	})

	key := bytes.Repeat([]byte{0x4A}, 32)
	encoded := base64.RawURLEncoding.EncodeToString(key)

	keyring, err := secretbox.NewKeyring(
		"1:"+encoded,
		1,
	)
	if err != nil {
		t.Fatal(err)
	}

	service := project.NewService(store, keyring)

	credentials, err := service.Create(
		context.Background(),
		"Delivery Test "+strings.ReplaceAll(
			t.Name(),
			"/",
			"-",
		),
		true,
	)
	if err != nil {
		t.Fatal(err)
	}

	return service, credentials.Project, credentials.CallbackSecret
}
