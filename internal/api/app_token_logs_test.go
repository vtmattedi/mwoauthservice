package api

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/vtmattedi/mw-oauth-service/internal/domain"
)

// captureLogs sends both the standard logger and slog to one buffer.
func captureLogs(t *testing.T) *bytes.Buffer {
	t.Helper()

	var buf bytes.Buffer
	oldWriter, oldFlags := log.Writer(), log.Flags()
	oldDefault := slog.Default()

	log.SetOutput(&buf)
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))

	t.Cleanup(func() {
		log.SetOutput(oldWriter)
		log.SetFlags(oldFlags)
		slog.SetDefault(oldDefault)
	})
	return &buf
}

func auditAll() domain.AuditFilters { return domain.AuditFilters{Limit: 200} }

// tokenFixtureRequest calls the token endpoint through the fixture's router
// and returns the issued access token, or "" when the request was rejected.
func tokenFixtureRequest(t *testing.T, f authzFixture, clientID, secret string) string {
	t.Helper()

	req := httptest.NewRequest(http.MethodPost, "/v1/auth/token",
		strings.NewReader("grant_type=client_credentials"))
	req.Header.Set("Authorization", basic(clientID, secret))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res := httptest.NewRecorder()
	f.handler.ServeHTTP(res, req)

	if res.Code != http.StatusOK {
		return ""
	}
	var body tokenResponse
	if err := json.Unmarshal(res.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	return body.AccessToken
}

func TestCredentialsNeverAppearInLogsOrAudit(t *testing.T) {
	logs := captureLogs(t)
	f := newAuthzFixture(t, true)

	secret := f.client.ClientSecret
	clientID := f.client.Client.ClientID
	wrongSecret := "mw_cs_this-is-a-wrong-secret-value"

	tokenRes := tokenFixtureRequest(t, f, clientID, secret)
	issued := tokenRes

	tokenFixtureRequest(t, f, clientID, wrongSecret) // rejected

	// Authorize with a good token, a bad token, a refresh-only token and the
	// legacy key.
	f.authorize(t, issued)
	f.authorize(t, "mw_at_bad-token-value")
	f.authorize(t, f.token(t, "google.refresh"))
	f.authorize(t, f.legacy)
	f.authorize(t, "mw_live_wrong-legacy-key")

	secrets := map[string]string{
		"client secret":  secret,
		"wrong secret":   wrongSecret,
		"issued token":   issued,
		"bad token":      "bad-token-value",
		"legacy key":     f.legacy,
		"wrong legacy":   "wrong-legacy-key",
		"basic header":   basic(clientID, secret)[len("Basic "):],
		"basic (wrong)":  basic(clientID, wrongSecret)[len("Basic "):],
		"bearer literal": "Bearer " + issued,
	}

	page, err := f.audit.List(context.Background(), auditAll())
	if err != nil {
		t.Fatal(err)
	}
	var auditText strings.Builder
	for _, e := range page.Items {
		auditText.WriteString(e.EventType + e.ReasonCode)
		for k, v := range e.Metadata {
			auditText.WriteString(k)
			if s, ok := v.(string); ok {
				auditText.WriteString(s)
			}
		}
	}

	if logs.Len() == 0 {
		t.Fatal("expected request logs to be captured")
	}
	for name, value := range secrets {
		if strings.Contains(logs.String(), value) {
			t.Fatalf("logs contain the %s", name)
		}
		if strings.Contains(auditText.String(), value) {
			t.Fatalf("audit data contains the %s", name)
		}
	}
}
