package appauth_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vtmattedi/mw-oauth-service/internal/appauth"
	"github.com/vtmattedi/mw-oauth-service/internal/project"
	"github.com/vtmattedi/mw-oauth-service/internal/store/sqlite"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

type fixture struct {
	store *sqlite.Store
	svc   *appauth.Service
	clock *clock
	p1    int64
	p2    int64
}

func newFixture(t *testing.T) fixture {
	t.Helper()

	store, err := sqlite.Open(filepath.Join(t.TempDir(), "oauth.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	ids := make([]int64, 2)
	for i := range ids {
		p, err := store.CreateProject(context.Background(), project.CreateRecord{
			Name: fmt.Sprintf("app-%d", i), Enabled: true,
			CallbackSecretCiphertext: "c",
			CallbackSecretNonce:      "n", CallbackSecretKeyVersion: 1,
		})
		if err != nil {
			t.Fatal(err)
		}
		ids[i] = p.ID
	}

	clk := &clock{t: time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)}
	return fixture{
		store: store,
		svc:   appauth.NewService(store, 0).WithClock(clk.Now),
		clock: clk,
		p1:    ids[0],
		p2:    ids[1],
	}
}

func (f fixture) create(t *testing.T, project int64) appauth.CreatedClient {
	t.Helper()
	created, err := f.svc.CreateClient(context.Background(), project, "Worker", nil)
	if err != nil {
		t.Fatal(err)
	}
	return created
}

func (f fixture) token(t *testing.T, c appauth.CreatedClient, scopes ...string) appauth.Token {
	t.Helper()
	tok, err := f.svc.IssueToken(context.Background(), c.Client.ClientID, c.ClientSecret, scopes)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// ---- P2.2: client and secret lifecycle ----

func TestCreateClientReturnsSecretOnceAndStoresOnlyHash(t *testing.T) {
	f := newFixture(t)
	created := f.create(t, f.p1)

	if !strings.HasPrefix(created.Client.ClientID, appauth.ClientIDPrefix) ||
		!strings.HasPrefix(created.ClientSecret, appauth.SecretPrefix) {
		t.Fatalf("unexpected identifiers: %q %q", created.Client.ClientID, created.ClientSecret)
	}
	// >= 32 random bytes encoded as base64url (43 chars) after the prefix.
	if len(created.ClientSecret)-len(appauth.SecretPrefix) < 43 {
		t.Fatalf("secret too short: %d", len(created.ClientSecret))
	}
	if created.Client.DisplayName != "Worker" || !created.Client.Enabled || len(created.Client.Secrets) != 1 {
		t.Fatalf("unexpected client: %+v", created.Client)
	}
	if got := strings.Join(created.Client.AllowedScopes, " "); got != "google.authorize google.refresh" {
		t.Fatalf("default scopes = %q", got)
	}

	// The raw secret appears nowhere in what we can read back.
	read, err := f.svc.Get(context.Background(), f.p1)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(read)
	if strings.Contains(string(encoded), created.ClientSecret) {
		t.Fatalf("metadata leaks secret: %s", encoded)
	}

	var stored string
	if err := f.store.DB().QueryRow(
		`SELECT secret_hash FROM mw_application_client_secrets`,
	).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored == created.ClientSecret || stored != appauth.HashSecret(created.ClientSecret) || len(stored) != 64 {
		t.Fatalf("stored value is not the hash: %q", stored)
	}
}

func TestCreateClientRules(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	f.create(t, f.p1)
	if _, err := f.svc.CreateClient(ctx, f.p1, "again", nil); !errors.Is(err, appauth.ErrConflict) {
		t.Fatalf("second client: %v", err)
	}
	if _, err := f.svc.CreateClient(ctx, 9999, "x", nil); !errors.Is(err, appauth.ErrNotFound) {
		t.Fatalf("unknown project: %v", err)
	}
	if _, err := f.svc.CreateClient(ctx, f.p2, "x", []string{"admin.everything"}); !errors.Is(err, appauth.ErrValidation) {
		t.Fatalf("unknown scope: %v", err)
	}
	if _, err := f.svc.CreateClient(ctx, f.p2, strings.Repeat("n", 161), nil); !errors.Is(err, appauth.ErrValidation) {
		t.Fatalf("long name: %v", err)
	}
	if _, err := f.svc.CreateClient(ctx, f.p2, "bad\x00name", nil); !errors.Is(err, appauth.ErrValidation) {
		t.Fatalf("control chars: %v", err)
	}
	if _, err := f.svc.Get(ctx, f.p2); !errors.Is(err, appauth.ErrNotFound) {
		t.Fatalf("failed creates must not leave a client: %v", err)
	}

	limited, err := f.svc.CreateClient(ctx, f.p2, "limited", []string{appauth.ScopeGoogleAuthorize, appauth.ScopeGoogleAuthorize})
	if err != nil || len(limited.Client.AllowedScopes) != 1 {
		t.Fatalf("limited client: %+v, %v", limited.Client, err)
	}
}

func TestSecretRotationWithBoundedOverlap(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	c := f.create(t, f.p1)

	added, err := f.svc.AddSecret(ctx, f.p1)
	if err != nil || added.ClientSecret == "" || added.ClientSecret == c.ClientSecret {
		t.Fatalf("add secret: %+v, %v", added, err)
	}

	// Both secrets work during the overlap window.
	for name, secret := range map[string]string{"old": c.ClientSecret, "new": added.ClientSecret} {
		if _, err := f.svc.IssueToken(ctx, c.Client.ClientID, secret, nil); err != nil {
			t.Fatalf("%s secret during overlap: %v", name, err)
		}
	}

	// A third active secret is refused.
	if _, err := f.svc.AddSecret(ctx, f.p1); !errors.Is(err, appauth.ErrTooManySecrets) {
		t.Fatalf("third secret: %v", err)
	}

	// Revoking the old one immediately stops it; the new one keeps working.
	if _, err := f.svc.RevokeSecret(ctx, f.p1, c.Client.Secrets[0].ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.IssueToken(ctx, c.Client.ClientID, c.ClientSecret, nil); !errors.Is(err, appauth.ErrInvalidClient) {
		t.Fatalf("revoked secret: %v", err)
	}
	if _, err := f.svc.IssueToken(ctx, c.Client.ClientID, added.ClientSecret, nil); err != nil {
		t.Fatalf("new secret after revoke: %v", err)
	}

	// Room for another rotation again.
	if _, err := f.svc.AddSecret(ctx, f.p1); err != nil {
		t.Fatalf("add after revoke: %v", err)
	}

	read, _ := f.svc.Get(ctx, f.p1)
	active, revoked := 0, 0
	for _, s := range read.Secrets {
		switch s.State {
		case appauth.SecretStateActive:
			active++
		case appauth.SecretStateRevoked:
			revoked++
			if s.RevokedAt == "" {
				t.Fatal("revoked secret needs a timestamp")
			}
		}
	}
	if active != 2 || revoked != 1 {
		t.Fatalf("active=%d revoked=%d", active, revoked)
	}
}

func TestRevokeSecretIsIdempotentAndProjectScoped(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	c1 := f.create(t, f.p1)
	f.create(t, f.p2)

	// Another project cannot revoke this project's secret.
	if _, err := f.svc.RevokeSecret(ctx, f.p2, c1.Client.Secrets[0].ID); !errors.Is(err, appauth.ErrNotFound) {
		t.Fatalf("cross-project revoke: %v", err)
	}
	if _, err := f.svc.IssueToken(ctx, c1.Client.ClientID, c1.ClientSecret, nil); err != nil {
		t.Fatalf("secret must be untouched: %v", err)
	}

	first, err := f.svc.RevokeSecret(ctx, f.p1, c1.Client.Secrets[0].ID)
	if err != nil || first.State != appauth.SecretStateRevoked {
		t.Fatalf("revoke: %+v, %v", first, err)
	}
	second, err := f.svc.RevokeSecret(ctx, f.p1, c1.Client.Secrets[0].ID)
	if err != nil || second.RevokedAt != first.RevokedAt {
		t.Fatalf("second revoke: %+v, %v", second, err)
	}

	if _, err := f.svc.RevokeSecret(ctx, f.p1, 99999); !errors.Is(err, appauth.ErrNotFound) {
		t.Fatalf("unknown secret: %v", err)
	}
	if _, err := f.svc.AddSecret(ctx, 9999); !errors.Is(err, appauth.ErrNotFound) {
		t.Fatalf("add secret without client: %v", err)
	}
}

func TestUpdateClient(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.create(t, f.p1)

	name := "Renamed"
	disabled := false
	updated, err := f.svc.UpdateClient(ctx, f.p1, &name, &disabled, []string{appauth.ScopeGoogleRefresh})
	if err != nil {
		t.Fatal(err)
	}
	if updated.DisplayName != "Renamed" || updated.Enabled || strings.Join(updated.AllowedScopes, ",") != appauth.ScopeGoogleRefresh {
		t.Fatalf("updated = %+v", updated)
	}

	if _, err := f.svc.UpdateClient(ctx, f.p1, nil, nil, nil); !errors.Is(err, appauth.ErrValidation) {
		t.Fatalf("empty update: %v", err)
	}
	if _, err := f.svc.UpdateClient(ctx, f.p1, nil, nil, []string{"nope"}); !errors.Is(err, appauth.ErrValidation) {
		t.Fatalf("bad scope: %v", err)
	}
	if _, err := f.svc.UpdateClient(ctx, f.p2, &name, nil, nil); !errors.Is(err, appauth.ErrNotFound) {
		t.Fatalf("other project: %v", err)
	}
}

func TestProjectDeletionRemovesApplicationAuth(t *testing.T) {
	f := newFixture(t)
	c := f.create(t, f.p1)
	f.token(t, c)

	if _, err := f.store.DB().Exec(`DELETE FROM projects WHERE id = ?`, f.p1); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.IssueToken(context.Background(), c.Client.ClientID, c.ClientSecret, nil); !errors.Is(err, appauth.ErrInvalidClient) {
		t.Fatalf("deleted project's client: %v", err)
	}
}

// ---- P2.3 / P2.4 service level: issuance and per-request validation ----

func TestIssueTokenShape(t *testing.T) {
	f := newFixture(t)
	c := f.create(t, f.p1)
	tok := f.token(t, c)

	if !strings.HasPrefix(tok.AccessToken, appauth.TokenPrefix) || tok.ExpiresIn != 900 {
		t.Fatalf("token = %+v", tok)
	}
	if strings.Join(tok.Scopes, " ") != "google.authorize google.refresh" {
		t.Fatalf("scopes = %v", tok.Scopes)
	}

	var stored string
	var issued, expires int64
	if err := f.store.DB().QueryRow(
		`SELECT token_hash, issued_at_unix, expires_at_unix FROM mw_application_access_tokens`,
	).Scan(&stored, &issued, &expires); err != nil {
		t.Fatal(err)
	}
	if stored == tok.AccessToken || stored != appauth.HashToken(tok.AccessToken) {
		t.Fatalf("token stored unhashed: %q", stored)
	}
	if expires-issued != 900 {
		t.Fatalf("lifetime = %d; want 900", expires-issued)
	}

	other := f.token(t, c)
	if other.AccessToken == tok.AccessToken {
		t.Fatal("tokens must be unique")
	}
}

func TestCustomTokenTTL(t *testing.T) {
	f := newFixture(t)
	svc := appauth.NewService(f.store, 2*time.Minute).WithClock(f.clock.Now)
	c := f.create(t, f.p1)

	tok, err := svc.IssueToken(context.Background(), c.Client.ClientID, c.ClientSecret, nil)
	if err != nil || tok.ExpiresIn != 120 {
		t.Fatalf("token = %+v, %v", tok, err)
	}
}

func TestIssueTokenRejectsBadCredentialsUniformly(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	c := f.create(t, f.p1)

	for name, in := range map[string][2]string{
		"wrong secret":   {c.Client.ClientID, c.ClientSecret + "x"},
		"empty secret":   {c.Client.ClientID, ""},
		"unknown client": {"mwc_doesnotexist", c.ClientSecret},
		"empty client":   {"", c.ClientSecret},
		"swapped":        {c.ClientSecret, c.Client.ClientID},
	} {
		if _, err := f.svc.IssueToken(ctx, in[0], in[1], nil); !errors.Is(err, appauth.ErrInvalidClient) {
			t.Fatalf("%s: err = %v; want ErrInvalidClient", name, err)
		}
	}
}

func TestIssueTokenScopeRules(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	limited, err := f.svc.CreateClient(ctx, f.p1, "limited", []string{appauth.ScopeGoogleAuthorize})
	if err != nil {
		t.Fatal(err)
	}

	// Cannot exceed the project grant.
	if _, err := f.svc.IssueToken(ctx, limited.Client.ClientID, limited.ClientSecret, []string{appauth.ScopeGoogleRefresh}); !errors.Is(err, appauth.ErrInvalidScope) {
		t.Fatalf("over-scoped: %v", err)
	}
	if _, err := f.svc.IssueToken(ctx, limited.Client.ClientID, limited.ClientSecret, []string{appauth.ScopeGoogleAuthorize, appauth.ScopeGoogleRefresh}); !errors.Is(err, appauth.ErrInvalidScope) {
		t.Fatalf("partially over-scoped: %v", err)
	}
	if _, err := f.svc.IssueToken(ctx, limited.Client.ClientID, limited.ClientSecret, []string{"admin"}); !errors.Is(err, appauth.ErrInvalidScope) {
		t.Fatalf("unknown scope: %v", err)
	}

	// Default grants everything allowed, nothing more.
	def, err := f.svc.IssueToken(ctx, limited.Client.ClientID, limited.ClientSecret, nil)
	if err != nil || strings.Join(def.Scopes, " ") != appauth.ScopeGoogleAuthorize {
		t.Fatalf("default grant: %+v, %v", def, err)
	}

	// A subset can be requested, and duplicates are collapsed.
	full := f.create2(t)
	sub, err := f.svc.IssueToken(ctx, full.Client.ClientID, full.ClientSecret, []string{appauth.ScopeGoogleRefresh, appauth.ScopeGoogleRefresh})
	if err != nil || strings.Join(sub.Scopes, " ") != appauth.ScopeGoogleRefresh {
		t.Fatalf("subset: %+v, %v", sub, err)
	}
}

func (f fixture) create2(t *testing.T) appauth.CreatedClient { return f.create(t, f.p2) }

func TestDisabledClientAndProjectCannotGetTokens(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	c := f.create(t, f.p1)

	off := false
	if _, err := f.svc.UpdateClient(ctx, f.p1, nil, &off, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.IssueToken(ctx, c.Client.ClientID, c.ClientSecret, nil); !errors.Is(err, appauth.ErrClientDisabled) {
		t.Fatalf("disabled client: %v", err)
	}
	// A wrong secret still looks like any other bad credential.
	if _, err := f.svc.IssueToken(ctx, c.Client.ClientID, "wrong", nil); !errors.Is(err, appauth.ErrInvalidClient) {
		t.Fatalf("disabled client + wrong secret: %v", err)
	}

	on := true
	if _, err := f.svc.UpdateClient(ctx, f.p1, nil, &on, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.DB().Exec(`UPDATE projects SET enabled = 0 WHERE id = ?`, f.p1); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.IssueToken(ctx, c.Client.ClientID, c.ClientSecret, nil); !errors.Is(err, appauth.ErrProjectDisabled) {
		t.Fatalf("disabled project: %v", err)
	}
}

func TestAuthenticateAcceptsValidToken(t *testing.T) {
	f := newFixture(t)
	c := f.create(t, f.p1)
	tok := f.token(t, c, appauth.ScopeGoogleRefresh)

	p, err := f.svc.Authenticate(context.Background(), tok.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	if p.ProjectID != f.p1 || p.ClientID != c.Client.ClientID || !p.HasScope(appauth.ScopeGoogleRefresh) || p.HasScope(appauth.ScopeGoogleAuthorize) {
		t.Fatalf("principal = %+v", p)
	}
}

func TestAuthenticateRejectsInvalidTokens(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	c := f.create(t, f.p1)
	tok := f.token(t, c)

	for name, raw := range map[string]string{
		"empty":         "",
		"garbage":       "garbage",
		"wrong prefix":  "mw_live_" + strings.TrimPrefix(tok.AccessToken, appauth.TokenPrefix),
		"unknown token": appauth.TokenPrefix + "unknown",
		"truncated":     tok.AccessToken[:len(tok.AccessToken)-2],
		"client secret": c.ClientSecret,
	} {
		if _, err := f.svc.Authenticate(ctx, raw); !errors.Is(err, appauth.ErrInvalidToken) {
			t.Fatalf("%s: err = %v; want ErrInvalidToken", name, err)
		}
	}
}

func TestTokenExpiresAfter900Seconds(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	c := f.create(t, f.p1)
	tok := f.token(t, c)

	f.clock.Advance(899 * time.Second)
	if _, err := f.svc.Authenticate(ctx, tok.AccessToken); err != nil {
		t.Fatalf("token should still be valid at 899s: %v", err)
	}

	f.clock.Advance(1 * time.Second)
	if _, err := f.svc.Authenticate(ctx, tok.AccessToken); !errors.Is(err, appauth.ErrInvalidToken) {
		t.Fatalf("token must expire at 900s: %v", err)
	}
}

func TestRevocationTakesEffectBeforeExpiry(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	c := f.create(t, f.p1)
	added, _ := f.svc.AddSecret(ctx, f.p1)

	oldTok := f.token(t, c)
	newTok, err := f.svc.IssueToken(ctx, c.Client.ClientID, added.ClientSecret, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Revoking the old secret kills only the tokens it issued.
	if _, err := f.svc.RevokeSecret(ctx, f.p1, c.Client.Secrets[0].ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Authenticate(ctx, oldTok.AccessToken); !errors.Is(err, appauth.ErrInvalidToken) {
		t.Fatalf("token from revoked secret: %v", err)
	}
	if _, err := f.svc.Authenticate(ctx, newTok.AccessToken); err != nil {
		t.Fatalf("token from live secret: %v", err)
	}

	// Explicit revoke of everything.
	n, err := f.svc.RevokeTokens(ctx, f.p1, nil)
	if err != nil || n != 1 {
		t.Fatalf("revoke tokens = %d, %v", n, err)
	}
	if _, err := f.svc.Authenticate(ctx, newTok.AccessToken); !errors.Is(err, appauth.ErrInvalidToken) {
		t.Fatalf("revoked token: %v", err)
	}

	// Revoking another project's tokens affects nothing here.
	c2 := f.create(t, f.p2)
	other := f.token(t, c2)
	if n, _ := f.svc.RevokeTokens(ctx, f.p1, nil); n != 0 {
		t.Fatalf("cross-project revoke count = %d", n)
	}
	if _, err := f.svc.Authenticate(ctx, other.AccessToken); err != nil {
		t.Fatalf("other project token: %v", err)
	}
}

func TestEveryRequestRevalidatesClientProjectAndScopes(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	c := f.create(t, f.p1)
	tok := f.token(t, c)

	// Narrowing the client's grant applies to tokens already issued.
	if _, err := f.svc.UpdateClient(ctx, f.p1, nil, nil, []string{appauth.ScopeGoogleAuthorize}); err != nil {
		t.Fatal(err)
	}
	p, err := f.svc.Authenticate(ctx, tok.AccessToken)
	if err != nil || p.HasScope(appauth.ScopeGoogleRefresh) || !p.HasScope(appauth.ScopeGoogleAuthorize) {
		t.Fatalf("narrowed principal = %+v, %v", p, err)
	}

	off := false
	if _, err := f.svc.UpdateClient(ctx, f.p1, nil, &off, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Authenticate(ctx, tok.AccessToken); !errors.Is(err, appauth.ErrClientDisabled) {
		t.Fatalf("disabled client: %v", err)
	}

	on := true
	if _, err := f.svc.UpdateClient(ctx, f.p1, nil, &on, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.DB().Exec(`UPDATE projects SET enabled = 0 WHERE id = ?`, f.p1); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Authenticate(ctx, tok.AccessToken); !errors.Is(err, appauth.ErrProjectDisabled) {
		t.Fatalf("disabled project: %v", err)
	}
}

func TestCleanupExpiredTokens(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	c := f.create(t, f.p1)

	old := f.token(t, c)
	f.clock.Advance(2 * time.Hour)
	fresh := f.token(t, c)

	// Expired but inside the retention window: kept.
	n, err := f.svc.CleanupExpired(ctx, 24*time.Hour)
	if err != nil || n != 0 {
		t.Fatalf("cleanup inside retention = %d, %v", n, err)
	}

	f.clock.Advance(24 * time.Hour)
	n, err = f.svc.CleanupExpired(ctx, time.Hour)
	if err != nil || n != 2 {
		t.Fatalf("cleanup = %d, %v; want both expired tokens removed", n, err)
	}

	_ = old
	_ = fresh
	var left int
	if err := f.store.DB().QueryRow(`SELECT COUNT(*) FROM mw_application_access_tokens`).Scan(&left); err != nil || left != 0 {
		t.Fatalf("tokens left = %d, %v", left, err)
	}
}

func TestCleanupKeepsLiveTokens(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	c := f.create(t, f.p1)

	f.token(t, c)
	if n, err := f.svc.CleanupExpired(ctx, 0); err != nil || n != 0 {
		t.Fatalf("live token removed: %d, %v", n, err)
	}
}

func TestConcurrentSecretAdditionNeverExceedsLimit(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.create(t, f.p1)

	var wg sync.WaitGroup
	results := make(chan error, 6)
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := f.svc.AddSecret(ctx, f.p1)
			results <- err
		}()
	}
	wg.Wait()
	close(results)

	ok := 0
	for err := range results {
		switch {
		case err == nil:
			ok++
		case errors.Is(err, appauth.ErrTooManySecrets):
		default:
			t.Fatalf("unexpected error: %v", err)
		}
	}
	// One secret existed already, so exactly one more may be added.
	if ok != 1 {
		t.Fatalf("successful additions = %d; want 1", ok)
	}
}
