package oauth_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vtmattedi/mw-oauth-service/internal/domain"
	"github.com/vtmattedi/mw-oauth-service/internal/googlecred"
	"github.com/vtmattedi/mw-oauth-service/internal/oauth"
	"github.com/vtmattedi/mw-oauth-service/internal/project"
	"github.com/vtmattedi/mw-oauth-service/internal/secretbox"
	"github.com/vtmattedi/mw-oauth-service/internal/store/sqlite"
	"github.com/vtmattedi/mw-oauth-service/internal/transactioncrypto"
)

const (
	pinCallbackURL = "https://app.example.com/api/oauth/google/result"
	pinReturnURL   = "https://app.example.com/settings/integrations"
	pinScope       = "https://www.googleapis.com/auth/calendar"

	clientOne = "one-111.apps.googleusercontent.com"
	secretOne = "GOCSPX-secret-one-123456"
	clientTwo = "two-222.apps.googleusercontent.com"
	secretTwo = "GOCSPX-secret-two-123456"
)

type recordingExchanger struct {
	calls []oauth.GoogleClient
	err   error
}

func (r *recordingExchanger) ExchangeCode(
	ctx context.Context,
	client oauth.GoogleClient,
	code string,
	verifier string,
) (oauth.TokenSet, error) {
	r.calls = append(r.calls, client)
	if r.err != nil {
		return oauth.TokenSet{}, r.err
	}
	return oauth.TokenSet{AccessToken: "access", RefreshToken: "refresh", TokenType: "Bearer", ExpiresIn: 3599}, nil
}

type recordingDeliverer struct {
	delivered []domain.OAuthTransaction
}

func (d *recordingDeliverer) Deliver(
	ctx context.Context,
	transaction domain.OAuthTransaction,
	tokens oauth.TokenSet,
) error {
	d.delivered = append(d.delivered, transaction)
	return nil
}

type pinFixture struct {
	store       *sqlite.Store
	projectID   int64
	otherID     int64
	creds       *googlecred.Service
	service     *oauth.Service
	cipher      *transactioncrypto.Cipher
	exchanger   *recordingExchanger
	deliverer   *recordingDeliverer
	callbackFor func(creds oauth.CredentialSource) *oauth.CallbackService
	projects    *project.Service
}

func gkeys(t *testing.T, raw string, active int) *secretbox.GoogleCredentialKeyring {
	t.Helper()
	ring, err := secretbox.NewGoogleCredentialKeyring(raw, active)
	if err != nil {
		t.Fatal(err)
	}
	return ring
}

func gkey(b byte) string {
	return base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{b}, 32))
}

func newPinFixture(t *testing.T) pinFixture {
	t.Helper()

	store, err := sqlite.Open(filepath.Join(t.TempDir(), "oauth.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	ids := make([]int64, 2)
	for i := range ids {
		row, err := store.CreateProject(context.Background(), project.CreateRecord{
			Name: "app-" + string(rune('a'+i)), Enabled: true,
			CallbackSecretCiphertext: "c",
			CallbackSecretNonce:      "n", CallbackSecretKeyVersion: 1,
		})
		if err != nil {
			t.Fatal(err)
		}
		ids[i] = row.ID

		if err := store.ReplaceGoogleOAuthConfig(context.Background(), row.ID, domain.GoogleOAuthConfig{
			Enabled:             true,
			AllowedScopes:       []string{pinScope},
			AllowedCallbackURLs: []string{pinCallbackURL},
			AllowedReturnURLs:   []string{pinReturnURL},
			Limits:              domain.OAuthLimits{PerMinute: 1000, PerHour: 10000, MaxPending: 1000},
		}); err != nil {
			t.Fatal(err)
		}
	}

	cipher, err := transactioncrypto.New(gkey(0x22))
	if err != nil {
		t.Fatal(err)
	}

	projects := project.NewService(store, nil)
	creds := googlecred.NewService(store, gkeys(t, "1:"+gkey(0x44), 1))

	service, err := oauth.NewService(store, projects, cipher, oauth.Options{
		GoogleRedirectURI: "https://oauth.example.com/oauth/google/callback",
		Credentials:       creds,
	})
	if err != nil {
		t.Fatal(err)
	}

	exchanger := &recordingExchanger{}
	deliverer := &recordingDeliverer{}

	return pinFixture{
		store: store, projectID: ids[0], otherID: ids[1], creds: creds,
		service: service, cipher: cipher, exchanger: exchanger, deliverer: deliverer,
		projects: projects,
		callbackFor: func(source oauth.CredentialSource) *oauth.CallbackService {
			var opts []oauth.CallbackOption
			if source != nil {
				opts = append(opts, oauth.WithCredentials(source))
			}
			cb, err := oauth.NewCallbackService(store, cipher, exchanger, deliverer, opts...)
			if err != nil {
				t.Fatal(err)
			}
			return cb
		},
	}
}

func (f pinFixture) configure(t *testing.T, projectID int64, client, secret string) googlecred.ConfigureResult {
	t.Helper()
	res, err := f.creds.Configure(context.Background(), projectID, client, secret)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

var refCounter int

func (f pinFixture) authorize(t *testing.T, projectID int64) (oauth.AuthorizationResult, error) {
	t.Helper()
	refCounter++
	return f.service.AuthorizeGoogle(
		context.Background(),
		domain.Project{ID: projectID},
		oauth.GoogleAuthorizationRequest{
			Scopes:          []string{pinScope},
			CallbackURL:     pinCallbackURL,
			ReturnURL:       pinReturnURL,
			ClientReference: "ref-" + string(rune('a'+refCounter%26)) + strings.Repeat("x", refCounter%7),
		},
	)
}

func stateFrom(t *testing.T, authorizationURL string) string {
	t.Helper()
	parsed, err := url.Parse(authorizationURL)
	if err != nil {
		t.Fatal(err)
	}
	return parsed.Query().Get("state")
}

func clientIDFrom(t *testing.T, authorizationURL string) string {
	t.Helper()
	parsed, err := url.Parse(authorizationURL)
	if err != nil {
		t.Fatal(err)
	}
	return parsed.Query().Get("client_id")
}

func (f pinFixture) pinned(t *testing.T, transactionID string) (string, bool) {
	t.Helper()
	var id *string
	if err := f.store.DB().QueryRow(
		`SELECT google_credential_id FROM oauth_transactions WHERE id = ?`, transactionID,
	).Scan(&id); err != nil {
		t.Fatal(err)
	}
	if id == nil {
		return "", false
	}
	return *id, true
}

func (f pinFixture) status(t *testing.T, transactionID string) string {
	t.Helper()
	var status string
	if err := f.store.DB().QueryRow(
		`SELECT status FROM oauth_transactions WHERE id = ?`, transactionID,
	).Scan(&status); err != nil {
		t.Fatal(err)
	}
	return status
}

func (f pinFixture) callback(t *testing.T, cb *oauth.CallbackService, authorizationURL string) (oauth.CallbackOutcome, error) {
	t.Helper()
	return cb.HandleGoogle(context.Background(), oauth.GoogleCallbackInput{
		State: stateFrom(t, authorizationURL),
		Code:  "provider-code",
	})
}

// ---- P3.2: selecting and pinning the Google client ----

func TestAuthorizeUsesActiveProjectCredentialAndPinsIt(t *testing.T) {
	f := newPinFixture(t)
	cred := f.configure(t, f.projectID, clientOne, secretOne).Credential

	res, err := f.authorize(t, f.projectID)
	if err != nil {
		t.Fatal(err)
	}

	if got := clientIDFrom(t, res.AuthorizationURL); got != clientOne {
		t.Fatalf("client_id in URL = %q; want the project's client", got)
	}
	if strings.Contains(res.AuthorizationURL, secretOne) {
		t.Fatal("authorization URL must never contain the client secret")
	}

	pinned, ok := f.pinned(t, res.TransactionID)
	if !ok || pinned != cred.ID {
		t.Fatalf("pinned credential = %q, %v; want %q", pinned, ok, cred.ID)
	}

	// PKCE, state and offline consent are unchanged.
	q, _ := url.Parse(res.AuthorizationURL)
	query := q.Query()
	for key, want := range map[string]string{
		"response_type": "code", "code_challenge_method": "S256", "access_type": "offline",
		"prompt": "consent", "include_granted_scopes": "true",
		"redirect_uri": "https://oauth.example.com/oauth/google/callback",
	} {
		if query.Get(key) != want {
			t.Fatalf("%s = %q; want %q", key, query.Get(key), want)
		}
	}
	if query.Get("state") == "" || query.Get("code_challenge") == "" {
		t.Fatal("state and code_challenge are required")
	}
}

func TestAuthorizeUsesDifferentClientsPerProject(t *testing.T) {
	f := newPinFixture(t)
	c1 := f.configure(t, f.projectID, clientOne, secretOne).Credential
	c2 := f.configure(t, f.otherID, clientTwo, secretTwo).Credential

	r1, err := f.authorize(t, f.projectID)
	if err != nil {
		t.Fatal(err)
	}
	r2, err := f.authorize(t, f.otherID)
	if err != nil {
		t.Fatal(err)
	}

	if clientIDFrom(t, r1.AuthorizationURL) != clientOne || clientIDFrom(t, r2.AuthorizationURL) != clientTwo {
		t.Fatal("each project must authorize with its own Google client")
	}
	if p, _ := f.pinned(t, r1.TransactionID); p != c1.ID {
		t.Fatalf("project 1 pinned %q", p)
	}
	if p, _ := f.pinned(t, r2.TransactionID); p != c2.ID {
		t.Fatalf("project 2 pinned %q", p)
	}
}

func TestAuthorizeFailsAfterTheOnlyCredentialIsDisabled(t *testing.T) {
	f := newPinFixture(t)
	cred := f.configure(t, f.projectID, clientOne, secretOne).Credential

	// Compromised credential disabled: there is no other client to use.
	if _, err := f.creds.Disable(context.Background(), f.projectID, cred.ID); err != nil {
		t.Fatal(err)
	}

	_, err := f.authorize(t, f.projectID)
	if !errors.Is(err, oauth.ErrNoGoogleClient) {
		t.Fatalf("err = %v; want ErrNoGoogleClient", err)
	}

	var transactions int
	_ = f.store.DB().QueryRow(`SELECT COUNT(*) FROM oauth_transactions`).Scan(&transactions)
	if transactions != 0 {
		t.Fatalf("a rejected authorization created %d transactions", transactions)
	}
}

func TestAuthorizeWithUnusableCredentialFails(t *testing.T) {
	f := newPinFixture(t)
	f.configure(t, f.projectID, clientOne, secretOne)

	cases := map[string]*googlecred.Service{
		"key version lost": googlecred.NewService(f.store, gkeys(t, "2:"+gkey(0x55), 2)),
		"no keyring":       googlecred.NewService(f.store, nil),
	}
	for name, creds := range cases {
		service, err := oauth.NewService(f.store, f.projects, f.cipher, oauth.Options{
			GoogleRedirectURI: "https://oauth.example.com/oauth/google/callback",
			Credentials:       creds,
		})
		if err != nil {
			t.Fatal(err)
		}

		_, err = service.AuthorizeGoogle(context.Background(), domain.Project{ID: f.projectID}, oauth.GoogleAuthorizationRequest{
			Scopes: []string{pinScope}, CallbackURL: pinCallbackURL, ReturnURL: pinReturnURL, ClientReference: "ref-broken-" + name,
		})
		if !errors.Is(err, oauth.ErrGoogleClientUnavailable) {
			t.Fatalf("%s: err = %v; want ErrGoogleClientUnavailable", name, err)
		}
		if strings.Contains(err.Error(), secretOne) {
			t.Fatalf("%s: error leaks the secret", name)
		}
	}

	var transactions int
	_ = f.store.DB().QueryRow(`SELECT COUNT(*) FROM oauth_transactions`).Scan(&transactions)
	if transactions != 0 {
		t.Fatalf("unusable credential created %d transactions", transactions)
	}
}

func TestAuthorizeAfterRotationUsesNewCredential(t *testing.T) {
	f := newPinFixture(t)
	f.configure(t, f.projectID, clientOne, secretOne)
	second := f.configure(t, f.projectID, clientTwo, secretTwo).Credential

	res, err := f.authorize(t, f.projectID)
	if err != nil {
		t.Fatal(err)
	}
	if clientIDFrom(t, res.AuthorizationURL) != clientTwo {
		t.Fatal("new authorizations must use the newly active client")
	}
	if p, _ := f.pinned(t, res.TransactionID); p != second.ID {
		t.Fatalf("pinned %q; want %q", p, second.ID)
	}
}

// ---- P3.3: callback exchanges with the pinned client ----

func TestCallbackExchangesWithPinnedClientAndDeliversCredentialRef(t *testing.T) {
	f := newPinFixture(t)
	cred := f.configure(t, f.projectID, clientOne, secretOne).Credential

	res, err := f.authorize(t, f.projectID)
	if err != nil {
		t.Fatal(err)
	}

	outcome, err := f.callback(t, f.callbackFor(f.creds), res.AuthorizationURL)
	if err != nil || outcome.Status != "completed" {
		t.Fatalf("outcome = %+v, %v", outcome, err)
	}

	if len(f.exchanger.calls) != 1 || f.exchanger.calls[0] != (oauth.GoogleClient{ClientID: clientOne, ClientSecret: secretOne}) {
		t.Fatalf("exchange used %+v", f.exchanger.calls)
	}
	if len(f.deliverer.delivered) != 1 || f.deliverer.delivered[0].GoogleCredentialID != cred.ID {
		t.Fatalf("delivered = %+v", f.deliverer.delivered)
	}

	got, _ := f.creds.Get(context.Background(), f.projectID, cred.ID)
	if got.LastAuthorizedAt == "" {
		t.Fatal("a successful exchange must mark the credential as authorized")
	}
}

func TestRotationBetweenAuthorizeAndCallbackDoesNotChangeTheExchangeClient(t *testing.T) {
	f := newPinFixture(t)
	first := f.configure(t, f.projectID, clientOne, secretOne).Credential

	res, err := f.authorize(t, f.projectID)
	if err != nil {
		t.Fatal(err)
	}

	// The operator rotates while the user is still on Google's consent page.
	second := f.configure(t, f.projectID, clientTwo, secretTwo).Credential

	outcome, err := f.callback(t, f.callbackFor(f.creds), res.AuthorizationURL)
	if err != nil || outcome.Status != "completed" {
		t.Fatalf("outcome = %+v, %v", outcome, err)
	}

	if len(f.exchanger.calls) != 1 || f.exchanger.calls[0].ClientID != clientOne || f.exchanger.calls[0].ClientSecret != secretOne {
		t.Fatalf("exchange must use the pinned (old) client, used %+v", f.exchanger.calls)
	}
	if f.deliverer.delivered[0].GoogleCredentialID != first.ID {
		t.Fatalf("credential_ref = %q; want the pinned %q", f.deliverer.delivered[0].GoogleCredentialID, first.ID)
	}

	oldCred, _ := f.creds.Get(context.Background(), f.projectID, first.ID)
	newCred, _ := f.creds.Get(context.Background(), f.projectID, second.ID)
	if oldCred.LastAuthorizedAt == "" || newCred.LastAuthorizedAt != "" {
		t.Fatalf("authorization recorded on the wrong credential: old=%q new=%q", oldCred.LastAuthorizedAt, newCred.LastAuthorizedAt)
	}
}

func TestRetiringPinnedCredentialStillCompletesInFlightCallback(t *testing.T) {
	f := newPinFixture(t)
	cred := f.configure(t, f.projectID, clientOne, secretOne).Credential
	res, err := f.authorize(t, f.projectID)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := f.creds.Retire(context.Background(), f.projectID, cred.ID); err != nil {
		t.Fatal(err)
	}

	if outcome, err := f.callback(t, f.callbackFor(f.creds), res.AuthorizationURL); err != nil || outcome.Status != "completed" {
		t.Fatalf("retiring credential: %+v, %v", outcome, err)
	}
}

func TestDisabledPinnedCredentialFailsCallbackClearly(t *testing.T) {
	for name, disable := range map[string]func(t *testing.T, f pinFixture, ref string){
		"disabled": func(t *testing.T, f pinFixture, ref string) {
			if _, err := f.creds.Disable(context.Background(), f.projectID, ref); err != nil {
				t.Fatal(err)
			}
		},
		"secret deleted": func(t *testing.T, f pinFixture, ref string) {
			if _, err := f.creds.Disable(context.Background(), f.projectID, ref); err != nil {
				t.Fatal(err)
			}
			if _, err := f.creds.DeleteSecret(context.Background(), f.projectID, ref); err != nil {
				t.Fatal(err)
			}
		},
	} {
		f := newPinFixture(t)
		cred := f.configure(t, f.projectID, clientOne, secretOne).Credential
		res, err := f.authorize(t, f.projectID)
		if err != nil {
			t.Fatal(err)
		}
		// Another credential is active, but the code must not be exchanged with it.
		disable(t, f, cred.ID)
		f.configure(t, f.projectID, clientTwo, secretTwo)

		outcome, err := f.callback(t, f.callbackFor(f.creds), res.AuthorizationURL)
		if !errors.Is(err, oauth.ErrCredentialUnavailable) {
			t.Fatalf("%s: err = %v; want ErrCredentialUnavailable", name, err)
		}
		if outcome.Status != "provider_failed" || f.status(t, res.TransactionID) != "provider_failed" {
			t.Fatalf("%s: status = %q / %q", name, outcome.Status, f.status(t, res.TransactionID))
		}
		if len(f.exchanger.calls) != 0 || len(f.deliverer.delivered) != 0 {
			t.Fatalf("%s: exchanged=%d delivered=%d; nothing may reach Google or the project", name, len(f.exchanger.calls), len(f.deliverer.delivered))
		}
		if strings.Contains(err.Error(), secretOne) || strings.Contains(err.Error(), secretTwo) {
			t.Fatalf("%s: error leaks a secret", name)
		}
	}
}

func TestPinnedCredentialWithLostKeyFailsCallback(t *testing.T) {
	f := newPinFixture(t)
	f.configure(t, f.projectID, clientOne, secretOne)
	res, err := f.authorize(t, f.projectID)
	if err != nil {
		t.Fatal(err)
	}

	lost := googlecred.NewService(f.store, gkeys(t, "2:"+gkey(0x55), 2))
	_, err = f.callback(t, f.callbackFor(lost), res.AuthorizationURL)
	if !errors.Is(err, oauth.ErrCredentialUnavailable) {
		t.Fatalf("err = %v; want ErrCredentialUnavailable", err)
	}
	if len(f.exchanger.calls) != 0 {
		t.Fatal("nothing may be exchanged when the pinned key is lost")
	}

	// A callback service with no credential source at all behaves the same.
	f2 := newPinFixture(t)
	f2.configure(t, f2.projectID, clientOne, secretOne)
	res2, _ := f2.authorize(t, f2.projectID)
	if _, err := f2.callback(t, f2.callbackFor(nil), res2.AuthorizationURL); !errors.Is(err, oauth.ErrCredentialUnavailable) {
		t.Fatalf("no credential source: %v", err)
	}
	if len(f2.exchanger.calls) != 0 {
		t.Fatal("nothing may be exchanged without the pinned credential")
	}
}

func TestCallbackRejectsCredentialOfAnotherProject(t *testing.T) {
	f := newPinFixture(t)
	f.configure(t, f.projectID, clientOne, secretOne)
	foreign := f.configure(t, f.otherID, clientTwo, secretTwo).Credential

	res, err := f.authorize(t, f.projectID)
	if err != nil {
		t.Fatal(err)
	}

	// Corrupt the pin to point at the other project's credential.
	if _, err := f.store.DB().Exec(
		`UPDATE oauth_transactions SET google_credential_id = ? WHERE id = ?`, foreign.ID, res.TransactionID,
	); err != nil {
		t.Fatal(err)
	}

	if _, err := f.callback(t, f.callbackFor(f.creds), res.AuthorizationURL); !errors.Is(err, oauth.ErrCredentialUnavailable) {
		t.Fatalf("err = %v; a project must never exchange with another project's client", err)
	}
	if len(f.exchanger.calls) != 0 {
		t.Fatal("exchange must not run with a foreign credential")
	}
}

func TestFailedExchangeDoesNotMarkCredentialAuthorized(t *testing.T) {
	f := newPinFixture(t)
	cred := f.configure(t, f.projectID, clientOne, secretOne).Credential
	res, _ := f.authorize(t, f.projectID)

	f.exchanger.err = errors.New("Google token exchange failed: status=400 code=invalid_grant")
	_, err := f.callback(t, f.callbackFor(f.creds), res.AuthorizationURL)
	if !errors.Is(err, oauth.ErrProviderExchangeFailed) {
		t.Fatalf("err = %v", err)
	}

	got, _ := f.creds.Get(context.Background(), f.projectID, cred.ID)
	if got.LastAuthorizedAt != "" {
		t.Fatal("only a successful exchange proves the credential works")
	}
}

func TestPinnedCallbackIsStillSingleUse(t *testing.T) {
	f := newPinFixture(t)
	f.configure(t, f.projectID, clientOne, secretOne)
	res, _ := f.authorize(t, f.projectID)
	cb := f.callbackFor(f.creds)

	if _, err := f.callback(t, cb, res.AuthorizationURL); err != nil {
		t.Fatal(err)
	}
	if _, err := f.callback(t, cb, res.AuthorizationURL); !errors.Is(err, oauth.ErrTransactionConsumed) {
		t.Fatalf("replay: err = %v; want ErrTransactionConsumed", err)
	}
	if len(f.exchanger.calls) != 1 {
		t.Fatalf("exchanges = %d; replay must not reach Google", len(f.exchanger.calls))
	}
}

// ---- no global client, and transient failures ----

func TestAuthorizeWithoutAnyCredentialIsRejected(t *testing.T) {
	f := newPinFixture(t)

	if _, err := f.authorize(t, f.projectID); !errors.Is(err, oauth.ErrNoGoogleClient) {
		t.Fatalf("err = %v; want ErrNoGoogleClient", err)
	}

	var transactions int
	_ = f.store.DB().QueryRow(`SELECT COUNT(*) FROM oauth_transactions`).Scan(&transactions)
	if transactions != 0 {
		t.Fatalf("created %d transactions without a Google client", transactions)
	}
}

func TestServiceRequiresACredentialSource(t *testing.T) {
	f := newPinFixture(t)

	if _, err := oauth.NewService(f.store, f.projects, f.cipher, oauth.Options{
		GoogleRedirectURI: "https://oauth.example.com/oauth/google/callback",
	}); err == nil {
		t.Fatal("there is no global Google client, so a credential source is mandatory")
	}
}

func TestTransactionWithoutAPinnedClientFailsClosed(t *testing.T) {
	f := newPinFixture(t)
	f.configure(t, f.projectID, clientOne, secretOne)
	res, err := f.authorize(t, f.projectID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.DB().Exec(
		`UPDATE oauth_transactions SET google_credential_id = NULL WHERE id = ?`, res.TransactionID,
	); err != nil {
		t.Fatal(err)
	}

	_, err = f.callback(t, f.callbackFor(f.creds), res.AuthorizationURL)
	if !errors.Is(err, oauth.ErrCredentialUnavailable) {
		t.Fatalf("err = %v; want ErrCredentialUnavailable", err)
	}
	if len(f.exchanger.calls) != 0 {
		t.Fatal("an unpinned authorization must not be exchanged with any client")
	}
}

// flakyCredentials fails the first n calls with a store-style error, then
// delegates.
type flakyCredentials struct {
	oauth.CredentialSource
	failures int
}

func (c *flakyCredentials) fail() error {
	if c.failures > 0 {
		c.failures--
		return errors.New("get google credential: database is locked")
	}
	return nil
}

func (c *flakyCredentials) Resolve(
	ctx context.Context, projectID int64, ref string, purpose googlecred.Purpose,
) (googlecred.Resolved, error) {
	if err := c.fail(); err != nil {
		return googlecred.Resolved{}, err
	}
	return c.CredentialSource.Resolve(ctx, projectID, ref, purpose)
}

func (c *flakyCredentials) ResolveActive(
	ctx context.Context, projectID int64,
) (googlecred.Resolved, error) {
	if err := c.fail(); err != nil {
		return googlecred.Resolved{}, err
	}
	return c.CredentialSource.ResolveActive(ctx, projectID)
}

func TestTransientResolveErrorKeepsTheAuthorizationRetryable(t *testing.T) {
	f := newPinFixture(t)
	f.configure(t, f.projectID, clientOne, secretOne)
	res, err := f.authorize(t, f.projectID)
	if err != nil {
		t.Fatal(err)
	}

	flaky := &flakyCredentials{CredentialSource: f.creds, failures: 1}
	cb := f.callbackFor(flaky)

	outcome, err := f.callback(t, cb, res.AuthorizationURL)
	if !errors.Is(err, oauth.ErrTemporaryFailure) || errors.Is(err, oauth.ErrCredentialUnavailable) {
		t.Fatalf("err = %v; a store hiccup is temporary, not a dead credential", err)
	}
	if outcome.Status != "pending" || f.status(t, res.TransactionID) != "pending" {
		t.Fatalf("status = %q / %q; the authorization must stay pending", outcome.Status, f.status(t, res.TransactionID))
	}
	if len(f.exchanger.calls) != 0 || len(f.deliverer.delivered) != 0 {
		t.Fatal("nothing may reach Google or the project during a transient failure")
	}

	// The user reloads the same callback URL and it completes.
	outcome, err = f.callback(t, cb, res.AuthorizationURL)
	if err != nil || outcome.Status != "completed" {
		t.Fatalf("retry: %+v, %v", outcome, err)
	}
	if len(f.exchanger.calls) != 1 || len(f.deliverer.delivered) != 1 {
		t.Fatalf("exchanges=%d deliveries=%d; exactly one of each expected", len(f.exchanger.calls), len(f.deliverer.delivered))
	}
}

func TestTransientErrorWhileAuthorizingIsNotReportedAsAMissingClient(t *testing.T) {
	f := newPinFixture(t)
	f.configure(t, f.projectID, clientOne, secretOne)

	flaky := &flakyCredentials{CredentialSource: f.creds, failures: 1}
	service, err := oauth.NewService(f.store, f.projects, f.cipher, oauth.Options{
		GoogleRedirectURI: "https://oauth.example.com/oauth/google/callback",
		Credentials:       flaky,
	})
	if err != nil {
		t.Fatal(err)
	}

	request := oauth.GoogleAuthorizationRequest{
		Scopes: []string{pinScope}, CallbackURL: pinCallbackURL, ReturnURL: pinReturnURL, ClientReference: "ref-transient",
	}
	_, err = service.AuthorizeGoogle(context.Background(), domain.Project{ID: f.projectID}, request)
	if err == nil || errors.Is(err, oauth.ErrNoGoogleClient) || errors.Is(err, oauth.ErrGoogleClientUnavailable) {
		t.Fatalf("err = %v; a store failure is neither a missing nor a broken client", err)
	}

	// The next attempt works.
	if _, err := service.AuthorizeGoogle(context.Background(), domain.Project{ID: f.projectID}, request); err != nil {
		t.Fatalf("retry: %v", err)
	}
}
