package googlecred_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/vtmattedi/mw-oauth-service/internal/domain"
	"github.com/vtmattedi/mw-oauth-service/internal/googlecred"
	"github.com/vtmattedi/mw-oauth-service/internal/project"
	"github.com/vtmattedi/mw-oauth-service/internal/secretbox"
	"github.com/vtmattedi/mw-oauth-service/internal/store/sqlite"
)

const (
	clientA = "111111-aaaa.apps.googleusercontent.com"
	clientB = "222222-bbbb.apps.googleusercontent.com"
	secretA = "GOCSPX-secret-A-0123456789"
	secretB = "GOCSPX-secret-B-0123456789"
)

func key(b byte) string {
	return base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{b}, 32))
}

func keyring(t *testing.T, raw string, active int) *secretbox.GoogleCredentialKeyring {
	t.Helper()
	ring, err := secretbox.NewGoogleCredentialKeyring(raw, active)
	if err != nil {
		t.Fatal(err)
	}
	return ring
}

type fixture struct {
	store *sqlite.Store
	svc   *googlecred.Service
	p1    int64
	p2    int64
}

func newFixture(t *testing.T, keys *secretbox.GoogleCredentialKeyring) fixture {
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
			TokenHash: fmt.Sprintf("hash-%d", i), CallbackSecretCiphertext: "c",
			CallbackSecretNonce: "n", CallbackSecretKeyVersion: 1,
		})
		if err != nil {
			t.Fatal(err)
		}
		ids[i] = p.ID
	}

	return fixture{store: store, svc: googlecred.NewService(store, keys), p1: ids[0], p2: ids[1]}
}

func (f fixture) configure(t *testing.T, project int64, client, secret string) googlecred.ConfigureResult {
	t.Helper()
	res, err := f.svc.Configure(context.Background(), project, client, secret)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestConfigureEncryptsAndNeverReturnsSecret(t *testing.T) {
	f := newFixture(t, keyring(t, "1:"+key(1), 1))

	res := f.configure(t, f.p1, clientA, secretA)

	if res.Credential.State != domain.GoogleCredentialActive ||
		!strings.HasPrefix(res.Credential.ID, domain.GoogleCredentialIDPrefix) ||
		res.Credential.ClientID != clientA || res.Retired != nil {
		t.Fatalf("unexpected result: %+v", res)
	}

	encoded, _ := json.Marshal(res)
	if strings.Contains(string(encoded), secretA) {
		t.Fatalf("result leaks secret: %s", encoded)
	}

	var ciphertext string
	if err := f.store.DB().QueryRow(
		`SELECT secret_ciphertext FROM google_client_credentials WHERE id = ?`, res.Credential.ID,
	).Scan(&ciphertext); err != nil {
		t.Fatal(err)
	}
	if ciphertext == "" || strings.Contains(ciphertext, secretA) {
		t.Fatalf("stored ciphertext is not encrypted: %q", ciphertext)
	}

	resolved, err := f.svc.Resolve(context.Background(), f.p1, res.Credential.ID, googlecred.PurposeAuthorize)
	if err != nil || resolved.ClientSecret != secretA || resolved.ClientID != clientA {
		t.Fatalf("resolve = %+v, %v", resolved, err)
	}
}

func TestConfigureValidation(t *testing.T) {
	f := newFixture(t, keyring(t, "1:"+key(1), 1))
	ctx := context.Background()

	bad := map[string][2]string{
		"empty client":         {"", secretA},
		"not a google client":  {"my-client-id", secretA},
		"suffix only":          {".apps.googleusercontent.com", secretA},
		"whitespace in client": {"1 2" + ".apps.googleusercontent.com", secretA},
		"empty secret":         {clientA, ""},
		"short secret":         {clientA, "short"},
		"secret with space":    {clientA, "GOCSPX has space"},
		"secret with newline":  {clientA, "GOCSPX-abc\ndef-123"},
		"oversized secret":     {clientA, strings.Repeat("x", 513)},
	}
	for name, in := range bad {
		if _, err := f.svc.Configure(ctx, f.p1, in[0], in[1]); !errors.Is(err, googlecred.ErrValidation) {
			t.Fatalf("%s: err = %v; want ErrValidation", name, err)
		}
	}

	if _, err := f.svc.Configure(ctx, 9999, clientA, secretA); !errors.Is(err, googlecred.ErrProjectNotFound) {
		t.Fatalf("unknown project: %v", err)
	}
	if _, err := f.svc.Configure(ctx, 0, clientA, secretA); !errors.Is(err, googlecred.ErrProjectNotFound) {
		t.Fatalf("zero project: %v", err)
	}
	if list, _ := f.svc.List(ctx, f.p1); len(list) != 0 {
		t.Fatalf("failed configures must not store anything: %v", list)
	}
}

func TestRotationKeepsOldCredentialUsableForPinnedFlows(t *testing.T) {
	f := newFixture(t, keyring(t, "1:"+key(1), 1))
	ctx := context.Background()

	first := f.configure(t, f.p1, clientA, secretA)
	second := f.configure(t, f.p1, clientB, secretB)

	if second.Retired == nil || second.Retired.ID != first.Credential.ID ||
		second.Retired.State != domain.GoogleCredentialRetiring {
		t.Fatalf("previous credential not retired: %+v", second.Retired)
	}

	// New authorizations only use the new credential.
	if _, err := f.svc.Resolve(ctx, f.p1, first.Credential.ID, googlecred.PurposeAuthorize); !errors.Is(err, googlecred.ErrSecretUnavailable) {
		t.Fatalf("retiring credential must not authorize: %v", err)
	}
	active, err := f.svc.ResolveActive(ctx, f.p1)
	if err != nil || active.Ref != second.Credential.ID || active.ClientSecret != secretB {
		t.Fatalf("active = %+v, %v", active, err)
	}

	// The retiring credential still finishes pinned callbacks and refreshes,
	// with its own secret.
	for _, purpose := range []googlecred.Purpose{googlecred.PurposeExchange, googlecred.PurposeRefresh} {
		old, err := f.svc.Resolve(ctx, f.p1, first.Credential.ID, purpose)
		if err != nil || old.ClientSecret != secretA || old.ClientID != clientA {
			t.Fatalf("%s on retiring = %+v, %v", purpose, old, err)
		}
	}
}

func TestDisabledAndDeletedCredentialsAreUnavailableForEveryPurpose(t *testing.T) {
	f := newFixture(t, keyring(t, "1:"+key(1), 1))
	ctx := context.Background()
	purposes := []googlecred.Purpose{googlecred.PurposeAuthorize, googlecred.PurposeExchange, googlecred.PurposeRefresh}

	cred := f.configure(t, f.p1, clientA, secretA).Credential

	// A compromised active credential is disabled without retiring first.
	disabled, err := f.svc.Disable(ctx, f.p1, cred.ID)
	if err != nil || disabled.State != domain.GoogleCredentialDisabled {
		t.Fatalf("disable: %+v, %v", disabled, err)
	}
	for _, p := range purposes {
		if _, err := f.svc.Resolve(ctx, f.p1, cred.ID, p); !errors.Is(err, googlecred.ErrSecretUnavailable) {
			t.Fatalf("disabled %s: %v", p, err)
		}
	}
	if _, err := f.svc.ResolveActive(ctx, f.p1); !errors.Is(err, googlecred.ErrNotFound) {
		t.Fatalf("no active credential expected: %v", err)
	}

	tomb, err := f.svc.DeleteSecret(ctx, f.p1, cred.ID)
	if err != nil || tomb.SecretAvailable {
		t.Fatalf("delete secret: %+v, %v", tomb, err)
	}
	for _, p := range purposes {
		if _, err := f.svc.Resolve(ctx, f.p1, cred.ID, p); !errors.Is(err, googlecred.ErrSecretUnavailable) {
			t.Fatalf("deleted %s: %v", p, err)
		}
	}
	if got, err := f.svc.Get(context.Background(), f.p1, cred.ID); err != nil || got.State != domain.GoogleCredentialDisabled {
		t.Fatalf("tombstone must stay readable: %+v, %v", got, err)
	}
}

func TestLifecycleRules(t *testing.T) {
	f := newFixture(t, keyring(t, "1:"+key(1), 1))
	ctx := context.Background()

	cred := f.configure(t, f.p1, clientA, secretA).Credential

	// The secret of a live credential cannot be deleted.
	if _, err := f.svc.DeleteSecret(ctx, f.p1, cred.ID); !errors.Is(err, googlecred.ErrInvalidTransition) {
		t.Fatalf("delete live secret: %v", err)
	}

	if _, err := f.svc.Retire(ctx, f.p1, cred.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Retire(ctx, f.p1, cred.ID); !errors.Is(err, googlecred.ErrInvalidTransition) {
		t.Fatalf("retire twice: %v", err)
	}
	if _, err := f.svc.Disable(ctx, f.p1, cred.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Retire(ctx, f.p1, cred.ID); !errors.Is(err, googlecred.ErrInvalidTransition) {
		t.Fatalf("retire disabled: %v", err)
	}
}

func TestCredentialsAreIsolatedBetweenProjects(t *testing.T) {
	f := newFixture(t, keyring(t, "1:"+key(1), 1))
	ctx := context.Background()

	c1 := f.configure(t, f.p1, clientA, secretA).Credential
	c2 := f.configure(t, f.p2, clientB, secretB).Credential

	// Each project has its own active credential.
	for project, want := range map[int64]string{f.p1: c1.ID, f.p2: c2.ID} {
		active, err := f.svc.Active(ctx, project)
		if err != nil || active.ID != want {
			t.Fatalf("project %d active = %+v, %v", project, active, err)
		}
	}

	// A reference from another project is indistinguishable from a missing one.
	for name, call := range map[string]func() error{
		"resolve": func() error {
			_, err := f.svc.Resolve(ctx, f.p2, c1.ID, googlecred.PurposeRefresh)
			return err
		},
		"get":     func() error { _, err := f.svc.Get(ctx, f.p2, c1.ID); return err },
		"retire":  func() error { _, err := f.svc.Retire(ctx, f.p2, c1.ID); return err },
		"disable": func() error { _, err := f.svc.Disable(ctx, f.p2, c1.ID); return err },
		"impact":  func() error { _, err := f.svc.Impact(ctx, f.p2, c1.ID); return err },
		"missing": func() error {
			_, err := f.svc.Resolve(ctx, f.p2, "gcred_doesnotexist", googlecred.PurposeRefresh)
			return err
		},
	} {
		if err := call(); !errors.Is(err, googlecred.ErrNotFound) {
			t.Fatalf("%s: err = %v; want ErrNotFound", name, err)
		}
	}

	// Rotating one project never touches the other.
	f.configure(t, f.p1, clientB, secretB)
	if still, _ := f.svc.Get(ctx, f.p2, c2.ID); still.State != domain.GoogleCredentialActive {
		t.Fatalf("other project credential changed: %+v", still)
	}

	// The legacy reference is not a stored credential.
	if _, err := f.svc.Resolve(ctx, f.p1, domain.LegacyGoogleCredentialRef, googlecred.PurposeRefresh); !errors.Is(err, googlecred.ErrNotFound) {
		t.Fatalf("legacy ref: %v", err)
	}
}

func TestMissingKeyVersionIsBrokenNotLegacy(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, keyring(t, "1:"+key(1), 1))
	cred := f.configure(t, f.p1, clientA, secretA).Credential

	// Same database, but the keyring only knows version 2 (key 1 lost).
	lost := googlecred.NewService(f.store, keyring(t, "2:"+key(2), 2))

	_, err := lost.Resolve(ctx, f.p1, cred.ID, googlecred.PurposeAuthorize)
	if !errors.Is(err, googlecred.ErrBroken) {
		t.Fatalf("err = %v; want ErrBroken", err)
	}
	// Metadata stays readable so an operator can see which credential broke.
	if got, err := lost.Get(ctx, f.p1, cred.ID); err != nil || got.ID != cred.ID {
		t.Fatalf("metadata read: %+v, %v", got, err)
	}
	if _, err := lost.ResolveActive(ctx, f.p1); !errors.Is(err, googlecred.ErrBroken) {
		t.Fatalf("ResolveActive: %v", err)
	}
}

func TestKeyRotationKeepsOldCredentialsDecryptable(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, keyring(t, "1:"+key(1), 1))
	old := f.configure(t, f.p1, clientA, secretA).Credential

	rotated := googlecred.NewService(f.store, keyring(t, "1:"+key(1)+",2:"+key(2), 2))
	got, err := rotated.Resolve(ctx, f.p1, old.ID, googlecred.PurposeAuthorize)
	if err != nil || got.ClientSecret != secretA {
		t.Fatalf("old key version: %+v, %v", got, err)
	}

	fresh, err := rotated.Configure(ctx, f.p2, clientB, secretB)
	if err != nil || fresh.Credential.KeyVersion != 2 {
		t.Fatalf("new credential should use key version 2: %+v, %v", fresh, err)
	}
}

func TestTamperedOrMovedCiphertextIsBroken(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, keyring(t, "1:"+key(1), 1))
	cred := f.configure(t, f.p1, clientA, secretA).Credential
	other := f.configure(t, f.p2, clientB, secretB).Credential

	// Swap ciphertexts between two credentials: AAD must reject it.
	if _, err := f.store.DB().Exec(`
		UPDATE google_client_credentials
		SET secret_ciphertext = (SELECT secret_ciphertext FROM google_client_credentials WHERE id = ?),
		    secret_nonce      = (SELECT secret_nonce      FROM google_client_credentials WHERE id = ?)
		WHERE id = ?`, other.ID, other.ID, cred.ID,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Resolve(ctx, f.p1, cred.ID, googlecred.PurposeAuthorize); !errors.Is(err, googlecred.ErrBroken) {
		t.Fatalf("moved ciphertext: %v", err)
	}

	// Corrupt ciphertext.
	if _, err := f.store.DB().Exec(
		`UPDATE google_client_credentials SET secret_ciphertext = 'AAAA' WHERE id = ?`, other.ID,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Resolve(ctx, f.p2, other.ID, googlecred.PurposeAuthorize); !errors.Is(err, googlecred.ErrBroken) {
		t.Fatalf("corrupt ciphertext: %v", err)
	}
}

func TestBrokenErrorsDoNotLeakSecretMaterial(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, keyring(t, "1:"+key(1), 1))
	cred := f.configure(t, f.p1, clientA, secretA).Credential

	lost := googlecred.NewService(f.store, keyring(t, "2:"+key(2), 2))
	_, err := lost.Resolve(ctx, f.p1, cred.ID, googlecred.PurposeAuthorize)
	if err == nil {
		t.Fatal("expected error")
	}
	for _, forbidden := range []string{secretA, key(1), key(2)} {
		if strings.Contains(err.Error(), forbidden) {
			t.Fatalf("error leaks %q: %v", forbidden, err)
		}
	}
}

func TestWithoutKeyringMetadataWorksButSecretsDoNot(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, keyring(t, "1:"+key(1), 1))
	cred := f.configure(t, f.p1, clientA, secretA).Credential

	noKeys := googlecred.NewService(f.store, nil)

	if _, err := noKeys.Configure(ctx, f.p1, clientB, secretB); !errors.Is(err, googlecred.ErrNotConfigured) {
		t.Fatalf("configure: %v", err)
	}
	if _, err := noKeys.Resolve(ctx, f.p1, cred.ID, googlecred.PurposeAuthorize); !errors.Is(err, googlecred.ErrNotConfigured) {
		t.Fatalf("resolve: %v", err)
	}
	if list, err := noKeys.List(ctx, f.p1); err != nil || len(list) != 1 {
		t.Fatalf("list: %v, %v", list, err)
	}
}

func TestImpactCountsPendingPinnedAuthorizations(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, keyring(t, "1:"+key(1), 1))
	cred := f.configure(t, f.p1, clientA, secretA).Credential

	insert := func(id, status string, expires int64, credential any) {
		t.Helper()
		if _, err := f.store.DB().Exec(
			`INSERT INTO oauth_transactions(id, project_id, provider, state_hash,
				pkce_verifier_ciphertext, pkce_verifier_nonce, client_reference,
				callback_url, return_url, requested_scopes_json, status,
				expires_at_unix, created_at_unix, google_credential_id)
			 VALUES (?, ?, 'google', ?, 'c', 'n', 'r', 'https://a/cb', 'https://a/r', '[]', ?, ?, 1, ?)`,
			id, f.p1, "state-"+id, status, expires, credential,
		); err != nil {
			t.Fatal(err)
		}
	}
	far := int64(4102444800) // year 2100
	insert("t-pending", "pending", far, cred.ID)
	insert("t-processing", "processing", far, cred.ID)
	insert("t-done", "completed", far, cred.ID)
	insert("t-expired", "pending", 1, cred.ID)
	insert("t-legacy", "pending", far, nil)

	impact, err := f.svc.Impact(ctx, f.p1, cred.ID)
	if err != nil {
		t.Fatal(err)
	}
	if impact.PendingAuthorizations != 2 || impact.ExistingTokensMayDepend {
		t.Fatalf("impact = %+v", impact)
	}

	if err := f.svc.RecordAuthorized(ctx, f.p1, cred.ID); err != nil {
		t.Fatal(err)
	}
	impact, _ = f.svc.Impact(ctx, f.p1, cred.ID)
	if !impact.ExistingTokensMayDepend || impact.Credential.LastAuthorizedAt == "" {
		t.Fatalf("authorized credential should flag dependants: %+v", impact)
	}
}

func TestConcurrentConfigureLeavesExactlyOneActive(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, keyring(t, "1:"+key(1), 1))

	const workers = 8
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := f.svc.Configure(ctx, f.p1,
				fmt.Sprintf("%d-%d.apps.googleusercontent.com", 1000+i, i),
				fmt.Sprintf("GOCSPX-concurrent-%d-secret", i))
			errs <- err
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent configure: %v", err)
		}
	}

	list, err := f.svc.List(ctx, f.p1)
	if err != nil || len(list) != workers {
		t.Fatalf("list = %d, %v", len(list), err)
	}
	active, retiring := 0, 0
	for _, c := range list {
		switch c.State {
		case domain.GoogleCredentialActive:
			active++
		case domain.GoogleCredentialRetiring:
			retiring++
		}
	}
	if active != 1 || retiring != workers-1 {
		t.Fatalf("active=%d retiring=%d", active, retiring)
	}
}
