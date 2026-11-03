package sqlite

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vtmattedi/mw-oauth-service/internal/domain"
	"github.com/vtmattedi/mw-oauth-service/internal/googlecred"
	"github.com/vtmattedi/mw-oauth-service/internal/project"
)

const credNow = "2026-11-03T12:00:00.000Z"

func newCredentialStore(t *testing.T) (*Store, int64, int64) {
	t.Helper()

	store, err := Open(filepath.Join(t.TempDir(), "oauth.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	ids := make([]int64, 2)
	for i := range ids {
		created, err := store.CreateProject(context.Background(), project.CreateRecord{
			Name:                     fmt.Sprintf("app-%d", i),
			Enabled:                  true,
			CallbackSecretCiphertext: "ct",
			CallbackSecretNonce:      "n",
			CallbackSecretKeyVersion: 1,
		})
		if err != nil {
			t.Fatal(err)
		}
		ids[i] = created.ID
	}
	return store, ids[0], ids[1]
}

func record(id string, projectID int64) googlecred.NewRecord {
	return googlecred.NewRecord{
		ID:         id,
		ProjectID:  projectID,
		ClientID:   id + ".apps.googleusercontent.com",
		Ciphertext: "ciphertext-" + id,
		Nonce:      "nonce-" + id,
		KeyVersion: 1,
	}
}

func TestActivateCredentialRotatesAtomically(t *testing.T) {
	store, p1, _ := newCredentialStore(t)
	ctx := context.Background()

	first, retired, err := store.ActivateCredential(ctx, record("gcred_1", p1), credNow)
	if err != nil || retired != nil {
		t.Fatalf("first activation: %v, retired=%v", err, retired)
	}
	if first.State != domain.GoogleCredentialActive || !first.SecretAvailable || first.KeyVersion != 1 {
		t.Fatalf("unexpected first credential: %+v", first)
	}

	second, retired, err := store.ActivateCredential(ctx, record("gcred_2", p1), "2026-11-03T13:00:00.000Z")
	if err != nil {
		t.Fatal(err)
	}
	if second.State != domain.GoogleCredentialActive {
		t.Fatalf("second state = %s", second.State)
	}
	if retired == nil || retired.ID != "gcred_1" || retired.State != domain.GoogleCredentialRetiring || retired.RetiredAt == "" {
		t.Fatalf("previous credential not retired: %+v", retired)
	}

	active, err := store.GetActiveCredential(ctx, p1)
	if err != nil || active.ID != "gcred_2" {
		t.Fatalf("active = %+v, %v", active, err)
	}
}

func TestActivateCredentialFailureLeavesPreviousActive(t *testing.T) {
	store, p1, _ := newCredentialStore(t)
	ctx := context.Background()

	if _, _, err := store.ActivateCredential(ctx, record("gcred_1", p1), credNow); err != nil {
		t.Fatal(err)
	}

	// Duplicate ID makes the insert fail after the demotion; the whole
	// activation must roll back.
	if _, _, err := store.ActivateCredential(ctx, record("gcred_1", p1), credNow); err == nil {
		t.Fatal("duplicate credential id should fail")
	}

	active, err := store.GetActiveCredential(ctx, p1)
	if err != nil || active.ID != "gcred_1" || active.State != domain.GoogleCredentialActive {
		t.Fatalf("previous credential not preserved: %+v, %v", active, err)
	}
}

func TestActivateCredentialUnknownProject(t *testing.T) {
	store, _, _ := newCredentialStore(t)
	if _, _, err := store.ActivateCredential(context.Background(), record("gcred_x", 9999), credNow); !errors.Is(err, googlecred.ErrProjectNotFound) {
		t.Fatalf("err = %v; want ErrProjectNotFound", err)
	}
}

func TestCredentialsAreScopedToProject(t *testing.T) {
	store, p1, p2 := newCredentialStore(t)
	ctx := context.Background()

	if _, _, err := store.ActivateCredential(ctx, record("gcred_1", p1), credNow); err != nil {
		t.Fatal(err)
	}

	if _, err := store.GetCredential(ctx, p2, "gcred_1"); !errors.Is(err, googlecred.ErrNotFound) {
		t.Fatalf("cross-project get: %v", err)
	}
	if _, err := store.GetCredentialSecret(ctx, p2, "gcred_1"); !errors.Is(err, googlecred.ErrNotFound) {
		t.Fatalf("cross-project secret: %v", err)
	}
	if _, err := store.TransitionCredential(ctx, p2, "gcred_1", domain.GoogleCredentialDisabled, credNow); !errors.Is(err, googlecred.ErrNotFound) {
		t.Fatalf("cross-project transition: %v", err)
	}
	if _, err := store.DeleteCredentialSecret(ctx, p2, "gcred_1", credNow); !errors.Is(err, googlecred.ErrNotFound) {
		t.Fatalf("cross-project delete: %v", err)
	}
	if err := store.MarkAuthorized(ctx, p2, "gcred_1", credNow); !errors.Is(err, googlecred.ErrNotFound) {
		t.Fatalf("cross-project mark: %v", err)
	}

	list, err := store.ListCredentials(ctx, p2)
	if err != nil || len(list) != 0 {
		t.Fatalf("other project list = %v, %v", list, err)
	}
	if _, err := store.GetActiveCredential(ctx, p2); !errors.Is(err, googlecred.ErrNotFound) {
		t.Fatalf("other project active: %v", err)
	}

	// Same state is untouched in the owning project.
	c, err := store.GetCredential(ctx, p1, "gcred_1")
	if err != nil || c.State != domain.GoogleCredentialActive {
		t.Fatalf("owner credential changed: %+v, %v", c, err)
	}
}

func TestMetadataReadsNeverExposeSecret(t *testing.T) {
	store, p1, _ := newCredentialStore(t)
	ctx := context.Background()

	if _, _, err := store.ActivateCredential(ctx, record("gcred_1", p1), credNow); err != nil {
		t.Fatal(err)
	}

	list, _ := store.ListCredentials(ctx, p1)
	one, _ := store.GetCredential(ctx, p1, "gcred_1")
	active, _ := store.GetActiveCredential(ctx, p1)

	for _, c := range append(list, one, active) {
		text := fmt.Sprintf("%+v", c)
		if strings.Contains(text, "ciphertext-gcred_1") || strings.Contains(text, "nonce-gcred_1") {
			t.Fatalf("metadata leaked secret material: %s", text)
		}
	}

	secret, err := store.GetCredentialSecret(ctx, p1, "gcred_1")
	if err != nil || secret.Ciphertext != "ciphertext-gcred_1" || secret.Nonce != "nonce-gcred_1" || secret.KeyVersion != 1 {
		t.Fatalf("secret record = %+v, %v", secret, err)
	}
}

func TestCredentialTransitions(t *testing.T) {
	store, p1, _ := newCredentialStore(t)
	ctx := context.Background()

	if _, _, err := store.ActivateCredential(ctx, record("gcred_1", p1), credNow); err != nil {
		t.Fatal(err)
	}

	retiring, err := store.TransitionCredential(ctx, p1, "gcred_1", domain.GoogleCredentialRetiring, credNow)
	if err != nil || retiring.State != domain.GoogleCredentialRetiring || retiring.RetiredAt == "" {
		t.Fatalf("retire: %+v, %v", retiring, err)
	}

	// retiring -> retiring and retiring -> active are not allowed.
	if _, err := store.TransitionCredential(ctx, p1, "gcred_1", domain.GoogleCredentialRetiring, credNow); !errors.Is(err, googlecred.ErrInvalidTransition) {
		t.Fatalf("retire twice: %v", err)
	}
	if _, err := store.TransitionCredential(ctx, p1, "gcred_1", domain.GoogleCredentialActive, credNow); !errors.Is(err, googlecred.ErrInvalidTransition) {
		t.Fatalf("reactivate: %v", err)
	}

	disabled, err := store.TransitionCredential(ctx, p1, "gcred_1", domain.GoogleCredentialDisabled, credNow)
	if err != nil || disabled.State != domain.GoogleCredentialDisabled || disabled.DisabledAt == "" {
		t.Fatalf("disable: %+v, %v", disabled, err)
	}
	if _, err := store.TransitionCredential(ctx, p1, "gcred_1", domain.GoogleCredentialDisabled, credNow); !errors.Is(err, googlecred.ErrInvalidTransition) {
		t.Fatalf("disable twice: %v", err)
	}
	if _, err := store.TransitionCredential(ctx, p1, "gcred_1", domain.GoogleCredentialRetiring, credNow); !errors.Is(err, googlecred.ErrInvalidTransition) {
		t.Fatalf("disabled -> retiring: %v", err)
	}
}

func TestCompromisedActiveCredentialCanBeDisabledDirectly(t *testing.T) {
	store, p1, _ := newCredentialStore(t)
	ctx := context.Background()

	if _, _, err := store.ActivateCredential(ctx, record("gcred_1", p1), credNow); err != nil {
		t.Fatal(err)
	}
	disabled, err := store.TransitionCredential(ctx, p1, "gcred_1", domain.GoogleCredentialDisabled, credNow)
	if err != nil || disabled.State != domain.GoogleCredentialDisabled || disabled.RetiredAt != "" {
		t.Fatalf("direct disable: %+v, %v", disabled, err)
	}
	if _, err := store.GetActiveCredential(ctx, p1); !errors.Is(err, googlecred.ErrNotFound) {
		t.Fatalf("no credential should be active: %v", err)
	}
}

func TestDeleteCredentialSecretLeavesTombstone(t *testing.T) {
	store, p1, _ := newCredentialStore(t)
	ctx := context.Background()

	if _, _, err := store.ActivateCredential(ctx, record("gcred_1", p1), credNow); err != nil {
		t.Fatal(err)
	}

	// Only a disabled credential can lose its secret.
	if _, err := store.DeleteCredentialSecret(ctx, p1, "gcred_1", credNow); !errors.Is(err, googlecred.ErrInvalidTransition) {
		t.Fatalf("delete active secret: %v", err)
	}

	if _, err := store.TransitionCredential(ctx, p1, "gcred_1", domain.GoogleCredentialDisabled, credNow); err != nil {
		t.Fatal(err)
	}
	tomb, err := store.DeleteCredentialSecret(ctx, p1, "gcred_1", credNow)
	if err != nil || tomb.SecretAvailable || tomb.SecretDeletedAt == "" || tomb.State != domain.GoogleCredentialDisabled {
		t.Fatalf("tombstone: %+v, %v", tomb, err)
	}

	if _, err := store.GetCredentialSecret(ctx, p1, "gcred_1"); !errors.Is(err, googlecred.ErrSecretUnavailable) {
		t.Fatalf("secret after delete: %v", err)
	}

	// Row stays for audit/reference and a second delete is idempotent.
	if _, err := store.GetCredential(ctx, p1, "gcred_1"); err != nil {
		t.Fatalf("tombstone should remain readable: %v", err)
	}
	if _, err := store.DeleteCredentialSecret(ctx, p1, "gcred_1", credNow); err != nil {
		t.Fatalf("second delete: %v", err)
	}

	var cipher, nonce *string
	if err := store.DB().QueryRow(
		`SELECT secret_ciphertext, secret_nonce FROM google_client_credentials WHERE id = 'gcred_1'`,
	).Scan(&cipher, &nonce); err != nil || cipher != nil || nonce != nil {
		t.Fatalf("secret material still stored: %v %v %v", cipher, nonce, err)
	}
}

func TestMarkAuthorizedAndRefreshed(t *testing.T) {
	store, p1, _ := newCredentialStore(t)
	ctx := context.Background()

	if _, _, err := store.ActivateCredential(ctx, record("gcred_1", p1), credNow); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkAuthorized(ctx, p1, "gcred_1", "2026-11-03T14:00:00.000Z"); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkRefreshed(ctx, p1, "gcred_1", "2026-11-03T15:00:00.000Z"); err != nil {
		t.Fatal(err)
	}

	c, _ := store.GetCredential(ctx, p1, "gcred_1")
	if c.LastAuthorizedAt != "2026-11-03T14:00:00.000Z" || c.LastRefreshedAt != "2026-11-03T15:00:00.000Z" {
		t.Fatalf("usage timestamps = %+v", c)
	}
}
