package project_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/vtmattedi/mw-oauth-service/internal/domain"
	"github.com/vtmattedi/mw-oauth-service/internal/project"
	"github.com/vtmattedi/mw-oauth-service/internal/secretbox"
	"github.com/vtmattedi/mw-oauth-service/internal/store/sqlite"
)

func TestProjectLifecycleAndGoogleConfig(t *testing.T) {
	store, err := sqlite.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	key := bytes.Repeat([]byte{0x37}, 32)
	encoded := base64.RawURLEncoding.EncodeToString(key)

	keyring, err := secretbox.NewKeyring("1:"+encoded, 1)
	if err != nil {
		t.Fatal(err)
	}

	service := project.NewService(store, keyring)

	credentials, err := service.Create(
		context.Background(),
		"Clinic Mantra",
		true,
	)
	if err != nil {
		t.Fatal(err)
	}

	if !strings.HasPrefix(credentials.APIKey, "mw_live_") {
		t.Fatal("unexpected API key prefix")
	}
	if !strings.HasPrefix(
		credentials.CallbackSecret,
		"mw_whsec_",
	) {
		t.Fatal("unexpected callback secret prefix")
	}

	found, err := service.LookupByAPIKey(
		context.Background(),
		credentials.APIKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	if found.ID != credentials.Project.ID {
		t.Fatalf(
			"lookup project id = %d; want %d",
			found.ID,
			credentials.Project.ID,
		)
	}

	var storedTokenHash string
	var ciphertext string
	if err := store.DB().QueryRow(
		`SELECT token_hash, callback_secret_ciphertext
         FROM projects
         WHERE id = ?`,
		credentials.Project.ID,
	).Scan(&storedTokenHash, &ciphertext); err != nil {
		t.Fatal(err)
	}

	if storedTokenHash == credentials.APIKey {
		t.Fatal("raw API key was stored")
	}
	if ciphertext == credentials.CallbackSecret {
		t.Fatal("raw callback secret was stored")
	}
	if strings.Contains(
		ciphertext,
		credentials.CallbackSecret,
	) {
		t.Fatal("ciphertext contains raw callback secret")
	}

	config, err := service.ConfigureGoogle(
		context.Background(),
		credentials.Project.ID,
		domain.GoogleOAuthConfig{
			Enabled: true,
			AllowedScopes: []string{
				"https://www.googleapis.com/auth/calendar",
			},
			AllowedCallbackURLs: []string{
				"https://app.example.com/api/oauth/google/result",
			},
			AllowedReturnURLs: []string{
				"https://app.example.com/settings/integrations",
			},
			Limits: domain.OAuthLimits{
				PerMinute:  10,
				PerHour:    100,
				MaxPending: 50,
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if !config.Enabled {
		t.Fatal("Google OAuth should be enabled")
	}

	loaded, err := service.GoogleConfig(
		context.Background(),
		credentials.Project.ID,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.AllowedScopes) != 1 {
		t.Fatalf(
			"allowed scopes = %d; want 1",
			len(loaded.AllowedScopes),
		)
	}

	oldAPIKey := credentials.APIKey
	newAPIKey, err := service.RotateAPIKey(
		context.Background(),
		credentials.Project.ID,
	)
	if err != nil {
		t.Fatal(err)
	}
	if newAPIKey == oldAPIKey {
		t.Fatal("API key rotation returned same key")
	}

	if _, err := service.LookupByAPIKey(
		context.Background(),
		oldAPIKey,
	); err == nil {
		t.Fatal("old API key still resolves after rotation")
	}

	if _, err := service.LookupByAPIKey(
		context.Background(),
		newAPIKey,
	); err != nil {
		t.Fatalf("new API key does not resolve: %v", err)
	}

	newCallbackSecret, err := service.RotateCallbackSecret(
		context.Background(),
		credentials.Project.ID,
	)
	if err != nil {
		t.Fatal(err)
	}
	if newCallbackSecret == credentials.CallbackSecret {
		t.Fatal("callback secret rotation returned same secret")
	}
}

func TestGoogleConfigRejectsUnsafeURLs(t *testing.T) {
	store, err := sqlite.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	key := bytes.Repeat([]byte{0x18}, 32)
	encoded := base64.RawURLEncoding.EncodeToString(key)
	keyring, err := secretbox.NewKeyring("1:"+encoded, 1)
	if err != nil {
		t.Fatal(err)
	}

	service := project.NewService(store, keyring)
	credentials, err := service.Create(
		context.Background(),
		"Test",
		true,
	)
	if err != nil {
		t.Fatal(err)
	}

	_, err = service.ConfigureGoogle(
		context.Background(),
		credentials.Project.ID,
		domain.GoogleOAuthConfig{
			Enabled:       true,
			AllowedScopes: []string{"scope"},
			AllowedCallbackURLs: []string{
				"https://*.example.com/oauth",
			},
			AllowedReturnURLs: []string{
				"https://app.example.com/return",
			},
		},
	)
	if err == nil {
		t.Fatal("expected wildcard callback URL to fail")
	}

	_, err = service.ConfigureGoogle(
		context.Background(),
		credentials.Project.ID,
		domain.GoogleOAuthConfig{
			Enabled:       true,
			AllowedScopes: []string{"scope"},
			AllowedCallbackURLs: []string{
				"http://app.example.com/oauth",
			},
			AllowedReturnURLs: []string{
				"https://app.example.com/return",
			},
		},
	)
	if err == nil {
		t.Fatal("expected remote http callback URL to fail")
	}
}

func TestGoogleConfigAllowsLocalHTTP(t *testing.T) {
	store, err := sqlite.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	key := bytes.Repeat([]byte{0x44}, 32)
	encoded := base64.RawURLEncoding.EncodeToString(key)
	keyring, err := secretbox.NewKeyring("1:"+encoded, 1)
	if err != nil {
		t.Fatal(err)
	}

	service := project.NewService(store, keyring)
	credentials, err := service.Create(
		context.Background(),
		"Local Dev",
		true,
	)
	if err != nil {
		t.Fatal(err)
	}

	_, err = service.ConfigureGoogle(
		context.Background(),
		credentials.Project.ID,
		domain.GoogleOAuthConfig{
			Enabled:       true,
			AllowedScopes: []string{"scope"},
			AllowedCallbackURLs: []string{
				"http://localhost:5173/api/oauth/google/result",
			},
			AllowedReturnURLs: []string{
				"http://127.0.0.1:5173/settings/integrations",
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
}
