// MW_OAUTH_STEP_01
package config

import (
	"log/slog"
	"testing"
	"time"

	"github.com/vtmattedi/mw-oauth-service/internal/federation"
)

func TestParseLogLevel(t *testing.T) {
	tests := []struct {
		input string
		want  slog.Level
	}{
		{"", slog.LevelInfo},
		{"debug", slog.LevelDebug},
		{"INFO", slog.LevelInfo},
		{"warn", slog.LevelWarn},
		{"error", slog.LevelError},
	}

	for _, tt := range tests {
		got, err := parseLogLevel(tt.input)
		if err != nil {
			t.Fatalf("parseLogLevel(%q): %v", tt.input, err)
		}
		if got != tt.want {
			t.Fatalf("parseLogLevel(%q) = %v; want %v", tt.input, got, tt.want)
		}
	}
}

func TestLoadFederationConfiguration(t *testing.T) {
	t.Setenv("ADMIN_AUTH_MODE", "hybrid")
	t.Setenv("MW_IDENTITY_INTERNAL_BASE_URL", "http://identity.internal:7100")
	t.Setenv("MW_IDENTITY_INTROSPECTION_CLIENT_ID", "mw-oauth-resource")
	t.Setenv("MW_IDENTITY_INTROSPECTION_CLIENT_SECRET", "secret")
	t.Setenv("MW_IDENTITY_AUDIENCE", "mw-oauth")
	t.Setenv("MW_IDENTITY_HTTP_TIMEOUT_SECONDS", "2.5")

	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AdminAuthMode != federation.ModeHybrid || cfg.IdentityHTTPTimeout != 2500*time.Millisecond {
		t.Fatalf("unexpected federation config: mode=%s timeout=%s", cfg.AdminAuthMode, cfg.IdentityHTTPTimeout)
	}
}

func TestLoadFederationRequiresIdentityConfiguration(t *testing.T) {
	t.Setenv("ADMIN_AUTH_MODE", "federated")
	t.Setenv("MW_IDENTITY_INTERNAL_BASE_URL", "")
	t.Setenv("MW_IDENTITY_INTROSPECTION_CLIENT_ID", "")
	t.Setenv("MW_IDENTITY_INTROSPECTION_CLIENT_SECRET", "")
	if _, err := Load(); err == nil {
		t.Fatal("expected missing Identity configuration to fail")
	}
}

func TestLoadDefaultsToLocalAuth(t *testing.T) {
	t.Setenv("ADMIN_AUTH_MODE", "")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AdminAuthMode != federation.ModeLocal || cfg.IdentityAudience != "mw-oauth" || cfg.IdentityHTTPTimeout != 5*time.Second {
		t.Fatalf("unexpected defaults: %+v", cfg)
	}
}

func TestLoadRejectsInvalidAdminAuthMode(t *testing.T) {
	t.Setenv("ADMIN_AUTH_MODE", "fallback")
	if _, err := Load(); err == nil {
		t.Fatal("expected invalid ADMIN_AUTH_MODE to fail")
	}
}

func TestLoadGoogleClientSecretKeyring(t *testing.T) {
	t.Setenv("ADMIN_AUTH_MODE", "")
	t.Setenv("GOOGLE_CLIENT_SECRET_KEYS", "")
	t.Setenv("GOOGLE_CLIENT_SECRET_ACTIVE_KEY_VERSION", "")

	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.GoogleClientSecretKeys != "" || cfg.GoogleClientSecretActiveKeyVersion != 1 {
		t.Fatalf("unexpected defaults: %q %d", cfg.GoogleClientSecretKeys, cfg.GoogleClientSecretActiveKeyVersion)
	}

	t.Setenv("GOOGLE_CLIENT_SECRET_KEYS", "2:abc")
	t.Setenv("GOOGLE_CLIENT_SECRET_ACTIVE_KEY_VERSION", "2")
	cfg, err = Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.GoogleClientSecretKeys != "2:abc" || cfg.GoogleClientSecretActiveKeyVersion != 2 {
		t.Fatalf("unexpected values: %q %d", cfg.GoogleClientSecretKeys, cfg.GoogleClientSecretActiveKeyVersion)
	}

	t.Setenv("GOOGLE_CLIENT_SECRET_ACTIVE_KEY_VERSION", "0")
	if _, err := Load(); err == nil {
		t.Fatal("expected non-positive active version to fail")
	}
}

func TestLoadAppAccessTokenTTL(t *testing.T) {
	t.Setenv("ADMIN_AUTH_MODE", "")
	t.Setenv("MW_APP_ACCESS_TOKEN_TTL_SECONDS", "")

	cfg, err := Load()
	if err != nil || cfg.AppAccessTokenTTL != 900*time.Second {
		t.Fatalf("default = %v, %v", cfg.AppAccessTokenTTL, err)
	}

	t.Setenv("MW_APP_ACCESS_TOKEN_TTL_SECONDS", "120")
	cfg, err = Load()
	if err != nil || cfg.AppAccessTokenTTL != 120*time.Second {
		t.Fatalf("custom = %v, %v", cfg.AppAccessTokenTTL, err)
	}

	for _, bad := range []string{"0", "59", "3601", "-5", "abc", "900s"} {
		t.Setenv("MW_APP_ACCESS_TOKEN_TTL_SECONDS", bad)
		if _, err := Load(); err == nil {
			t.Fatalf("%q should be rejected", bad)
		}
	}
}

func TestParseLogLevelRejectsInvalid(t *testing.T) {
	if _, err := parseLogLevel("verbose"); err == nil {
		t.Fatal("expected invalid LOG_LEVEL to fail")
	}
}
