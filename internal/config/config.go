// MW_OAUTH_STEP_01
package config

import (
	"fmt"
	"log/slog"
	"math"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/vtmattedi/mw-oauth-service/internal/federation"
)

type Config struct {
	AppEnv                             string
	Port                               string
	DatabasePath                       string
	LogLevel                           slog.Level
	AdminOrigins                       []string
	CheckSPHost                        bool
	SPHost                             string
	AdminSessionCookie                 string
	WebAuthnRPID                       string
	WebAuthnRPName                     string
	WebAuthnOrigins                    []string
	WebAuthnCredentialKeys             string
	WebAuthnCredentialActiveKeyVersion int
	CallbackSecretKeys                 string
	CallbackSecretActiveKeyVersion     int
	GoogleClientSecretKeys             string
	GoogleClientSecretActiveKeyVersion int
	GoogleClientID                     string
	GoogleClientSecret                 string
	GoogleRedirectURI                  string
	TokenEncryptionKey                 string
	AdminAuthMode                      federation.Mode
	IdentityInternalBaseURL            string
	IdentityIntrospectionClientID      string
	IdentityIntrospectionClientSecret  string
	IdentityAudience                   string
	IdentityHTTPTimeout                time.Duration
}

func Load() (Config, error) {
	cfg := Config{
		AppEnv:       strings.TrimSpace(os.Getenv("APP_ENV")),
		Port:         strings.TrimSpace(os.Getenv("PORT")),
		DatabasePath: strings.TrimSpace(os.Getenv("DATABASE_PATH")),
	}

	if cfg.AppEnv == "" {
		cfg.AppEnv = "development"
	}
	if cfg.Port == "" {
		cfg.Port = "8282"
	}
	if cfg.DatabasePath == "" {
		cfg.DatabasePath = "./data/oauth.db"
	}

	level, err := parseLogLevel(os.Getenv("LOG_LEVEL"))
	if err != nil {
		return Config{}, err
	}
	cfg.LogLevel = level

	cfg.AdminOrigins = compactStrings(
		os.Getenv("ADMIN_ORIGIN"),
		os.Getenv("ADMIN_DEV_ORIGIN"),
	)

	checkSPHost, err := parseBoolEnv(
		"CHECK_SP_HOST",
		os.Getenv("CHECK_SP_HOST"),
		false,
	)
	if err != nil {
		return Config{}, err
	}
	cfg.CheckSPHost = checkSPHost
	cfg.SPHost = strings.TrimSpace(os.Getenv("SP_HOST"))

	if cfg.CheckSPHost && cfg.SPHost == "" {
		return Config{}, fmt.Errorf(
			"SP_HOST is required when CHECK_SP_HOST=true",
		)
	}

	cfg.AdminSessionCookie = strings.TrimSpace(
		os.Getenv("ADMIN_SESSION_COOKIE"),
	)
	if cfg.AdminSessionCookie == "" {
		cfg.AdminSessionCookie = "mw_oauth_admin_session"
	}

	cfg.WebAuthnRPID = strings.TrimSpace(
		os.Getenv("WEBAUTHN_RP_ID"),
	)
	if cfg.WebAuthnRPID == "" {
		cfg.WebAuthnRPID = "oauth.mattediworks.com"
	}

	cfg.WebAuthnRPName = strings.TrimSpace(
		os.Getenv("WEBAUTHN_RP_NAME"),
	)
	if cfg.WebAuthnRPName == "" {
		cfg.WebAuthnRPName = "MW OAuth"
	}

	cfg.WebAuthnOrigins = splitCommaStrings(
		os.Getenv("WEBAUTHN_ORIGINS"),
	)

	cfg.WebAuthnCredentialKeys = strings.TrimSpace(
		os.Getenv("WEBAUTHN_CREDENTIAL_KEYS"),
	)

	webAuthnVersionRaw := strings.TrimSpace(
		os.Getenv("WEBAUTHN_CREDENTIAL_ACTIVE_KEY_VERSION"),
	)
	if webAuthnVersionRaw == "" {
		cfg.WebAuthnCredentialActiveKeyVersion = 1
	} else {
		version, err := strconv.Atoi(webAuthnVersionRaw)
		if err != nil || version <= 0 {
			return Config{}, fmt.Errorf(
				"invalid WEBAUTHN_CREDENTIAL_ACTIVE_KEY_VERSION %q",
				webAuthnVersionRaw,
			)
		}
		cfg.WebAuthnCredentialActiveKeyVersion = version
	}

	cfg.CallbackSecretKeys = strings.TrimSpace(
		os.Getenv("CALLBACK_SECRET_KEYS"),
	)

	activeVersionRaw := strings.TrimSpace(
		os.Getenv("CALLBACK_SECRET_ACTIVE_KEY_VERSION"),
	)
	if activeVersionRaw == "" {
		cfg.CallbackSecretActiveKeyVersion = 1
	} else {
		activeVersion, err := strconv.Atoi(activeVersionRaw)
		if err != nil || activeVersion <= 0 {
			return Config{}, fmt.Errorf(
				"invalid CALLBACK_SECRET_ACTIVE_KEY_VERSION %q",
				activeVersionRaw,
			)
		}
		cfg.CallbackSecretActiveKeyVersion = activeVersion
	}

	// Per-project Google client secret keyring. Optional: when empty, the
	// per-project credential feature is unavailable and only the legacy
	// global client can be used.
	cfg.GoogleClientSecretKeys = strings.TrimSpace(
		os.Getenv("GOOGLE_CLIENT_SECRET_KEYS"),
	)

	googleKeyVersionRaw := strings.TrimSpace(
		os.Getenv("GOOGLE_CLIENT_SECRET_ACTIVE_KEY_VERSION"),
	)
	if googleKeyVersionRaw == "" {
		cfg.GoogleClientSecretActiveKeyVersion = 1
	} else {
		version, err := strconv.Atoi(googleKeyVersionRaw)
		if err != nil || version <= 0 {
			return Config{}, fmt.Errorf(
				"invalid GOOGLE_CLIENT_SECRET_ACTIVE_KEY_VERSION %q",
				googleKeyVersionRaw,
			)
		}
		cfg.GoogleClientSecretActiveKeyVersion = version
	}

	cfg.GoogleClientID = strings.TrimSpace(
		os.Getenv("GOOGLE_CLIENT_ID"),
	)

	cfg.GoogleClientSecret = strings.TrimSpace(
		os.Getenv("GOOGLE_CLIENT_SECRET"),
	)

	cfg.GoogleRedirectURI = strings.TrimSpace(
		os.Getenv("GOOGLE_REDIRECT_URI"),
	)
	if cfg.GoogleRedirectURI == "" {
		cfg.GoogleRedirectURI =
			"https://oauth.mattediworks.com/oauth/google/callback"
	}

	cfg.TokenEncryptionKey = strings.TrimSpace(
		os.Getenv("TOKEN_ENCRYPTION_KEY"),
	)

	cfg.AdminAuthMode, err = federation.ParseMode(os.Getenv("ADMIN_AUTH_MODE"))
	if err != nil {
		return Config{}, err
	}
	cfg.IdentityInternalBaseURL = strings.TrimSpace(
		os.Getenv("MW_IDENTITY_INTERNAL_BASE_URL"),
	)
	cfg.IdentityIntrospectionClientID = strings.TrimSpace(
		os.Getenv("MW_IDENTITY_INTROSPECTION_CLIENT_ID"),
	)
	cfg.IdentityIntrospectionClientSecret = os.Getenv(
		"MW_IDENTITY_INTROSPECTION_CLIENT_SECRET",
	)
	cfg.IdentityAudience = strings.TrimSpace(
		os.Getenv("MW_IDENTITY_AUDIENCE"),
	)
	if cfg.IdentityAudience == "" {
		cfg.IdentityAudience = "mw-oauth"
	}

	timeoutRaw := strings.TrimSpace(
		os.Getenv("MW_IDENTITY_HTTP_TIMEOUT_SECONDS"),
	)
	timeoutSeconds := 5.0
	if timeoutRaw != "" {
		timeoutSeconds, err = strconv.ParseFloat(timeoutRaw, 64)
		if err != nil || timeoutSeconds <= 0 ||
			math.IsNaN(timeoutSeconds) || math.IsInf(timeoutSeconds, 0) {
			return Config{}, fmt.Errorf(
				"invalid MW_IDENTITY_HTTP_TIMEOUT_SECONDS %q",
				timeoutRaw,
			)
		}
	}
	cfg.IdentityHTTPTimeout = time.Duration(
		timeoutSeconds * float64(time.Second),
	)
	if cfg.IdentityHTTPTimeout <= 0 {
		return Config{}, fmt.Errorf(
			"invalid MW_IDENTITY_HTTP_TIMEOUT_SECONDS %q",
			timeoutRaw,
		)
	}

	if cfg.AdminAuthMode != federation.ModeLocal {
		if cfg.IdentityInternalBaseURL == "" ||
			cfg.IdentityIntrospectionClientID == "" ||
			cfg.IdentityIntrospectionClientSecret == "" ||
			cfg.IdentityAudience == "" {
			return Config{}, fmt.Errorf(
				"MW Identity configuration is required when ADMIN_AUTH_MODE=%s",
				cfg.AdminAuthMode,
			)
		}
	}

	return cfg, nil
}

func parseLogLevel(raw string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "info":
		return slog.LevelInfo, nil
	case "debug":
		return slog.LevelDebug, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("invalid LOG_LEVEL %q", raw)
	}
}

func parseBoolEnv(
	name string,
	raw string,
	defaultValue bool,
) (bool, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return defaultValue, nil
	}

	value, err := strconv.ParseBool(raw)
	if err != nil {
		return false, fmt.Errorf("invalid %s %q", name, raw)
	}

	return value, nil
}

func compactStrings(values ...string) []string {
	result := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))

	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}

		seen[value] = struct{}{}
		result = append(result, value)
	}

	return result
}

func splitCommaStrings(raw string) []string {
	parts := strings.Split(raw, ",")
	result := make([]string, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))

	for _, value := range parts {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}

	return result
}
