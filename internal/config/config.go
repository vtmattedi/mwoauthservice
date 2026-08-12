// MW_OAUTH_STEP_01
package config

import (
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
)

type Config struct {
	AppEnv                         string
	Port                           string
	DatabasePath                   string
	LogLevel                       slog.Level
	AdminOrigins                   []string
	CheckSPHost                    bool
	SPHost                         string
	AdminSessionCookie             string
	CallbackSecretKeys             string
	CallbackSecretActiveKeyVersion int
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
