// MW_OAUTH_STEP_01
package config

import (
	"fmt"
	"log/slog"
	"os"
	"strings"
)

type Config struct {
	AppEnv       string
	Port         string
	DatabasePath string
	LogLevel     slog.Level
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
