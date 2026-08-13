package envfile

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/joho/godotenv"
)

// LoadDevelopment loads .env only for local/development execution.
//
// Rules:
//   - If APP_ENV is unset, treat the process as a local development run.
//   - If APP_ENV is "development" or "local", load .env.
//   - Any other explicit APP_ENV (production, staging, test, etc.) skips .env.
//   - Existing process environment variables are preserved.
//   - A missing .env file is not an error.
func LoadDevelopment() error {
	appEnv := strings.ToLower(
		strings.TrimSpace(os.Getenv("APP_ENV")),
	)

	switch appEnv {
	case "", "development", "local":
	default:
		return nil
	}

	err := godotenv.Load(".env")
	if err == nil {
		return nil
	}

	if errors.Is(err, os.ErrNotExist) {
		return nil
	}

	return fmt.Errorf("load development .env: %w", err)
}
