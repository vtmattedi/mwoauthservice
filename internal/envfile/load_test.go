package envfile

import (
	"os"
	"path/filepath"
	"testing"
)

func withTempWorkingDir(t *testing.T) string {
	t.Helper()

	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() {
		if err := os.Chdir(old); err != nil {
			t.Errorf("restore cwd: %v", err)
		}
	})

	return dir
}

func TestLoadDevelopmentLoadsDotEnvWhenAppEnvUnset(
	t *testing.T,
) {
	dir := withTempWorkingDir(t)

	key := "MW_OAUTH_DOTENV_TEST_UNSET"
	t.Cleanup(func() {
		_ = os.Unsetenv(key)
	})
	_ = os.Unsetenv(key)
	_ = os.Unsetenv("APP_ENV")
	t.Cleanup(func() {
		_ = os.Unsetenv("APP_ENV")
	})

	if err := os.WriteFile(
		filepath.Join(dir, ".env"),
		[]byte(key+"=from-dotenv\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}

	if err := LoadDevelopment(); err != nil {
		t.Fatal(err)
	}

	if got := os.Getenv(key); got != "from-dotenv" {
		t.Fatalf("%s = %q; want from-dotenv", key, got)
	}
}

func TestLoadDevelopmentPreservesExistingEnvironment(
	t *testing.T,
) {
	dir := withTempWorkingDir(t)

	key := "MW_OAUTH_DOTENV_TEST_EXISTING"
	t.Setenv("APP_ENV", "development")
	t.Setenv(key, "from-process")

	if err := os.WriteFile(
		filepath.Join(dir, ".env"),
		[]byte(key+"=from-dotenv\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}

	if err := LoadDevelopment(); err != nil {
		t.Fatal(err)
	}

	if got := os.Getenv(key); got != "from-process" {
		t.Fatalf("%s = %q; want from-process", key, got)
	}
}

func TestLoadDevelopmentSkipsProductionDotEnv(
	t *testing.T,
) {
	dir := withTempWorkingDir(t)

	key := "MW_OAUTH_DOTENV_TEST_PRODUCTION"
	t.Setenv("APP_ENV", "production")
	t.Cleanup(func() {
		_ = os.Unsetenv(key)
	})
	_ = os.Unsetenv(key)

	if err := os.WriteFile(
		filepath.Join(dir, ".env"),
		[]byte(key+"=should-not-load\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}

	if err := LoadDevelopment(); err != nil {
		t.Fatal(err)
	}

	if got := os.Getenv(key); got != "" {
		t.Fatalf("%s = %q; want empty", key, got)
	}
}

func TestLoadDevelopmentAllowsMissingDotEnv(
	t *testing.T,
) {
	withTempWorkingDir(t)
	t.Setenv("APP_ENV", "development")

	if err := LoadDevelopment(); err != nil {
		t.Fatalf("missing .env returned error: %v", err)
	}
}
