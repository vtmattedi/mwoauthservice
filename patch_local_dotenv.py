#!/usr/bin/env python3
from __future__ import annotations

import datetime as dt
import shutil
import subprocess
import sys
from pathlib import Path

ENVFILE_GO = 'package envfile\n\nimport (\n    "errors"\n    "fmt"\n    "os"\n    "strings"\n\n    "github.com/joho/godotenv"\n)\n\n// LoadDevelopment loads .env only for local/development execution.\n//\n// Rules:\n//   - If APP_ENV is unset, treat the process as a local development run.\n//   - If APP_ENV is "development" or "local", load .env.\n//   - Any other explicit APP_ENV (production, staging, test, etc.) skips .env.\n//   - Existing process environment variables are preserved.\n//   - A missing .env file is not an error.\nfunc LoadDevelopment() error {\n    appEnv := strings.ToLower(\n        strings.TrimSpace(os.Getenv("APP_ENV")),\n    )\n\n    switch appEnv {\n    case "", "development", "local":\n    default:\n        return nil\n    }\n\n    err := godotenv.Load(".env")\n    if err == nil {\n        return nil\n    }\n\n    if errors.Is(err, os.ErrNotExist) {\n        return nil\n    }\n\n    return fmt.Errorf("load development .env: %w", err)\n}\n'
ENVFILE_TEST_GO = 'package envfile\n\nimport (\n    "os"\n    "path/filepath"\n    "testing"\n)\n\nfunc withTempWorkingDir(t *testing.T) string {\n    t.Helper()\n\n    old, err := os.Getwd()\n    if err != nil {\n        t.Fatal(err)\n    }\n\n    dir := t.TempDir()\n    if err := os.Chdir(dir); err != nil {\n        t.Fatal(err)\n    }\n\n    t.Cleanup(func() {\n        if err := os.Chdir(old); err != nil {\n            t.Errorf("restore cwd: %v", err)\n        }\n    })\n\n    return dir\n}\n\nfunc TestLoadDevelopmentLoadsDotEnvWhenAppEnvUnset(\n    t *testing.T,\n) {\n    dir := withTempWorkingDir(t)\n\n    key := "MW_OAUTH_DOTENV_TEST_UNSET"\n    t.Cleanup(func() {\n        _ = os.Unsetenv(key)\n    })\n    _ = os.Unsetenv(key)\n    _ = os.Unsetenv("APP_ENV")\n    t.Cleanup(func() {\n        _ = os.Unsetenv("APP_ENV")\n    })\n\n    if err := os.WriteFile(\n        filepath.Join(dir, ".env"),\n        []byte(key+"=from-dotenv\\n"),\n        0o600,\n    ); err != nil {\n        t.Fatal(err)\n    }\n\n    if err := LoadDevelopment(); err != nil {\n        t.Fatal(err)\n    }\n\n    if got := os.Getenv(key); got != "from-dotenv" {\n        t.Fatalf("%s = %q; want from-dotenv", key, got)\n    }\n}\n\nfunc TestLoadDevelopmentPreservesExistingEnvironment(\n    t *testing.T,\n) {\n    dir := withTempWorkingDir(t)\n\n    key := "MW_OAUTH_DOTENV_TEST_EXISTING"\n    t.Setenv("APP_ENV", "development")\n    t.Setenv(key, "from-process")\n\n    if err := os.WriteFile(\n        filepath.Join(dir, ".env"),\n        []byte(key+"=from-dotenv\\n"),\n        0o600,\n    ); err != nil {\n        t.Fatal(err)\n    }\n\n    if err := LoadDevelopment(); err != nil {\n        t.Fatal(err)\n    }\n\n    if got := os.Getenv(key); got != "from-process" {\n        t.Fatalf("%s = %q; want from-process", key, got)\n    }\n}\n\nfunc TestLoadDevelopmentSkipsProductionDotEnv(\n    t *testing.T,\n) {\n    dir := withTempWorkingDir(t)\n\n    key := "MW_OAUTH_DOTENV_TEST_PRODUCTION"\n    t.Setenv("APP_ENV", "production")\n    t.Cleanup(func() {\n        _ = os.Unsetenv(key)\n    })\n    _ = os.Unsetenv(key)\n\n    if err := os.WriteFile(\n        filepath.Join(dir, ".env"),\n        []byte(key+"=should-not-load\\n"),\n        0o600,\n    ); err != nil {\n        t.Fatal(err)\n    }\n\n    if err := LoadDevelopment(); err != nil {\n        t.Fatal(err)\n    }\n\n    if got := os.Getenv(key); got != "" {\n        t.Fatalf("%s = %q; want empty", key, got)\n    }\n}\n\nfunc TestLoadDevelopmentAllowsMissingDotEnv(\n    t *testing.T,\n) {\n    withTempWorkingDir(t)\n    t.Setenv("APP_ENV", "development")\n\n    if err := LoadDevelopment(); err != nil {\n        t.Fatalf("missing .env returned error: %v", err)\n    }\n}\n'
DOCS_APPEND = '\n---\n\n## Local `.env` loading\n\nFor local/direct execution, the server loads `.env` before calling\n`config.Load()` when `APP_ENV` is:\n\n```text\nunset\ndevelopment\nlocal\n```\n\nExamples:\n\n```powershell\ngo run ./cmd/server\n```\n\nor:\n\n```powershell\ngo run cmd/server/main.go\n```\n\ncan therefore use the repository `.env` file directly.\n\nAn explicitly configured non-development environment does not load `.env`:\n\n```text\nAPP_ENV=production\nAPP_ENV=staging\nAPP_ENV=test\n```\n\nEnvironment variables already present in the process take precedence over\nvalues from `.env`.\n\nDocker/production configuration remains environment-native; `.env` loading is\nonly a local-development convenience and is not used when production\n`APP_ENV` is explicitly set.\n'


def fail(message: str) -> None:
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


def run(cmd: list[str], cwd: Path) -> None:
    print("+", " ".join(cmd))
    subprocess.run(cmd, cwd=cwd, check=True, text=True)


def backup(root: Path, path: Path, backup_dir: Path) -> None:
    if not path.exists():
        return

    rel = path.relative_to(root)
    dst = backup_dir / rel
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(path, dst)


def write_file(
    root: Path,
    path: Path,
    content: str,
    backup_dir: Path,
) -> None:
    if path.exists():
        current = path.read_text(encoding="utf-8")
        if current == content:
            print(f"unchanged: {path.relative_to(root)}")
            return
        backup(root, path, backup_dir)

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    print(f"wrote: {path.relative_to(root)}")


def patch_main(src: str) -> str:
    out = src

    import_line = (
        '"github.com/vtmattedi/mw-oauth-service/internal/envfile"'
    )
    if import_line not in out:
        anchor = (
            '"github.com/vtmattedi/mw-oauth-service/internal/config"\n'
        )
        if anchor not in out:
            fail(
                "could not find config import in cmd/server/main.go; "
                "refusing to patch an unexpected main.go"
            )

        out = out.replace(
            anchor,
            anchor + "\t" + import_line + "\n",
            1,
        )

    load_block = """\tif err := envfile.LoadDevelopment(); err != nil {
\t\tslog.Error(
\t\t\t"development .env load failed",
\t\t\t"error",
\t\t\terr,
\t\t)
\t\tos.Exit(1)
\t}

"""

    if "envfile.LoadDevelopment()" not in out:
        anchor = "func main() {\n"
        config_anchor = "\tcfg, err := config.Load()\n"

        if anchor not in out or config_anchor not in out:
            fail(
                "could not find expected config.Load startup flow in "
                "cmd/server/main.go; refusing to patch"
            )

        out = out.replace(
            config_anchor,
            load_block + config_anchor,
            1,
        )

    return out


def patch_docs(src: str) -> str:
    if "## Local `.env` loading" in src:
        return src

    return src.rstrip() + "\n" + DOCS_APPEND


def patch_file(
    root: Path,
    path: Path,
    transform,
    backup_dir: Path,
) -> None:
    if not path.exists():
        fail(f"missing required file: {path.relative_to(root)}")

    old = path.read_text(encoding="utf-8")
    new = transform(old)

    if new == old:
        print(f"unchanged: {path.relative_to(root)}")
        return

    backup(root, path, backup_dir)
    path.write_text(new, encoding="utf-8")
    print(f"patched: {path.relative_to(root)}")


def main() -> None:
    root = Path.cwd().resolve()

    required = [
        root / "go.mod",
        root / "cmd/server/main.go",
        root / "internal/config/config.go",
    ]
    for path in required:
        if not path.exists():
            fail(
                f"missing expected repository file: "
                f"{path.relative_to(root)}"
            )

    print("== Preflight ==")
    try:
        run(["go", "test", "./..."], root)
        run(["go", "vet", "./..."], root)
    except subprocess.CalledProcessError as exc:
        fail(
            f"preflight failed with exit code {exc.returncode}; "
            "no dotenv patch was applied"
        )

    backup_root = root / ".backups"
    backup_root.mkdir(parents=True, exist_ok=True)

    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    backup_dir = (
        backup_root
        / f"local-dotenv-{stamp}"
    )
    backup_dir.mkdir(parents=True, exist_ok=False)
    print(f"backup: {backup_dir.relative_to(root)}")

    patch_file(
        root,
        root / "cmd/server/main.go",
        patch_main,
        backup_dir,
    )

    docs = root / "docs/development-steps.md"
    if docs.exists():
        patch_file(
            root,
            docs,
            patch_docs,
            backup_dir,
        )

    write_file(
        root,
        root / "internal/envfile/load.go",
        ENVFILE_GO,
        backup_dir,
    )
    write_file(
        root,
        root / "internal/envfile/load_test.go",
        ENVFILE_TEST_GO,
        backup_dir,
    )

    try:
        print("")
        print("* pin godotenv v1.5.1")
        run(
            [
                "go",
                "get",
                "github.com/joho/godotenv@v1.5.1",
            ],
            root,
        )

        run(["go", "mod", "tidy"], root)

        run(
            [
                "gofmt",
                "-w",
                "cmd/server/main.go",
                "internal/envfile/load.go",
                "internal/envfile/load_test.go",
            ],
            root,
        )

        run(["go", "test", "./..."], root)
        run(["go", "vet", "./..."], root)
    except FileNotFoundError:
        fail("Go toolchain not found in PATH")
    except subprocess.CalledProcessError as exc:
        fail(
            f"dotenv patch sanity failed with exit code "
            f"{exc.returncode}."
        )

    print("")
    print("Local .env loading patch passed.")
    print("")
    print("Behavior:")
    print("  APP_ENV unset        -> load .env")
    print("  APP_ENV=development  -> load .env")
    print("  APP_ENV=local        -> load .env")
    print("  APP_ENV=production   -> do not load .env")
    print("  existing env values  -> keep precedence")
    print("")
    print("Now test:")
    print("  go run ./cmd/server")


if __name__ == "__main__":
    main()
