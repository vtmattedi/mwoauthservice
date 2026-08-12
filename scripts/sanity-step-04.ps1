$ErrorActionPreference = "Stop"

Write-Host "== gofmt =="
gofmt -w ./cmd ./internal ./migrations

Write-Host "== go test =="
go test ./...

Write-Host "== go vet =="
go vet ./...

Write-Host ""
Write-Host "Step 04 sanity checks passed."
Write-Host ""
Write-Host "Before starting the server, configure:"
Write-Host "  CALLBACK_SECRET_KEYS=1:<32-byte-base64url-key>"
Write-Host "  CALLBACK_SECRET_ACTIVE_KEY_VERSION=1"
