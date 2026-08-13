$ErrorActionPreference = "Stop"

Write-Host "== gofmt =="
gofmt -w ./cmd ./internal ./migrations

Write-Host "== go test =="
go test ./...

Write-Host "== go vet =="
go vet ./...

Write-Host ""
Write-Host "Step 07 sanity checks passed."
Write-Host ""
Write-Host "Required Step 07 env:"
Write-Host "  GOOGLE_CLIENT_SECRET=<Google OAuth client secret>"
