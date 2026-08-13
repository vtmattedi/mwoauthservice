$ErrorActionPreference = "Stop"

Write-Host "== gofmt =="
gofmt -w ./cmd ./internal ./migrations

Write-Host "== go test =="
go test ./...

Write-Host "== go vet =="
go vet ./...

Write-Host ""
Write-Host "Step 06 sanity checks passed."
Write-Host ""
Write-Host "Required Step 06 env:"
Write-Host "  GOOGLE_CLIENT_ID=<google oauth client id>"
Write-Host "  GOOGLE_REDIRECT_URI=https://oauth.mattediworks.com/oauth/google/callback"
Write-Host "  TOKEN_ENCRYPTION_KEY=<base64url encoded 32-byte key>"
