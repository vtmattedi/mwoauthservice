$ErrorActionPreference = "Stop"

Write-Host "== gofmt =="
gofmt -w ./cmd ./internal ./migrations

Write-Host "== go test =="
go test ./...

Write-Host "== go vet =="
go vet ./...

Write-Host ""
Write-Host "Step 03 sanity checks passed."
Write-Host "Create admin:"
Write-Host "  go run ./cmd/create-admin -email admin@example.com"
