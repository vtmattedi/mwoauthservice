$ErrorActionPreference = "Stop"

Write-Host "== gofmt =="
gofmt -w ./cmd ./internal ./migrations

Write-Host "== go test =="
go test ./...

Write-Host "== go vet =="
go vet ./...

Write-Host ""
Write-Host "Step 05 sanity checks passed."
