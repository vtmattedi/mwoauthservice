#!/bin/sh
set -eu

echo "== gofmt =="
gofmt -w ./cmd ./internal ./migrations

echo "== go test =="
go test ./...

echo "== go vet =="
go vet ./...

echo
echo "Step 07 sanity checks passed."
echo
echo "Required Step 07 env:"
echo "  GOOGLE_CLIENT_SECRET=<Google OAuth client secret>"
