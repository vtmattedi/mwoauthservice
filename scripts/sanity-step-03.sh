#!/bin/sh
set -eu

echo "== gofmt =="
gofmt -w ./cmd ./internal ./migrations

echo "== go test =="
go test ./...

echo "== go vet =="
go vet ./...

echo
echo "Step 03 sanity checks passed."
echo "Create admin:"
echo "  go run ./cmd/create-admin -email admin@example.com"
