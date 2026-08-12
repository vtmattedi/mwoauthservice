#!/bin/sh
set -eu

echo "== gofmt =="
gofmt -w ./cmd ./internal

echo "== go test =="
go test ./...

echo "== go vet =="
go vet ./...

echo
echo "Step 01 sanity checks passed."
echo
echo "Manual runtime check:"
echo "  cp .env.example .env"
echo "  go run ./cmd/server"
echo "  curl -i http://127.0.0.1:8080/health"
