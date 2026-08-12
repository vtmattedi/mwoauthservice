#!/bin/sh
set -eu

echo "== gofmt =="
gofmt -w ./cmd ./internal ./migrations

echo "== go test =="
go test ./...

echo "== go vet =="
go vet ./...

echo
echo "Step 04 sanity checks passed."
echo
echo "Before starting the server, configure:"
echo "  CALLBACK_SECRET_KEYS=1:<32-byte-base64url-key>"
echo "  CALLBACK_SECRET_ACTIVE_KEY_VERSION=1"
