#!/bin/sh
set -eu

echo "== gofmt =="
gofmt -w ./cmd ./internal ./migrations

echo "== go test =="
go test ./...

echo "== go vet =="
go vet ./...

echo
echo "Step 06 sanity checks passed."
echo
echo "Required Step 06 env:"
echo "  GOOGLE_CLIENT_ID=<google oauth client id>"
echo "  GOOGLE_REDIRECT_URI=https://oauth.mattediworks.com/oauth/google/callback"
echo "  TOKEN_ENCRYPTION_KEY=<base64url encoded 32-byte key>"
