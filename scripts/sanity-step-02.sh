#!/bin/sh
set -eu

echo "== gofmt =="
gofmt -w ./cmd ./internal ./migrations

echo "== go test =="
go test ./...

echo "== go vet =="
go vet ./...

echo
echo "Step 02 sanity checks passed."
echo
echo "Current expected ports:"
echo "  local/internal: 8282"
echo "  Docker host:    3010"
echo
echo "Runtime:"
echo "  go run ./cmd/server"
echo "  curl -i http://127.0.0.1:8282/health"
echo
echo "Docker:"
echo "  docker compose up -d --build"
echo "  curl -i http://127.0.0.1:3010/health"
