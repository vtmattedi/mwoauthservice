#!/bin/sh
set -eu

echo "== Step 10.a: optional WebAuthn =="

echo "- go test ./..."
go test ./...

echo "- go vet ./..."
go vet ./...

echo
echo "Static checks passed."
echo
echo "Before browser testing verify:"
echo "  WEBAUTHN_RP_ID=oauth.mattediworks.com"
echo "  WEBAUTHN_ORIGINS=https://<admin>.oauth.mattediworks.com"
echo "  WEBAUTHN_CREDENTIAL_KEYS=1:<base64url-32-byte-key>"
echo
echo "Then test registration and passkey login from the real admin SPA origin."
