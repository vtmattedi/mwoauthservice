$ErrorActionPreference = "Stop"

Write-Host "== Step 10.a: optional WebAuthn =="

Write-Host "- go test ./..."
go test ./...

Write-Host "- go vet ./..."
go vet ./...

Write-Host ""
Write-Host "Static checks passed."
Write-Host ""
Write-Host "Before browser testing verify:"
Write-Host "  WEBAUTHN_RP_ID=oauth.mattediworks.com"
Write-Host "  WEBAUTHN_ORIGINS=https://<admin>.oauth.mattediworks.com"
Write-Host "  WEBAUTHN_CREDENTIAL_KEYS=1:<base64url-32-byte-key>"
Write-Host ""
Write-Host "Then test registration and passkey login from the real admin SPA origin."
