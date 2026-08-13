# Step 10.a — Optional WebAuthn

Step 10.a adds passkey/WebAuthn authentication to the MW OAuth admin API while preserving the existing password login.

## Goal

An administrator may authenticate using either:

```text
email + password
```

or:

```text
WebAuthn / passkey
```

Both successful paths issue the same existing opaque server-side admin session and CSRF token.

Step 10.a does not make WebAuthn mandatory and does not add TOTP or recovery.

## Production relying-party configuration

```env
WEBAUTHN_RP_ID=oauth.mattediworks.com
WEBAUTHN_RP_NAME=MW OAuth
WEBAUTHN_ORIGINS=https://<admin>.oauth.mattediworks.com

WEBAUTHN_CREDENTIAL_KEYS=1:<base64url-32-byte-key>
WEBAUTHN_CREDENTIAL_ACTIVE_KEY_VERSION=1
```

The admin SPA runs at:

```text
https://<admin>.oauth.mattediworks.com
```

The WebAuthn RP ID is:

```text
oauth.mattediworks.com
```

For local development, use a matching development RP ID and origin, for example:

```env
WEBAUTHN_RP_ID=localhost
WEBAUTHN_ORIGINS=http://localhost:5173
```

Do not add wildcard origins.

## Credential policy

Step 10.a requests:

```text
userVerification = required
resident/discoverable credential = required
attestation = none
```

Platform authenticators and cross-platform security keys are both allowed.

Each admin receives a random 64-byte opaque WebAuthn user handle.

Multiple credentials are supported.

## Encryption

The complete serialized WebAuthn credential is encrypted at rest with AES-256-GCM, except for lookup/operational metadata such as the credential ID.

WebAuthn ceremony `SessionData` is also encrypted at rest.

The encryption keyring is separate from:

```text
CALLBACK_SECRET_KEYS
TOKEN_ENCRYPTION_KEY
GOOGLE_CLIENT_SECRET
```

Key format:

```text
WEBAUTHN_CREDENTIAL_KEYS=1:<base64url-32-byte-key>
```

Multiple key versions may be retained during future rotation:

```text
WEBAUTHN_CREDENTIAL_KEYS=1:<old>,2:<new>
WEBAUTHN_CREDENTIAL_ACTIVE_KEY_VERSION=2
```

## Ceremony tokens

Each begin endpoint returns an opaque token:

```text
wac_<random>
```

Only SHA-256 of this token is stored.

The token identifies encrypted server-side WebAuthn `SessionData`.

Ceremonies are:

```text
short-lived (~5 minutes)
single-use
atomically consumed
```

## Admin API

### List passkeys

```http
GET /admin/api/auth/webauthn
Cookie: mw_oauth_admin_session=...
```

Response:

```json
{
  "items": [
    {
      "credential_id": "...",
      "label": "Windows Hello — Office PC",
      "transports": ["internal"],
      "sign_count": 3,
      "clone_warning": false,
      "backup_eligible": true,
      "backup_state": true,
      "created_at": "...",
      "last_used_at": "..."
    }
  ]
}
```

### Begin registration

Requires authenticated session + CSRF.

```http
POST /admin/api/auth/webauthn/register/options
X-CSRF-Token: ...
Content-Type: application/json
```

```json
{
  "label": "Windows Hello — Office PC"
}
```

Response:

```json
{
  "ceremony_token": "wac_...",
  "options": {
    "publicKey": {}
  }
}
```

The `options` object is the WebAuthn credential-creation options returned by the backend.

The SPA converts the JSON representation as required by the browser WebAuthn API and invokes:

```js
navigator.credentials.create(...)
```

### Finish registration

Requires authenticated session + CSRF.

The body is the raw JSON representation of the browser's WebAuthn credential result.

```http
POST /admin/api/auth/webauthn/register/verify
Content-Type: application/json
X-CSRF-Token: ...
X-MW-WebAuthn-Ceremony: wac_...

<raw WebAuthn registration credential JSON>
```

The backend consumes the ceremony token and verifies the challenge, expected RP ID, expected origin, user verification, and credential.

A failed verification consumes the ceremony. Start a new ceremony to retry.

### Begin passkey login

No existing session is required, but the route remains inside the normal concealed admin surface.

```http
POST /admin/api/auth/webauthn/login/options
Origin: https://<admin>.oauth.mattediworks.com
```

Response:

```json
{
  "ceremony_token": "wac_...",
  "options": {
    "publicKey": {}
  }
}
```

The SPA invokes:

```js
navigator.credentials.get(...)
```

with the returned options.

### Finish passkey login

```http
POST /admin/api/auth/webauthn/login/verify
Content-Type: application/json
X-MW-WebAuthn-Ceremony: wac_...

<raw WebAuthn assertion credential JSON>
```

On success the response is the same session response shape as password login:

```json
{
  "user": {},
  "csrf_token": "...",
  "expires_at": "..."
}
```

The normal `HttpOnly`, `Secure`, `SameSite=Strict` admin session cookie is also issued.

### Remove a passkey

Step 10.a still treats the password as the recovery path, so removing a credential requires fresh password confirmation in addition to session + CSRF.

```http
DELETE /admin/api/auth/webauthn/{credential_id}
Content-Type: application/json
X-CSRF-Token: ...
```

```json
{
  "password": "current password"
}
```

Removal is implemented as revocation rather than physical deletion.

## CORS

The admin CORS policy additionally permits:

```text
X-MW-WebAuthn-Ceremony
```

No wildcard admin origins are introduced.

## Audit

Step 10.a records safe events for registration, login, verification failures, and credential removal.

The audit trail must not contain:

```text
raw ceremony token
raw WebAuthn challenge
raw authenticator response
serialized WebAuthn credential
password
```

## Step 10.a non-goals

Not implemented yet:

```text
mandatory WebAuthn MFA
password + WebAuthn requirement
manual recovery
email recovery
TOTP
passwordless-only mode
WebAuthn step-up for sensitive operations
```

These belong to Steps 10.b and 10.c.

## Sanity

Run:

```powershell
.\scripts\sanity-step-10a.ps1
```

or:

```bash
./scripts/sanity-step-10a.sh
```

Do not begin Step 10.b unless:

```text
go test ./...
go vet ./...
```

are clean and a real browser can successfully register and use a passkey against the configured admin origin.
