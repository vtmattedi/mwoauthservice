# MW OAuth Service — v1 API Reference

**Base URL**

```text
https://oauth.mattediworks.com
```

## Public API

### POST `/v1/oauth/google/authorize`

Starts a Google OAuth authorization transaction.

#### Authentication

```http
Authorization: Bearer mw_at_<access-token>
```

#### Request

```json
{
  "scopes": [
    "https://www.googleapis.com/auth/calendar"
  ],
  "callback_url": "https://app.example.com/api/oauth/google/result",
  "return_url": "https://app.example.com/settings/integrations",
  "client_reference": "oauth_pending_86bV7"
}
```

#### Success

```http
200 OK
```

```json
{
  "transaction_id": "oauth_txn_01...",
  "authorization_url": "https://accounts.google.com/...",
  "expires_in": 600
}
```

#### Typical failures

```text
400 invalid request
401 invalid/missing/expired access token (invalid_token)
403 disabled project
403 provider disabled
403 scope not allowed
403 callback URL not allowed
403 return URL not allowed
429 rate limited
500 internal gateway failure
```

## Provider callback

### GET `/oauth/google/callback`

Registered Google redirect URI.

```text
/oauth/google/callback?code=...&state=...
```

or:

```text
/oauth/google/callback?error=access_denied&state=...
```

This endpoint is provider-facing, not a project endpoint.

## MW → Project callback

MW sends the OAuth result to the exact configured project backend callback URL.

```http
Content-Type: application/json
X-MW-Webhook-Id: oauth_delivery_01...
X-MW-Timestamp: 1786552800
X-MW-Signature: v1=<signature>
```

Canonical signature input:

```text
<webhook-id>.<timestamp>.<raw-body>
```

Signature:

```text
HMAC-SHA256(callback_secret, canonical_payload)
```

Success payload:

```json
{
  "event": "oauth.authorization.completed",
  "transaction_id": "oauth_txn_01...",
  "client_reference": "oauth_pending_86bV7",
  "provider": "google",
  "token": {
    "access_token": "ya29...",
    "refresh_token": "1//...",
    "token_type": "Bearer",
    "expires_in": 3599,
    "scope": [
      "https://www.googleapis.com/auth/calendar"
    ]
  }
}
```

Failure payload:

```json
{
  "event": "oauth.authorization.failed",
  "transaction_id": "oauth_txn_01...",
  "client_reference": "oauth_pending_86bV7",
  "provider": "google",
  "error": {
    "code": "access_denied"
  }
}
```

The project must verify the signature using the raw request body and return `2xx` only after durably accepting/storing the result.

## Google access-token renewal

The project owns encrypted-at-rest storage of the callback's `refresh_token`,
while MW owns the Google OAuth client secret. Projects must not receive that
shared secret or call Google's token endpoint using MW's credentials.

The current v1 API has no token-renewal endpoint. Long-lived Google access is
therefore not currently supported after the initial access token expires; the
implemented fallback is a new authorization transaction.

Renewal support requires a future authenticated backend endpoint such as:

```http
POST /v1/oauth/google/refresh
Authorization: Bearer mw_at_<access-token>
Content-Type: application/json

{
  "refresh_token": "1//..."
}
```

MW would authenticate and rate-limit the project, keep the submitted refresh
token only transiently in memory, and exchange it with Google using the
MW-owned client credentials. Example response:

```json
{
  "access_token": "ya29...",
  "expires_in": 3599,
  "scope": "https://www.googleapis.com/auth/calendar",
  "token_type": "Bearer"
}
```

Retain the existing refresh token when Google omits `refresh_token` during
renewal. Calculate access-token expiry from the response receipt time, refresh
shortly before expiry, and serialize concurrent refresh attempts for the same
connection. If Google returns `invalid_grant`, mark the connection as requiring
reauthorization and start a new transaction through
`POST /v1/oauth/google/authorize`.

The future endpoint must redact provider tokens from logs, errors, metrics, and
audit records. Provider tokens must remain backend-only and must never be
placed in a URL or returned to a browser.

## Admin API

All admin endpoints use `/admin/api`.

### Auth

```text
POST /admin/api/auth/login
GET  /admin/api/auth/me
POST /admin/api/auth/csrf
POST /admin/api/auth/logout
```

### Optional WebAuthn / passkeys — Step 10.a

WebAuthn is optional in Step 10.a. Existing password login remains available.

```text
GET    /admin/api/auth/webauthn
POST   /admin/api/auth/webauthn/register/options
POST   /admin/api/auth/webauthn/register/verify
DELETE /admin/api/auth/webauthn/{credential_id}

POST   /admin/api/auth/webauthn/login/options
POST   /admin/api/auth/webauthn/login/verify
```

Registration and removal require the existing session/CSRF protections.

`register/verify` and `login/verify` receive the raw browser WebAuthn credential JSON and require:

```http
X-MW-WebAuthn-Ceremony: wac_...
Content-Type: application/json
```

The begin endpoints return:

```json
{
  "ceremony_token": "wac_...",
  "options": {
    "publicKey": {}
  }
}
```

Successful passkey login issues the same server-side admin session and CSRF response used by password login.

### Server and docs

```text
GET /admin/api/server
GET /admin/api/docs
GET /admin/api/docs/{version}
```

### Projects

```text
GET   /admin/api/projects
POST  /admin/api/projects
PATCH /admin/api/projects/{id}
DELETE /admin/api/projects/{id}
POST  /admin/api/projects/{id}/rotate-callback-secret
GET   /admin/api/projects/{id}/oauth/google
PUT   /admin/api/projects/{id}/oauth/google
```

Example Google tenant configuration:

```json
{
  "enabled": true,
  "allowed_scopes": [
    "https://www.googleapis.com/auth/calendar"
  ],
  "allowed_callback_urls": [
    "https://app.example.com/api/oauth/google/result"
  ],
  "allowed_return_urls": [
    "https://app.example.com/settings/integrations"
  ],
  "limits": {
    "per_minute": 10,
    "per_hour": 100,
    "max_pending": 50
  }
}
```

### Audit

```text
GET /admin/api/audit
GET /admin/api/audit/{id}
```

### Metrics

```text
GET /admin/api/metrics
```

## Admin query contract

Collection/metric endpoints support:

```text
from
to
project_id
status
limit
offset
```

Timestamps are RFC3339.

Example:

```text
/admin/api/audit?from=2026-08-01T00:00:00Z&to=2026-08-12T23:59:59Z&project_id=4&status=failed&limit=50&offset=0
```

Defaults:

```text
limit = 50
max limit = 200
offset >= 0
from <= to
```

### Pagination

```json
{
  "items": [],
  "pagination": {
    "limit": 50,
    "offset": 0,
    "count": 0,
    "total": 0,
    "has_more": false
  }
}
```

## Server metadata example

```json
{
  "service": "MW OAuth Service",
  "version": "1.0.0",
  "build": {
    "commit": "a81d3e7",
    "built_at": "2026-08-12T19:42:11Z",
    "go_version": "go1.26.5"
  },
  "api": {
    "current": "v1",
    "accepted": ["v1"],
    "deprecated": []
  },
  "providers": {
    "google": {
      "enabled": true,
      "oauth_flow": "authorization_code_pkce"
    }
  }
}
```

## Security rules

Never log/store provider authorization codes, access tokens, refresh tokens, MW client secrets, MW access tokens, callback signing secrets, raw state, PKCE verifier, or the Google client secret.

Never place provider tokens in browser URLs.
