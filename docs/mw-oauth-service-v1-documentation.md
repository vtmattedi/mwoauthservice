# MW OAuth Service — v1.0 Documentation

**Application:** `mw-oauth-service`  
**Production domain:** `https://oauth.mattediworks.com`  
**Version:** `v1.0`  
**Purpose:** Centralized OAuth authorization broker for MattediWorks projects.

## 1. Goal

MW OAuth Service centralizes OAuth client configuration and provider callback handling across MattediWorks applications while keeping ownership of user OAuth credentials inside the consuming project.

The service:

- authenticates each consuming project with a project API key;
- validates tenant-specific OAuth policy;
- starts OAuth authorization transactions;
- redirects users to the provider's real login and consent page;
- receives the provider callback;
- exchanges the authorization code for OAuth tokens;
- immediately delivers the token bundle to the consuming project's backend through a signed HTTPS callback;
- does **not** persist provider access tokens or refresh tokens;
- records only safe operational and audit metadata.

The initial provider is **Google**. The initial public API version is **v1**.

## 2. Core principles

### 2.1 The consuming project owns the OAuth connection

MW OAuth Service does not understand consuming-application users. The consuming project remains responsible for mapping an OAuth operation to its own user/account/integration.

The project supplies an opaque `client_reference`, for example:

```text
oauth_pending_86bV7...
```

MW stores/returns this value as opaque correlation metadata. It must not depend on the project's local user model.

### 2.2 OAuth tokens are never persisted by MW

The following must never be stored in SQLite, Redis, disk logs, audit metadata, or URLs:

- provider authorization codes;
- OAuth access tokens;
- OAuth refresh tokens;
- raw OAuth `state`;
- PKCE verifier;
- project API keys;
- project callback signing secrets;
- Google client secret.

OAuth tokens may exist only transiently in process memory while MW exchanges the provider code and performs the signed callback delivery.

### 2.3 Two project credentials

Each project receives two independent credentials.

**Project API key** — example `mw_live_...`

```text
Project → MW OAuth
```

Used to authenticate the project and determine the tenant policy applied to public API calls. The raw value is only shown at creation/rotation and is stored as a secure hash.

**Callback signing secret** — example `mw_whsec_...`

```text
MW OAuth → Project
```

Used to sign OAuth result callbacks. This secret is independently rotatable. Because MW must generate HMAC signatures, it must be stored encrypted at rest rather than irreversibly hashed.

## 3. High-level flow

```text
Project Frontend
      │ user clicks "Connect Google"
      ▼
Project Backend
      │ POST /v1/oauth/google/authorize
      │ Authorization: Bearer mw_live_...
      ▼
MW OAuth Service
      ├─ authenticate project
      ├─ validate provider/scopes/URLs
      ├─ apply rate limits
      ├─ create transaction
      ├─ generate state
      └─ generate PKCE challenge
      │
      ▼
returns authorization_url
      │
      ▼
User Browser → Google Login + Consent
      │
      ▼
Google redirects to
https://oauth.mattediworks.com/oauth/google/callback
      │
      ▼
MW OAuth Service
      ├─ validate state/transaction
      ├─ atomically consume transaction
      ├─ exchange code with Google
      └─ signed HTTPS POST
             │
             ▼
      Project Backend Callback
             ├─ verify MW signature
             ├─ verify timestamp
             ├─ deduplicate delivery id
             ├─ persist Google credentials
             └─ return 2xx only after durable storage
             │
             ▼
MW OAuth Service
      ├─ mark transaction completed
      ├─ discard token values
      └─ redirect browser to trusted return_url
```

The user still sees Google's normal login and consent screen. MW never emulates Google's consent UI.

## 4. Transaction protocol

Recommended `oauth_transactions` fields:

```text
id
project_id
provider
state_hash
pkce_verifier_enc
client_reference
callback_url
return_url
requested_scopes
status
expires_at
consumed_at
created_at
updated_at
```

Recommended TTL: **10 minutes**.

### State

Generate 32 random bytes. Only `SHA256(state)` is stored. The raw value is sent to Google and returned in the callback, then hashed for lookup. The raw state is never persisted or logged.

### PKCE

Use PKCE `S256`. MW generates the verifier/challenge. The verifier is encrypted for the short lifetime of the transaction, used for the code exchange, then discarded.

### Transaction states

```text
pending → processing → completed
```

Terminal alternatives:

```text
denied
expired
provider_failed
delivery_failed
invalid
```

Only a pending transaction may transition to processing. Callback consumption must be atomic to prevent replay.

## 5. Public API v1

### POST `/v1/oauth/google/authorize`

```http
Authorization: Bearer mw_live_<project-key>
Content-Type: application/json
```

Example request:

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

MW validates:

- API key;
- project enabled;
- Google enabled for the project;
- requested scopes are allowed;
- callback URL exactly matches an allowed callback URL;
- return URL exactly matches an allowed return URL;
- project rate limits and pending-transaction limits.

Example response:

```json
{
  "transaction_id": "oauth_txn_01...",
  "authorization_url": "https://accounts.google.com/...",
  "expires_in": 600
}
```

The frontend may use a full-page redirect or popup.

### Provider callback

Google redirects to:

```http
GET /oauth/google/callback
```

Success:

```text
?code=...&state=...
```

Denial:

```text
?error=access_denied&state=...
```

This endpoint is provider-facing, not a project API endpoint.

## 6. Project callback delivery

MW sends the token result to the exact configured backend callback URL.

```http
POST https://app.example.com/api/oauth/google/result
Content-Type: application/json
X-MW-Webhook-Id: oauth_delivery_01...
X-MW-Timestamp: 1786552800
X-MW-Signature: v1=<signature>
```

Success body:

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

Failure/denial example:

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

Authorization codes are never passed to consuming projects.

## 7. Callback signature protocol

Use per-project HMAC-SHA256.

Canonical payload:

```text
<webhook-id>.<timestamp>.<raw-body>
```

Signature:

```text
HMAC-SHA256(callback_signing_secret, canonical_payload)
```

The exact output encoding must be frozen in implementation and public documentation.

The project must:

1. verify using the exact raw HTTP body;
2. reject stale timestamps;
3. compare signatures in constant time;
4. deduplicate `X-MW-Webhook-Id`;
5. persist OAuth credentials;
6. return `2xx` only after durable persistence.

## 8. Callback delivery retries

Because MW does not persist OAuth tokens, retries exist only while the token bundle remains in process memory.

Suggested policy:

```text
attempt 1
  ↓ failure
wait ~250 ms
attempt 2
  ↓ failure
wait ~750 ms
attempt 3
```

If no attempt succeeds:

```text
transaction.status = delivery_failed
```

MW stores safe failure metadata and discards the tokens. The user must authorize again.

## 9. Tenant configuration

Suggested base project model:

```text
projects
id
name
token_hash
enabled
callback_secret_enc
callback_secret_key_version
created_at
updated_at
```

OAuth provider policy:

```text
project_oauth_configs
project_id
provider
enabled
allowed_scopes
allowed_callback_urls
allowed_return_urls
rate_per_minute
rate_per_hour
max_pending_transactions
created_at
updated_at
```

For v1, `provider = google`.

### Allowed scopes

A project may only request scopes configured by an administrator. Requests outside the configured allowlist return `403` and create a safe audit event.

### Callback URLs

Token callback URLs use **exact matching only** in v1.

### Return URLs

Browser return URLs also use exact matching in v1.

## 10. Rate limits

v1 should support per-project:

```text
rate_per_minute
rate_per_hour
max_pending_transactions
```

These protect temporary transaction storage and provider authorization-flow creation from accidental or malicious abuse.

## 11. Audit and logging

MW audits successful events and rejected client behavior.

Suggested `audit_events` fields:

```text
id
created_at
event_type
severity
project_id nullable
transaction_id nullable
request_id
method
path
http_status
origin nullable
remote_ip nullable
reason_code
metadata_json
attempt_count
```

Recommended events:

```text
oauth.request.accepted
oauth.request.rejected.invalid_api_key
oauth.request.rejected.disabled_project
oauth.request.rejected.missing_origin
oauth.request.rejected.origin_mismatch
oauth.request.rejected.invalid_body
oauth.request.rejected.callback_not_allowed
oauth.request.rejected.return_url_not_allowed
oauth.request.rejected.scope_not_allowed
oauth.request.rejected.rate_limited
oauth.provider.denied
oauth.provider.callback_invalid_state
oauth.provider.transaction_expired
oauth.provider.exchange_failed
oauth.delivery.retry
oauth.delivery.failed
oauth.delivery.completed
oauth.authorization.completed
```

### Invalid-token correlation

Never log a raw API token. A short non-reversible fingerprint may be used:

```text
first 16 hex characters of SHA256(raw token)
```

### Safe URL metadata

For rejected callback/return URLs, record normalized safe components only where useful:

```text
scheme
hostname
port
path
```

Drop query strings/fragments.

### Never audit

Never log or store:

```text
authorization code
access token
refresh token
project API key
callback signing secret
raw state
PKCE verifier
Google client secret
full token callback body
```

### Audit amplification

Repeated unauthenticated failures may be coalesced by IP + token fingerprint + reason within a short window rather than creating unlimited rows.

## 12. Admin API

The admin API manages tenant OAuth policy and operational state.

Recommended v1 routes:

```text
POST /admin/api/auth/login
GET  /admin/api/auth/me
POST /admin/api/auth/csrf
POST /admin/api/auth/logout

GET /admin/api/server
GET /admin/api/docs
GET /admin/api/docs/{version}

GET   /admin/api/projects
POST  /admin/api/projects
PATCH /admin/api/projects/{id}
DELETE /admin/api/projects/{id}
POST  /admin/api/projects/{id}/rotate-key
POST  /admin/api/projects/{id}/rotate-callback-secret

GET /admin/api/projects/{id}/oauth/google
PUT /admin/api/projects/{id}/oauth/google

GET /admin/api/audit
GET /admin/api/audit/{id}
GET /admin/api/metrics
```

Admin auth should follow the same model established for MW Email:

```text
server-side session
HttpOnly cookie
SameSite=Strict
Secure in production
CSRF on mutations
ADMIN_ORIGIN allowlist
optional StackPort SP_HOST concealment
```

Origin/host concealment is defense in depth, never authentication.

## 13. Server metadata

Public health remains minimal:

```http
GET /health
```

```json
{
  "status": "ok"
}
```

Detailed metadata is admin-only:

```http
GET /admin/api/server
```

Example:

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

Build metadata should be injected at build time through Go linker flags.

## 14. Embedded API documentation

The deployed binary should carry versioned API documentation via `//go:embed`.

```text
GET /admin/api/docs
GET /admin/api/docs/{version}
```

Example:

```json
{
  "version": "v1",
  "status": "current",
  "content_type": "text/markdown",
  "documentation": "# MW OAuth API v1\n..."
}
```

This ensures the admin UI sees documentation that corresponds to the deployed binary.

## 15. Admin metrics and collection query contract

Collection/metric endpoints use a common query contract:

```text
from
To
project_id
status
limit
offset
```

Canonical spelling should be lowercase:

```text
from
to
project_id
status
limit
offset
```

Timestamps use RFC3339.

Example:

```text
/admin/api/audit?from=2026-08-01T00:00:00Z&to=2026-08-12T23:59:59Z&project_id=4&status=failed&limit=50&offset=0
```

Defaults/caps:

```text
default limit = 50
max limit = 200
offset >= 0
from <= to
```

Malformed timestamps or invalid pagination values return `400`.

### Pagination metadata

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

Definitions:

```text
limit     effective page size
offset    matching rows skipped
count     rows returned
total     matching rows before pagination
has_more  offset + count < total
```

Metric endpoints may return both a summary and paginated grouped data.

## 16. StackPort deployment

Production hostname:

```text
oauth.mattediworks.com
```

Recommended deployment:

```text
Internet
   ↓
StackPort / Nginx
   ↓
127.0.0.1:<host-port>
   ↓
mw-oauth-service container
```

Nginx should preserve:

```text
Host
Origin
X-Forwarded-Proto
X-Forwarded-For
X-Real-IP
```

The app container should bind only to localhost on the VPS host, for example:

```yaml
ports:
  - "127.0.0.1:3010:8080"
```

Only trust forwarded-IP headers when the gateway is reachable exclusively through the trusted local reverse proxy/container network.

## 17. Suggested environment

```env
APP_ENV=production
PORT=8080
DATABASE_PATH=/app/data/oauth.db

GOOGLE_CLIENT_ID=
GOOGLE_CLIENT_SECRET=

TOKEN_ENCRYPTION_KEY=

ADMIN_ORIGIN=https://<admin-domain>
ADMIN_DEV_ORIGIN=http://localhost:5173

CHECK_SP_HOST=true
SP_HOST=oauth.mattediworks.com
```

Secrets must never be baked into Docker images.

## 18. Persistence

SQLite is acceptable for v1.

Recommended:

```text
WAL mode
foreign_keys=ON
busy_timeout configured
persistent Docker volume
```

Example:

```yaml
services:
  gateway:
    volumes:
      - oauth-data:/app/data

volumes:
  oauth-data:
```

Do not use `docker compose down -v` during normal redeployments if the volume contains production data.

## 19. Provider scope

v1 supports:

```text
Google OAuth
authorization-code flow
PKCE S256
offline access where requested and allowed
```

The internal provider design should remain extensible:

```go
type Provider interface {
    AuthorizationURL(...)
    ExchangeCode(...)
}
```

Possible future providers are outside v1 scope.

## 20. Explicit non-goals

v1 does **not**:

- persist provider access tokens;
- persist provider refresh tokens;
- proxy Google APIs;
- manage consuming-project users;
- provide a generalized identity platform;
- support arbitrary OAuth providers;
- support wildcard token callback URLs;
- retry token delivery after process memory is lost;
- expose admin metrics publicly.

## 21. Security boundary summary

```text
Project → MW
    project API key

MW → Project
    per-project callback HMAC secret

Browser → Google
    normal provider login and consent

Google → MW
    provider callback + state + PKCE

Project policy
    provider allowlist
    scope allowlist
    exact callback URLs
    exact return URLs
    rate limits

MW persists
    project metadata/policy
    hashed API keys
    encrypted callback secrets
    temporary transaction metadata
    audit/metric metadata

MW never persists
    provider access tokens
    provider refresh tokens
```

## 22. v1 completion definition

MW OAuth Service v1.0 is complete when it can:

1. create/administer projects;
2. issue/rotate project API keys;
3. issue/rotate callback signing secrets;
4. configure Google per project;
5. configure allowed scopes;
6. configure exact callback/return URLs;
7. configure rate limits;
8. start Google OAuth transactions;
9. generate/validate opaque state;
10. use PKCE S256;
11. receive Google's callback;
12. prevent callback replay atomically;
13. exchange provider authorization codes;
14. deliver token bundles through signed HTTPS callbacks;
15. retry callback delivery synchronously without token persistence;
16. discard token bundles after success or terminal failure;
17. redirect browsers to trusted return URLs;
18. audit accepted/rejected requests and provider/delivery failures;
19. expose filtered/paginated admin audit and metrics endpoints;
20. expose build/server/API metadata;
21. embed versioned API documentation in the binary;
22. deploy behind StackPort at `oauth.mattediworks.com`.
