# Development Steps

The service is intentionally built in small stages with a sanity check between
each stage.

## Planned sequence

1. **Runnable service scaffold**
   - Go module
   - configuration
   - structured logging
   - `/health`
   - build metadata package
   - Docker/Compose baseline

2. **SQLite + migration engine**
   - persistent `/app/data`
   - embedded migrations
   - WAL / foreign keys / busy timeout
   - database health

3. **Admin authentication**
   - admin users
   - Argon2id password hashes
   - server-side sessions
   - CSRF
   - admin origin + optional `SP_HOST` concealment
   - create-admin CLI

4. **Projects and tenant configuration**
   - project API key
   - callback signing secret
   - Google provider config
   - scopes
   - exact callback/return URLs
   - limits
   - secret rotation

5. **Audit, server metadata, embedded API docs**
   - audit event persistence/redaction
   - `/admin/api/server`
   - `/admin/api/docs`
   - filtered/paginated admin collection contract
   - initial metrics

6. **Public OAuth transaction creation**
   - `POST /v1/oauth/google/authorize`
   - project authentication
   - policy validation
   - rate limits
   - opaque state
   - PKCE S256
   - transaction TTL

7. **Google callback + token exchange**
   - provider callback
   - atomic state consumption
   - authorization-code exchange
   - no provider-token persistence

8. **Signed project callback delivery**
   - HMAC callback signing
   - synchronous retries
   - durable-acceptance semantics
   - redirect to trusted return URL
   - success/failure audit

9. **Hardening / deployment checks**
   - integration tests
   - abuse/audit aggregation
   - Docker build metadata
   - StackPort/Nginx validation
   - v1 docs finalization

---

## Step 01 sanity check

```bash
sh scripts/sanity-step-01.sh
```

Then:

```bash
cp .env.example .env
go run ./cmd/server
```

In another shell:

```bash
curl -i http://127.0.0.1:8080/health
```

Expected:

```json
{"status":"ok"}
```

Docker:

```bash
docker compose build
docker compose up -d
curl -i http://127.0.0.1:3010/health
docker compose down
```

Stop after Step 01 and verify it before applying Step 02.

---

## Step 02 sanity check

Step 02 adds SQLite and the embedded migration engine.

The service now:

- opens `DATABASE_PATH` at startup;
- creates the database parent directory when required;
- enables WAL;
- enables foreign keys;
- configures a 5-second busy timeout;
- applies embedded migrations;
- checks SQLite from the existing minimal `/health` endpoint.

Run:

```bash
sh scripts/sanity-step-02.sh
```

With the current local internal port:

```bash
go run ./cmd/server
curl -i http://127.0.0.1:8282/health
```

With the current Docker mapping (`3010 -> 8282`):

```bash
docker compose up -d --build
curl -i http://127.0.0.1:3010/health
```

Expected:

```json
{"status":"ok"}
```

Do not use `docker compose down -v` once production data exists.

---

## Step 03 sanity check

Step 03 adds the admin authentication foundation:

- Argon2id password hashes;
- server-side sessions;
- hashed session and CSRF tokens;
- HttpOnly `SameSite=Strict` cookie;
- `Secure` cookies outside development;
- admin origin allowlist/CORS;
- optional `SP_HOST` concealment;
- `create-admin` CLI.

Routes:

```text
POST /admin/api/auth/login
GET  /admin/api/auth/me
POST /admin/api/auth/csrf
POST /admin/api/auth/logout
```

Local:

```bash
go run ./cmd/create-admin -email admin@example.com
```

Docker:

```bash
docker compose up -d --build
docker compose exec -it gateway /app/create-admin -email admin@example.com
```

Development configuration:

```env
ADMIN_DEV_ORIGIN=http://localhost:5173
CHECK_SP_HOST=false
```

Production should use the real admin SPA origin plus:

```env
CHECK_SP_HOST=true
SP_HOST=oauth.mattediworks.com
```

Host/origin concealment is defense in depth, not authentication.

Stop after this step until login, `/auth/me`, CSRF rotation and logout have
been verified.

---

## Step 04 sanity check

Step 04 adds project/tenant administration:

- project API keys (`mw_live_...`), stored only as SHA-256 hashes;
- callback signing secrets (`mw_whsec_...`), encrypted at rest with AES-256-GCM;
- versioned callback-secret encryption keys;
- project enable/disable and rename;
- API-key rotation;
- callback-secret rotation;
- Google provider policy;
- allowed scopes;
- exact callback URLs;
- exact browser return URLs;
- per-project OAuth rate configuration.

Admin routes:

```text
GET   /admin/api/projects
POST  /admin/api/projects
PATCH /admin/api/projects/{id}

POST /admin/api/projects/{id}/rotate-key
POST /admin/api/projects/{id}/rotate-callback-secret

GET /admin/api/projects/{id}/oauth/google
PUT /admin/api/projects/{id}/oauth/google
```

Project creation returns the raw API key and callback signing secret exactly once.
Neither raw secret is persisted in plaintext.

Before starting the Step 04 server, add:

```env
CALLBACK_SECRET_KEYS=1:<base64url-encoded-32-byte-key>
CALLBACK_SECRET_ACTIVE_KEY_VERSION=1
```

Generate a development key with:

```bash
python -c "import secrets,base64; print('1:'+base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip('='))"
```

For future encryption-key rotation, keep old key versions configured while
introducing a new active version, for example:

```env
CALLBACK_SECRET_KEYS=1:<old>,2:<new>
CALLBACK_SECRET_ACTIVE_KEY_VERSION=2
```

Step 04 does not yet expose project authentication on the public OAuth API.
That is introduced when public transaction creation is implemented.

---

## Step 05 sanity check

Step 05 adds observability/admin introspection:

- structured audit-event persistence;
- audit metadata redaction for known secret fields;
- API-key fingerprint helper for future rejected-key correlation;
- global request IDs via `X-Request-ID`;
- filtered/paginated admin audit listing;
- initial OAuth metrics grouped by project;
- server/build/API metadata;
- embedded versioned API documentation.

Admin routes:

```text
GET /admin/api/server

GET /admin/api/docs
GET /admin/api/docs/{version}

GET /admin/api/audit
GET /admin/api/audit/{id}

GET /admin/api/metrics
```

Common audit/metric query parameters:

```text
from
to
project_id
status
limit
offset
```

`from` and `to` use RFC3339 and are normalized to UTC Unix timestamps before
querying SQLite.

Pagination response metadata:

```json
{
  "limit": 50,
  "offset": 0,
  "count": 0,
  "total": 0,
  "has_more": false
}
```

The embedded `v1` documentation snapshot is copied from:

```text
docs/mw-oauth-service-v1-api-reference.md
```

into the Go package at Step 05 generation time, so the binary serves the API
documentation snapshot it was built with.

Step 05 establishes audit infrastructure. Public OAuth rejection/success
events are wired into it when the public OAuth flow is introduced.

---

## Step 06 sanity check

Step 06 introduces the first public OAuth endpoint:

```text
POST /v1/oauth/google/authorize
```

The endpoint authenticates the consuming project with:

```http
Authorization: Bearer mw_live_...
```

and accepts:

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

It validates:

- project API key;
- project enabled status;
- Google enabled status;
- requested scopes as a subset of the configured allowlist;
- exact configured callback URL;
- exact configured return URL;
- per-minute rate limit;
- per-hour rate limit;
- maximum active pending transactions.

On success, Step 06 creates a 10-minute transaction containing:

- random opaque OAuth `state`, stored only as SHA-256;
- PKCE S256 verifier/challenge;
- encrypted PKCE verifier;
- opaque `client_reference`;
- exact project callback URL;
- exact browser return URL;
- requested scopes;
- `pending` status.

Success:

```json
{
  "transaction_id": "oauth_txn_...",
  "authorization_url": "https://accounts.google.com/...",
  "expires_in": 600
}
```

The authorization URL uses Google's real authorization endpoint with PKCE,
offline access, and consent.

Step 06 adds these environment variables:

```env
GOOGLE_CLIENT_ID=
GOOGLE_REDIRECT_URI=https://oauth.mattediworks.com/oauth/google/callback
TOKEN_ENCRYPTION_KEY=
```

`TOKEN_ENCRYPTION_KEY` is a raw base64url-encoded 32-byte key. Unlike
`CALLBACK_SECRET_KEYS`, it does **not** use a `1:` version prefix in v1.

Generate one with:

```bash
python -c "import secrets,base64; print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip('='))"
```

Step 06 also begins writing public request audit events, including:

```text
oauth.request.accepted
oauth.request.rejected.invalid_api_key
oauth.request.rejected.disabled_project
oauth.request.rejected.disabled_provider
oauth.request.rejected.invalid_body
oauth.request.rejected.scope_not_allowed
oauth.request.rejected.callback_not_allowed
oauth.request.rejected.return_url_not_allowed
oauth.request.rejected.rate_limited
```

Authorization codes and provider tokens do not exist in Step 06 yet. Google
callback/code exchange is Step 07.

---

## Step 07 sanity check

Step 07 adds Google's provider callback and authorization-code exchange:

```text
GET /oauth/google/callback
```

Callback processing:

1. receives Google's opaque `state`;
2. hashes it and resolves the short-lived transaction;
3. atomically consumes only a `pending` transaction;
4. rejects replayed or unknown state;
5. expires stale transactions atomically;
6. handles `error=access_denied`;
7. decrypts the stored PKCE verifier only in process memory;
8. exchanges Google's authorization code at the Google token endpoint;
9. keeps returned OAuth tokens only in process memory;
10. invokes a delivery interface;
11. updates the transaction to a terminal state;
12. redirects the browser only to the previously configured trusted
    `return_url`.

Step 07 intentionally wires an unavailable delivery implementation. Therefore,
a successful Google code exchange currently becomes:

```text
processing -> delivery_failed
```

and the token values are discarded. This is deliberate: Step 08 replaces the
temporary deliverer with the signed HTTPS callback to the consuming project.

A callback result redirects to the trusted project return URL with only:

```text
mw_oauth_status
mw_oauth_transaction_id
```

Google's authorization code, OAuth state, access token, and refresh token are
never placed in the browser redirect.

Step 07 adds:

```env
GOOGLE_CLIENT_SECRET=
```

### Reverse-proxy logging requirement

Google returns the authorization `code` and `state` in the callback query
string. The Go application never logs `r.URL.RawQuery`, but a default Nginx
access log commonly logs the full request URI.

For `/oauth/google/callback`, production proxy logging must therefore either:

- use a log format based on `$uri` rather than `$request_uri`; or
- disable the access log for this callback location.

Do not persist the callback query string in reverse-proxy logs.

Step 08 implements the signed project callback and turns successful exchanges
into:

```text
processing -> completed
```

---

## Step 08 sanity check

Step 08 replaces the temporary unavailable token deliverer with the real
signed HTTPS callback to the consuming project's backend.

Successful flow:

```text
Google callback
  -> atomic pending -> processing
  -> exchange code with PKCE
  -> tokens exist only in process memory
  -> signed POST to exact project callback_url
  -> project persists credentials and returns 2xx
  -> processing -> completed
  -> tokens discarded
  -> browser redirects to trusted return_url
```

The callback body is:

```json
{
  "event": "oauth.authorization.completed",
  "transaction_id": "oauth_txn_...",
  "client_reference": "oauth_pending_...",
  "provider": "google",
  "token": {
    "access_token": "...",
    "refresh_token": "...",
    "token_type": "Bearer",
    "expires_in": 3599,
    "scope": ["..."]
  }
}
```

Headers:

```text
Content-Type: application/json
X-MW-Webhook-Id: oauth_delivery_...
X-MW-Timestamp: <unix-seconds>
X-MW-Signature: v1=<hex-hmac-sha256>
```

Canonical signature input:

```text
<webhook-id>.<timestamp>.<raw-request-body>
```

Signature:

```text
HMAC-SHA256(project_callback_secret, canonical_input)
```

The v1 signature encoding is now frozen as lowercase hexadecimal.

Delivery retries are synchronous and in memory only:

```text
attempt 1: immediately
attempt 2: +250ms
attempt 3: +750ms
```

The same webhook ID, timestamp, body, and signature are reused for all retry
attempts. A consuming project must deduplicate by `X-MW-Webhook-Id`.

Any 2xx response is success. Redirects are never followed. This is a security
requirement: following a project callback redirect could forward OAuth tokens
to an unintended host.

After three failed attempts:

```text
processing -> delivery_failed
```

Tokens are discarded and are not queued or persisted for later retry. The
project/user must start a new authorization.

The callback signing secret is decrypted only on demand for delivery and is
not exposed by list/get admin APIs after initial creation/rotation.

The browser return redirect still never contains Google code, state, access
token, refresh token, or callback signing secret.

---

## Step 09 sanity check

Step 09 is the v1 hardening/deployment pass.

It adds global security headers and disables caching on sensitive admin/OAuth
routes. The Google callback response specifically gets:

```text
Referrer-Policy: no-referrer
Cache-Control: no-store, max-age=0
Pragma: no-cache
```

Incoming `X-Request-ID` values are accepted only when they contain safe ASCII
identifier characters (`A-Z`, `a-z`, `0-9`, `.`, `_`, `-`). Invalid values are
replaced with a generated request ID.

Review:

```text
docs/production-hardening.md
```

Step 09 does not automatically rewrite Docker networking. If host Nginx
proxies directly to the service, prefer:

```text
127.0.0.1:3010:8282
```

The exact Nginx `/oauth/google/callback` location with `access_log off`
remains mandatory.

---

## Step 10.a — Optional WebAuthn

Step 10.a adds optional passkey/WebAuthn authentication for administrators.

Password login remains valid.

WebAuthn uses:

```text
RP ID: oauth.mattediworks.com
Admin origin: https://<admin>.oauth.mattediworks.com
userVerification: required
discoverable credential: required
attestation: none
```

New admin routes:

```text
GET    /admin/api/auth/webauthn
POST   /admin/api/auth/webauthn/register/options
POST   /admin/api/auth/webauthn/register/verify
DELETE /admin/api/auth/webauthn/{credential_id}

POST   /admin/api/auth/webauthn/login/options
POST   /admin/api/auth/webauthn/login/verify
```

Registration and credential removal use the existing admin session + CSRF boundary.

Credential removal additionally requires fresh password confirmation in Step 10.a.

Passkey login issues the same existing opaque server-side session and CSRF token as password login.

Server-side WebAuthn `SessionData` and serialized credential records are encrypted using a dedicated versioned keyring.

```env
WEBAUTHN_CREDENTIAL_KEYS=1:<base64url-32-byte-key>
WEBAUTHN_CREDENTIAL_ACTIVE_KEY_VERSION=1
```

Ceremony tokens are random, short-lived, single-use, and stored only as SHA-256 hashes.

Step 10.a intentionally does not implement mandatory MFA, recovery, TOTP, or passwordless-only authentication.

See:

```text
docs/step-10a-optional-webauthn.md
```
