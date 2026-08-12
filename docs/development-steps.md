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
