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
