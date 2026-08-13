# MW OAuth Service — Production Hardening

Apply this before real Google OAuth traffic is enabled.

## Reverse proxy

The public internet should reach only the reverse proxy on ports 80/443.

If host Nginx proxies directly to the service, prefer:

```yaml
ports:
  - "127.0.0.1:3010:8282"
```

If StackPort/Nginx uses another Docker/network topology, use equivalent
firewall or internal-network isolation instead.

Preserve:

```nginx
proxy_set_header Host $host;
proxy_set_header X-Real-IP $remote_addr;
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
proxy_set_header X-Forwarded-Proto $scheme;
```

## Google callback logging

Google calls:

```text
/oauth/google/callback?code=...&state=...
```

The query contains the one-time authorization code and raw OAuth state.

The Go application does not log this query string. Nginx must not log it
either.

Use:

```nginx
location = /oauth/google/callback {
    access_log off;

    proxy_pass http://127.0.0.1:3010;

    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
}
```

The current StackPort log format contains `$request`, so the callback must not
inherit that access log.

Also verify upstream CDN/proxy logs.

## Browser callback protection

Sensitive OAuth/admin responses use:

```text
Referrer-Policy: no-referrer
Cache-Control: no-store, max-age=0
Pragma: no-cache
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
```

`Referrer-Policy: no-referrer` prevents the Google callback URL from becoming
a browser Referer when MW redirects to the consuming project.

## Google OAuth configuration

Production redirect URI:

```text
https://oauth.mattediworks.com/oauth/google/callback
```

Required environment values include:

```env
GOOGLE_CLIENT_ID=
GOOGLE_CLIENT_SECRET=
GOOGLE_REDIRECT_URI=https://oauth.mattediworks.com/oauth/google/callback
TOKEN_ENCRYPTION_KEY=
CALLBACK_SECRET_KEYS=1:<base64url-32-byte-key>
CALLBACK_SECRET_ACTIVE_KEY_VERSION=1
```

Do not commit or log secret values.

## Signed project callback

Headers:

```text
X-MW-Webhook-Id: oauth_delivery_...
X-MW-Timestamp: <unix-seconds>
X-MW-Signature: v1=<lowercase-hex-HMAC-SHA256>
```

Canonical input:

```text
<webhook-id>.<timestamp>.<raw-request-body>
```

The consuming project must verify the raw body, use constant-time signature
comparison, reject stale timestamps, deduplicate webhook IDs, durably persist
credentials, and only then return 2xx.

MW must never follow project callback redirects.

## Token handling

Authorization codes, access tokens, refresh tokens, raw state, raw PKCE
verifiers, callback signing secrets, and Google client secrets must never be
logged.

Delivery attempts are synchronous:

```text
immediately
+250ms
+750ms
```

After three failures the transaction becomes `delivery_failed`; tokens are
discarded and authorization must restart.

## SQLite

Keep SQLite on its persistent volume.

Do not use:

```bash
docker compose down -v
```

during normal deploy/restart.

## Final checks

Run:

```bash
go test ./...
go vet ./...
nginx -t
```

Verify:

```text
GET  /health                                  -> 200
POST /v1/oauth/google/authorize without key  -> 401
GET  /oauth/google/callback with bogus state -> 400
direct external access to host port 3010     -> blocked
callback code/state in Nginx access logs     -> absent
```

Then perform one controlled end-to-end Google authorization against a test
consuming project.
