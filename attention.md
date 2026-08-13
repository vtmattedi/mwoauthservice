# Attention

## OAuth callback query strings must not be logged

Google returns the authorization code and raw OAuth state to:

```text
/oauth/google/callback?code=...&state=...
```

The application must never persist that query string.

### Nginx / StackPort

Inside the `server {}` block for `oauth.mattediworks.com`, add an exact-match
location for the Google callback and disable its access log:

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

Keep the normal catch-all location for the rest of the service:

```nginx
location / {
    proxy_pass http://127.0.0.1:3010;

    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
}
```

The exact-match `=` location still matches requests carrying a query string;
the query string is simply excluded from access logging because logging is
disabled for that route.

### Alternative: safe callback log format

If callback request logging is required, define a custom `log_format` in the
global `http {}` context and use `$uri`, not `$request_uri` or `$request`:

```nginx
log_format oauth_safe
    '$remote_addr - $remote_user [$time_local] '
    '"$request_method $uri $server_protocol" '
    '$status $body_bytes_sent';
```

Then:

```nginx
location = /oauth/google/callback {
    access_log /var/log/nginx/oauth-callback.access.log oauth_safe;

    proxy_pass http://127.0.0.1:3010;

    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
}
```

### Deployment check

After changing Nginx:

```bash
nginx -t
nginx -s reload
```

Also verify that any upstream CDN/reverse proxy does not persist the full
callback URL containing `code` and `state`.

This is a production hardening requirement before real Google OAuth traffic is
enabled.
