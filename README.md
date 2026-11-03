# MW OAuth

A Go and SQLite service that brokers Google OAuth authorization for registered applications. It handles the provider redirect and code exchange, then sends the resulting tokens to the application's backend through a signed callback.

MW OAuth was built to share Google integration infrastructure across MattediWorks apps. The application keeps its own users, business data and durable provider-token storage. Shared MW account login is handled separately by MW Identity.

[Ecosystem case study](https://mwecosystem.mattediworks.com/) · [API reference](docs/mw-oauth-service-v1-api-reference.md) · [Service documentation](docs/mw-oauth-service-v1-documentation.md)

## Authorization flow

```text
Application backend -- project API key --> POST /v1/oauth/google/authorize
Application browser <--- authorization URL --- MW OAuth
Application browser ------------------------> Google consent
Google -------------------------------------> MW OAuth callback
MW OAuth -- signed token delivery -----------> Application backend
Application browser <--- return redirect ---- MW OAuth
```

The service validates project policies for scopes and callback/return URLs, creates a state/PKCE transaction, consumes it on callback, exchanges the provider code, and attempts signed delivery to the registered backend.

Project API keys authenticate requests into MW OAuth. A separate callback secret authenticates deliveries back to the application. Provider access/refresh tokens exist transiently during exchange and delivery; the service does not persist them. Short-lived PKCE material and callback signing secrets are encrypted at rest for their respective workflows.

## Current scope

- Google authorization with a project-scoped API and policy checks.
- Signed callbacks carrying correlation metadata and the token bundle.
- SQLite transaction state and audit events.
- Project/credential administration, optional local admin passkeys and delegated MW Identity federation.
- **No token-renewal endpoint in the current v1 API.** With an MW-owned Google client, consumers cannot renew through this broker after the initial access token expires. They must repeat authorization; renewal support is future work. See [Google access-token renewal](docs/mw-oauth-service-v1-documentation.md#61-google-access-token-renewal).

## Run locally

Requires Go 1.26 or newer as declared in [go.mod](go.mod), a writable SQLite path, and a Google OAuth client for an end-to-end authorization flow.

Copy the configuration from the repository root:

```sh
cp .env.example .env
```

On PowerShell, use `Copy-Item .env.example .env`. The example is a configuration checklist, not a runnable set of credentials. Set:

| Variable | Purpose |
| --- | --- |
| `APP_ENV=development` | Enables local `.env` loading; an explicit production/staging environment does not load it |
| `PORT=8080` | Port used by the example environment for direct Go execution |
| `DATABASE_PATH=./data/oauth.db` | Local SQLite database |
| `GOOGLE_CLIENT_SECRET_KEYS` | Versioned 32-byte base64url keyring that encrypts each project's own Google OAuth client secret, e.g. `1:<generated-key>`; required, and must not reuse any other key |
| `GOOGLE_CLIENT_SECRET_ACTIVE_KEY_VERSION=1` | Version used for newly stored Google client secrets |
| `GOOGLE_REDIRECT_URI` | Exact callback URI registered with Google, ending in `/oauth/google/callback` |
| `TOKEN_ENCRYPTION_KEY` | An independently generated 32-byte base64url key for short-lived transaction material |
| `CALLBACK_SECRET_KEYS` | Versioned 32-byte base64url keyring, e.g. `1:<generated-key>` |
| `CALLBACK_SECRET_ACTIVE_KEY_VERSION=1` | Version used for new encrypted callback secrets |
| `WEBAUTHN_RP_ID`, `WEBAUTHN_ORIGINS` | Set to the host and exact origins of your local admin client; see the example's localhost notes |
| `WEBAUTHN_CREDENTIAL_KEYS` | A separate versioned 32-byte base64url keyring for local admin passkeys |
| `WEBAUTHN_CREDENTIAL_ACTIVE_KEY_VERSION=1` | Version used for new encrypted passkey records |
| `ADMIN_ORIGIN`, `ADMIN_DEV_ORIGIN` | Exact origins allowed for the local admin client |
| `CHECK_SP_HOST=false` | Allows direct localhost access without the deployment-specific host check |
| `ADMIN_AUTH_MODE=local` | Independent local administration; default if omitted |

The current server initializes the admin WebAuthn service at startup, so its RP/origin/keyring configuration is needed even when you have not enrolled a passkey. Generate and retain distinct keys for each encryption purpose; do not reuse example text as a key.

```sh
go run ./cmd/server
```

Check `GET http://localhost:8080/health`. Development `.env` values do not override variables already present in the process environment.

### Register an application

The standalone local admin bootstrap is:

```sh
go run ./cmd/create-admin --email admin@example.com --db ./data/oauth.db
```

It prompts for a password and writes to the selected database. Use local credentials and a disposable database while exploring.

Register a project through the admin API or the shared MW admin console, configuring its allowed scopes and exact backend callback/browser return URLs. Save the one-time-issued project key and callback secret in the application backend. Follow the [API reference](docs/mw-oauth-service-v1-api-reference.md) to start authorization and validate the callback signature, timestamp and delivery identifier before accepting tokens.

The admin SPA lives in [MW Control Plane](https://github.com/vtmattedi/mw-plane-control), not in this repository. [Service documentation](docs/mw-oauth-service-v1-documentation.md) describes the project registration and correlation contract.

## Shared administration

`ADMIN_AUTH_MODE` supports `local`, `hybrid` and `federated`. Hybrid/federated administration uses MW Identity introspection with this service's resource-server credentials, audience `mw-oauth` and route-specific `oauth.*` scopes. Project API keys still authenticate the application-facing OAuth API.

See [Federation configuration](docs/mwoauth_federation.md). Keep introspection credentials server-side and distinct from Mail's credentials.

## Delivery and operational limits

- Callback delivery has bounded in-process retries. Failed delivery is recorded; provider tokens are not retained in a durable retry queue. Do not assume that a completed Google consent flow guarantees the application received its tokens.
- The consuming application owns the association between an OAuth transaction and its user/account, token storage and replay protection.
- Google client configuration, consent-screen settings and any required provider verification remain deployment responsibilities.
- Configure reverse-proxy/CDN logs to exclude callback query strings containing `code` and `state`. The service's safe path logging cannot control upstream logs.
- No independent security audit is claimed. Review the [hardening notes](docs/production-hardening.md) and [callback logging guidance](attention.md) before exposing a deployment.

## Deployment and development

[docker-compose.stackport.yml](docker-compose.stackport.yml) exposes the `gateway` service on container port `8282` without publishing a host port. [docker-compose.yml](docker-compose.yml) also uses `8282`; both override the direct Go example's port. The SQLite database uses the persistent `oauth-data` volume.

```sh
go test ./...
```

| Path | Purpose |
| --- | --- |
| `cmd/` | Server and local admin bootstrap |
| `internal/` | OAuth transactions, provider exchange, signed delivery, admin API, federation and persistence |
| `migrations/` | SQLite schema migrations |
| `docs/` | API contracts, federation, hardening and construction history |

The [development steps](docs/development-steps.md) are the engineering build record; use this README and the API reference as the entry points for running or integrating the current service.

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE). Third-party dependencies retain their respective licenses.
