# MW OAuth federation

MW OAuth accepts opaque MW Identity delegated tokens on its existing `/admin/api/*` business routes. Tokens are introspected at `POST /oauth/introspect`; they are never parsed locally or persisted.

## Configuration

Start rollout in hybrid mode:

```env
ADMIN_AUTH_MODE=hybrid
MW_IDENTITY_INTERNAL_BASE_URL=http://mw-identity:7100
MW_IDENTITY_INTROSPECTION_CLIENT_ID=<mw-oauth-resource-client-id>
MW_IDENTITY_INTROSPECTION_CLIENT_SECRET=<secret>
MW_IDENTITY_AUDIENCE=mw-oauth
MW_IDENTITY_HTTP_TIMEOUT_SECONDS=5
```

`local` (the compatibility default) accepts only the existing local session. `hybrid` accepts either local session authentication or a delegated Bearer token. `federated` accepts delegated tokens only and does not expose local login/session or WebAuthn endpoints. A request containing any `Authorization` header always takes the federated path and never falls back to a local cookie.

The Identity internal URL is private transport configuration, not the public issuer. Register this service as its own confidential resource server with audience `mw-oauth`; do not share its introspection credential with another service or expose it to a browser.

## Route scopes

| Routes                                                           | Required scope                                 |
| ---------------------------------------------------------------- | ---------------------------------------------- |
| `GET /admin/api/projects`                                      | `oauth.projects.read`                        |
| `POST /admin/api/projects`, `PATCH /admin/api/projects/{id}` | `oauth.projects.write`                       |
| `DELETE /admin/api/projects/{id}`                            | `oauth.projects.delete`                      |
| project API-key and callback-secret rotation                     | `oauth.credentials.rotate`                   |
| `GET` / `PUT` project Google OAuth policy                    | `oauth.policy.read` / `oauth.policy.write` |
| audit list/detail                                                | `oauth.audit.read`                           |
| metrics                                                          | `oauth.metrics.read`                         |
| server and documentation routes                                  | `oauth.server.read`                          |

Federated requests do not require a browser `Origin` or CSRF token. Local browser requests retain Host/Origin concealment, session, and mutation CSRF checks.

Each completed federated operation emits an `admin.federated.operation` audit event containing the human Identity `sub`, `auth_time`, `amr`, audience, authorized scope, and request ID. Raw delegated tokens and introspection credentials are excluded.

The public `/v1/oauth/google/authorize` project API-key contract and signed callback-secret flow are unchanged.

Project deletion returns `204` after atomically removing project credential
material, provider configuration, and OAuth transaction history. A missing
project returns `404`. A dependency protected by a retention constraint returns
`409` with `code=project_has_dependencies`. Successful deletion writes the
immutable `admin.project.deleted` audit event in the same database transaction;
its metadata retains the project ID and name after the project row is gone.
