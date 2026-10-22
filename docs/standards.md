# Standards and conformance

AuthKit implements a focused OIDC/OAuth 2.0 profile. It does not attempt to be a universal
identity broker or a visual flow platform. This document defines the protocol surface,
endpoint behavior, token and session rules, explicitly deferred features, and the
conformance test approach.

Related documents:

- [Architecture](architecture.md)
- [Domain model](domain-model.md)
- [Runtime targets](runtime-targets.md)
- [UI stack](ui-stack.md)

## 1. Standards baseline

AuthKit targets these specifications and profiles:

| Area | Standard |
| --- | --- |
| OAuth 2.0 core | RFC 6749, RFC 6750 |
| PKCE | RFC 7636 |
| Authorization server metadata | RFC 8414 |
| OIDC Core | OpenID Connect Core 1.0 |
| OIDC Discovery | OpenID Connect Discovery 1.0 |
| JWT access tokens | RFC 9068 |
| Token revocation | RFC 7009 |
| RP-initiated logout | OpenID Connect RP-Initiated Logout 1.0 |
| Resource indicators | RFC 8707 |
| Security best practice | OAuth 2.0 Security Best Current Practice (RFC 9700) |
| JWT | RFC 7519; JWS RFC 7515; JWK RFC 7517 |
| Browser cookies | RFC 6265bis cookie prefixes and attributes as implemented by browsers |

OAuth 2.1 is still a moving target. AuthKit follows the stable RFCs and the security BCP
rather than claiming compliance with a draft. Where the BCP and older interoperability
expectations differ, the stricter behavior is documented and configurable only when a
deployment explicitly accepts the risk.

### Issuer

- One issuer per deployment, recommended as `https://auth.<apex>` (for example,
  `https://auth.example.com`).
- The issuer identifier is an exact string, HTTPS, with no query or fragment. Do not use a
  path-based issuer such as `https://example.com/auth`. Path issuers complicate discovery,
  cookie scope, reverse-proxy routing, and migration.
- Endpoints are paths under the issuer host. That is not a path-based issuer: the issuer is
  still the origin, and every `iss` value is exactly `https://auth.example.com`.
- The issuer cannot change without breaking registered clients and existing tokens. Treat it
  as immutable for the deployment's lifetime. Migration requires a new deployment and client
  re-registration, or a carefully designed compatibility window. **Decision pending:**
  whether an issuer migration tool is in scope.
- Organizations are not issuers. A tenant does not get `https://auth.example.com/orgs/acme`.
  Tenancy is carried in membership, authorization, and token claims, not in the issuer URL.

## 2. Discovery and metadata

Discovery documents:

```text
GET https://auth.example.com/.well-known/openid-configuration
GET https://auth.example.com/.well-known/oauth-authorization-server
```

Both return JSON with `Cache-Control` suitable for caching (for example, minutes, not
seconds) and an `ETag`. The OIDC document is authoritative for OIDC clients; the OAuth
metadata document is provided for OAuth-only clients. Their shared values must agree.

Required metadata:

```json
{
  "issuer": "https://auth.example.com",
  "authorization_endpoint": "https://auth.example.com/oauth2/authorize",
  "token_endpoint": "https://auth.example.com/oauth2/token",
  "userinfo_endpoint": "https://auth.example.com/oauth2/userinfo",
  "jwks_uri": "https://auth.example.com/oauth2/jwks",
  "revocation_endpoint": "https://auth.example.com/oauth2/revoke",
  "end_session_endpoint": "https://auth.example.com/oauth2/logout",
  "response_types_supported": ["code"],
  "response_modes_supported": ["query"],
  "grant_types_supported": ["authorization_code", "refresh_token", "client_credentials"],
  "subject_types_supported": ["public"],
  "id_token_signing_alg_values_supported": ["ES256"],
  "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "none"],
  "revocation_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
  "code_challenge_methods_supported": ["S256"],
  "scopes_supported": ["openid", "profile", "email", "offline_access"],
  "claims_supported": [
    "iss", "sub", "aud", "exp", "iat", "auth_time", "nonce", "acr", "amr",
    "azp", "sid", "at_hash", "name", "email", "email_verified"
  ],
  "claims_parameter_supported": false,
  "request_parameter_supported": false,
  "request_uri_parameter_supported": false,
  "require_request_uri_registration": false,
  "tls_client_certificate_bound_access_tokens": false
}
```

Rules:

- Do not advertise a capability that is not implemented on the current runtime. The
  Workers-lite profile may omit `refresh_token` or password-related behavior if the
  deployment disables them.
- `id_token_signing_alg_values_supported` matches the keys actually published. Do not
  advertise `none` or HS256.
- `response_modes_supported` is `query` for the code flow. `form_post` may be added only
  after it is implemented and tested. **Decision pending:** whether `form_post` is needed
  for clients with URL length constraints.
- Dynamic client registration (RFC 7591) is not supported in v1. Clients are created through
  the admin UI/API. Do not advertise `registration_endpoint`.
- `request` and `request_uri` parameters (JAR) are not supported in v1. Reject them rather
  than silently ignoring them.
- `claims_parameter_supported` is false; the `claims` request parameter is rejected in v1.
- Metadata is generated from the same configuration used by the endpoints. Hard-coded
  documents that drift from behavior are a release blocker.

## 3. Authorization endpoint

```text
GET /oauth2/authorize
```

### 3.1 Request parameters

| Parameter | Requirement | Behavior |
| --- | --- | --- |
| `response_type` | Required | Must be `code`. Implicit and hybrid are not supported. |
| `client_id` | Required | Resolve to an active client and its application/organization. |
| `redirect_uri` | Required | Exact match against a registered URI. No wildcards, no fragments. |
| `scope` | Required for OIDC | Space-delimited. Must include `openid` for an ID token. Unknown scopes are rejected. |
| `state` | Recommended | Opaque to AuthKit; echoed exactly. Applications must verify it. |
| `nonce` | Required for OIDC in AuthKit | Bound into the ID token. Rejected if missing when `openid` is requested. |
| `code_challenge` | Required for public clients; required by policy for confidential clients unless explicitly exempted | 43-128 characters, base64url. |
| `code_challenge_method` | Required with challenge | `S256` only. `plain` is rejected outside tests. |
| `prompt` | Optional | `none`, `login`, `consent`, `select_account` as supported. |
| `max_age` | Optional | Forces reauthentication when the authentication is older. |
| `login_hint` | Optional | Prefills the identifier; never authenticates by itself. |
| `acr_values` | Optional | Only advertised/supported values are honored; otherwise `invalid_request`. |
| `ui_locales` | Optional | Best-effort localization. Unsupported locales fall back to the deployment default. |
| `resource` | Optional | RFC 8707 resource indicator; constrains the access-token audience. |

**Decision pending:** whether PKCE is mandatory for every client, including confidential
BFF clients. The recommendation is to require S256 for all clients, with a documented
exemption only for a legacy confidential client during migration. OAuth 2.1 and the
security BCP push in this direction.

**Decision pending:** whether `nonce` is mandatory for all OIDC authorization-code requests
(AuthKit's stricter profile) or only recommended. If mandatory, clients that omit it receive
`invalid_request` before any redirect.

### 3.2 Validation order

1. Parse the request without trusting any parameter.
2. Resolve `client_id`. If it is unknown or disabled, return a local error page. Never
   redirect to an unvalidated URI.
3. Validate `redirect_uri` exactly against the client's registered list. If it does not
   match, return a local error page.
4. Validate `response_type`, `scope`, PKCE, nonce, and other parameters. Once the client and
   redirect URI are valid, protocol errors redirect to the redirect URI with `error`,
   `error_description` (non-sensitive), and the original `state`.
5. Authenticate the user if there is no active AuthKit session, or if `prompt=login` or
   `max_age` requires it.
6. Resolve the tenant from the client's application. Verify that the user has an active
   membership in that organization. A user who is not a member receives `access_denied`
   after authentication, not a cross-tenant token.
7. Evaluate consent. First-party clients may be auto-consented only under an explicit policy;
   otherwise show the consent screen for requested scopes not already granted.
8. Issue a code and redirect.

Open redirects are prevented by exact matching before any redirect. Error responses must not
reflect attacker-controlled HTML. Use a local error page for invalid clients and redirect
URIs, and a plain redirect error for valid clients.

### 3.3 Authorization code

- At least 256 bits of cryptographically secure randomness, base64url encoded.
- Stored only as a hash, with `client_id`, `user_id`, `org_id`, exact `redirect_uri`,
  `scope`, PKCE challenge/method, `nonce`, `auth_time`, and `sid`.
- Lifetime: short, recommended 60 seconds; configurable within a strict maximum.
- Single use. Consumption is a guarded update; replay is audited and, where possible,
  revokes tokens issued from that code.
- Bound to the client and redirect URI. A code presented by another client or with a
  different redirect URI fails with `invalid_grant`.
- A code is not a JWT and is never logged.

### 3.4 Consent

- Consent is per user, client, and organization, with the granted scope set.
- Adding scopes requires a new consent. Reducing scopes does not.
- The consent screen lists the client name, application, organization, and human-readable
  scopes. It does not display raw internal permission keys.
- Denial redirects with `access_denied` and the original `state`.
- Consent grants are auditable and revocable in the account UI. Revoking consent does not
  automatically revoke existing refresh families unless the user also revokes access.
  **Decision pending:** whether consent revocation revokes active refresh tokens.
- First-party auto-consent is **Decision pending**. If enabled, it is restricted to clients
  explicitly marked first-party by a system administrator, still recorded as an audit event,
  and still visible in the account UI.

### 3.5 Prompt and session behavior

- `prompt=none`: never show UI. Return `login_required`, `consent_required`, or
  `interaction_required` as appropriate.
- `prompt=login`: force reauthentication even with an active session.
- `prompt=consent`: force the consent screen.
- `prompt=select_account`: show account selection for a user with multiple sessions or
  identities. **Decision pending:** whether AuthKit supports multiple simultaneous user
  sessions in one browser. The default is one active AuthKit session per browser profile.
- `max_age`: if `auth_time` is older than allowed, reauthenticate. The new `auth_time` is
  reflected in the ID token.

## 4. Token endpoint

```text
POST /oauth2/token
Content-Type: application/x-www-form-urlencoded
```

- TLS is required outside local development.
- JSON request bodies are rejected. Parameters are form-encoded.
- Client credentials are never accepted in the query string.
- Responses use `Cache-Control: no-store` and `Pragma: no-cache`.
- Errors are JSON with `error` and a non-sensitive `error_description`. Do not redirect from
  the token endpoint.
- Rate limits apply per client, per IP, and per grant type. Rate-limit failures return
  `temporarily_unavailable` or HTTP 429 with `Retry-After`, not `invalid_grant`.

### 4.1 Client authentication

Supported in v1:

- `client_secret_basic` (preferred for confidential clients).
- `client_secret_post` (allowed for compatibility; discouraged).
- `none` for public clients using PKCE.

Deferred:

- `private_key_jwt` and mTLS (`tls_client_certificate_bound_access_tokens`) are not in v1.
- JWT-secured authorization requests and JARM are not in v1.

Client secrets are high-entropy values stored as keyed hashes. Basic authentication parsing
follows RFC 6749, including form-url-decoding of the client ID and secret. Reject multiple
authentication methods in one request.

### 4.2 Authorization code grant

Required parameters: `grant_type=authorization_code`, `code`, `redirect_uri`, `client_id`
(for public clients), `code_verifier`, and client authentication as applicable.

Checks:

1. Client is active and authenticated.
2. Code hash exists, is unexpired, unconsumed, and belongs to this client.
3. `redirect_uri` matches the value used at authorization exactly.
4. PKCE verifier hashes to the stored S256 challenge.
5. The user and organization are still active and the membership is still valid.
6. The requested scopes are a subset of the authorized scopes.

On success, issue an access token, an ID token for OIDC requests, and a refresh token when
the client is allowed the refresh grant and `offline_access` was requested (or the OAuth
client is configured for refresh without OIDC). Rotate the session if the token exchange
occurred in a browser context that has an AuthKit session and a privilege change is implied.
**Decision pending:** whether code exchange always rotates the OP session; the conservative
default is yes when the code was issued from that session.

### 4.3 Refresh token grant

Required: `grant_type=refresh_token`, `refresh_token`, client authentication.

- Refresh tokens are opaque, at least 256 bits, stored as hashes.
- Every successful use rotates the refresh token. The old token is consumed atomically.
- Presenting a consumed token is replay. Revoke the entire family, audit with high severity,
  and return `invalid_grant`.
- A refresh request may narrow scopes, never widen them. Requesting a scope outside the
  original grant fails.
- The ID token is not reissued by default unless the client requests `openid` and the
  original grant included it. If reissued, it carries the current `auth_time` and fresh
  claims. **Decision pending:** whether refresh returns a new ID token by default.
- Absolute refresh-family lifetime and idle expiry are configurable and enforced server-side.
  The recommendation is a bounded absolute lifetime with rotation on every use. Revocation
  is checked against primary-consistent storage on D1.
- Refresh tokens are not accepted from public clients that did not use PKCE, and are never
  issued to client-credentials grants.

### 4.4 Client credentials grant

- Confidential clients only. Public clients cannot use this grant.
- No user, no ID token, no refresh token.
- The subject is the client identity, for example `client_id`, and the token is marked as a
  service token. Do not stuff a synthetic user into `sub`.
- Scopes are limited to those registered for the client and allowed for the grant.
- The access token audience is the requested resource or the client's configured default
  resource. It is never the OIDC client ID by accident.
- Secret rotation invalidates the old secret at the configured overlap boundary. Audit client
  credential use and failures.
- Rate limiting and anomaly detection apply. A leaked service secret should be rotatable
  without downtime.

### 4.5 Token response

```json
{
  "access_token": "...",
  "token_type": "Bearer",
  "expires_in": 600,
  "refresh_token": "...",
  "scope": "openid profile email offline_access",
  "id_token": "..."
}
```

- `expires_in` is the access-token lifetime in seconds.
- `scope` is the granted scope, which may be narrower than requested.
- `refresh_token` and `id_token` are present only when applicable.
- No token is ever returned in a URL fragment or query string.
- Do not include internal tenant IDs, role lists, or permission lists in the token response
  beyond the documented claims.

## 5. Tokens and claims

### 5.1 Access token

- JWT with `typ=at+jwt` (RFC 9068), signed ES256 by default.
- Short lifetime, recommended 5-15 minutes; configurable.
- Claims: `iss`, `sub`, `aud`, `exp`, `iat`, `nbf` (optional), `jti`, `client_id`,
  `scope`, and the tenant claim described below. `auth_time` and `sid` may be included when
  useful for correlation.
- `aud` identifies the resource server/API, not the OAuth client. Clients request a resource
  with RFC 8707 `resource`, or receive a default resource configured on the client. Resource
  servers must reject tokens whose `aud` does not include their identifier.
- `scope` is a space-delimited string. Do not encode roles or permissions as scopes; those
  belong to the application's own authorization model.
- Tenant claim: AuthKit needs a stable way to identify the organization in an access token.
  The recommendation is a namespaced claim such as `urn:authkit:org_id` rather than a bare
  `org_id` that could collide with application claims. **Decision pending:** the exact claim
  name and whether it is always present. It must be derived from the client's application
  tenant, never from a request parameter.
- Access tokens are not session cookies. A resource server must not treat them as proof of an
  interactive session, and must not accept ID tokens as access tokens.

### 5.2 ID token

- Signed JWT with `iss`, `sub`, `aud` (the client ID), `exp`, `iat`, `auth_time`, `nonce`
  (when provided), `amr`, `acr` (when applicable), `azp` (when needed), `sid`, and profile
  or email claims only when the corresponding scopes were granted.
- `sub` is the stable opaque user identifier (`usr_...`), not an email address. It never
  changes when the email changes. Public subject type is used in v1; pairwise subjects are
  deferred.
- `email` and `email_verified` are included only with the `email` scope. Do not include an
  unverified email as verified.
- `nonce` is copied exactly from the authorization request when present. Clients must verify
  it.
- `at_hash` may be included when an access token is issued alongside the ID token. Verify
  support in conformance tests before advertising behavior that depends on it.
- ID tokens are not used for API authorization.

### 5.3 Token lifetimes and clocks

Recommended starting points, all configurable:

| Artifact | Lifetime |
| --- | --- |
| Authorization code | 60 seconds, single use |
| Access token | 5-15 minutes |
| ID token | Same order as the access token |
| Refresh token | Rotated every use; bounded family lifetime |
| AuthKit session idle | 30 minutes for admin, longer for account UI |
| AuthKit session absolute | 12 hours, or shorter for system admin |
| Clock skew allowance | 60 seconds |

These are durations, not calendar deadlines. Deployments may tighten them. Do not extend
access-token lifetimes to compensate for missing revocation; fix revocation instead.

### 5.4 JWKS and key rotation

```text
GET /oauth2/jwks
```

- Returns a JWK Set with public keys only. Include `kid`, `kty`, `use=sig`, `alg`, and the
  algorithm-specific parameters.
- Multiple keys are published during rotation. The active key signs; `next` keys are
  published before use; retired keys remain published until the maximum token lifetime has
  elapsed.
- `Cache-Control` is short enough to allow rotation but long enough to avoid per-request
  fetches. Clients must handle an unknown `kid` by refetching JWKS with rate limiting.
- Never publish private key parameters. Never return a key without a `kid`.
- Algorithm confusion attacks are prevented by an allowlist on the verifier and by checking
  `alg` against the key type. Never accept `none`.
- Key compromise response: mark the key retired/compromised, publish the new key, stop
  signing with the old key, and document that already issued tokens may remain valid until
  expiry. **Decision pending:** whether a compromised-key denylist is supported.

## 6. Userinfo

```text
GET /oauth2/userinfo
POST /oauth2/userinfo
Authorization: Bearer <access_token>
```

- Requires a valid access token with `openid` and the relevant scopes.
- Returns `sub` and claims allowed by the granted scopes: `name`, `email`,
  `email_verified`, and similar standard claims. Do not return internal roles, permissions,
  organization membership lists, or secrets.
- `sub` must exactly match the access token's `sub`.
- Invalid or expired token: HTTP 401 with
  `WWW-Authenticate: Bearer error="invalid_token"`.
- Insufficient scope: HTTP 403 with `error="insufficient_scope"`.
- Responses are `Cache-Control: no-store`.
- Userinfo is not an authorization endpoint. Applications must enforce their own
  authorization using token claims and their domain data.
- CORS is disabled by default because userinfo is intended for server-side callers. If a
  browser client needs it, an explicit allowlist is required. **Decision pending:** whether
  CORS is supported at all in v1.

## 7. Revocation

```text
POST /oauth2/revoke
Content-Type: application/x-www-form-urlencoded
```

Parameters: `token`, optional `token_type_hint` (`access_token` or `refresh_token`), and
client authentication.

- Authenticate the client. A client may revoke only its own tokens.
- Revoking a refresh token revokes the entire family, including unconsumed descendants.
- Revoking an access token is best-effort for JWTs. If opaque access tokens are enabled, the
  stored token is revoked and introspection reflects it. With JWTs, the resource server may
  continue to accept the token until expiry; document this.
- Unknown or already revoked tokens return HTTP 200 for a valid client, per RFC 7009, to
  avoid token-state probing.
- Revocation is idempotent and audited. Do not log the token.
- Revocation endpoint authentication failures use `invalid_client`; malformed requests use
  `invalid_request`.
- Token-family revocation on password change, session compromise, client secret rotation, and
  membership removal is an application policy, not something the client requests.

## 8. RP-initiated logout

```text
GET/POST /oauth2/logout
```

Parameters:

- `id_token_hint`: recommended. AuthKit validates signature, issuer, audience, and subject.
  An expired ID token may be accepted within a short grace window if the session is still
  active. **Decision pending:** the exact grace policy.
- `post_logout_redirect_uri`: must exactly match a URI registered for the client. If absent
  or invalid, show a signed-out page and do not redirect.
- `state`: echoed to the post-logout redirect URI for client correlation.
- `client_id`: may be used when no ID token hint is available, but it does not by itself
  authorize an arbitrary redirect.

Behavior:

1. Validate the hint and the redirect URI.
2. Revoke the AuthKit session and clear the host-only session cookie.
3. Optionally revoke refresh families associated with the session/client. **Decision
   pending:** whether logout revokes all client tokens for the session or only ends the OP
   session. The recommendation is to end the OP session and revoke the refresh family for the
   requesting client, while leaving other clients' tokens to their own logout flows.
4. Redirect to the exact post-logout URI with `state`, or show a confirmation page.

Limitations:

- AuthKit cannot clear cookies for application origins. Each application must implement its
  own logout and clear its own host-only session.
- There is no parent-domain logout cookie. `auth.example.com` cannot and must not clear
  `app.example.com`.
- OIDC Front-Channel Logout and Back-Channel Logout are deferred. Session Management 1.0
  iframe-based logout is deferred because third-party cookies and iframe storage are
  restricted by browsers and unreliable. RP-initiated logout is the supported mechanism.
- Logout is a POST when initiated from the AuthKit UI. The endpoint may accept GET for
  protocol compatibility, but state-changing browser-initiated logout from the UI uses POST
  with CSRF protection.

## 9. Token validation guidance for resource servers

Resource servers must:

1. Fetch JWKS over HTTPS and cache it with a bounded TTL.
2. Select the key by `kid`; if unknown, refetch JWKS at most once per cooldown.
3. Allowlist algorithms (ES256; EdDSA only if deployed and advertised) and reject `none`.
4. Verify the signature over the exact compact serialization.
5. Verify `iss` exactly equals the configured issuer.
6. Verify `aud` contains this resource server's identifier.
7. Verify `exp` and `nbf` with a small clock skew, and reject tokens with an implausible
   `iat`.
8. Verify `typ` is `at+jwt` for access tokens. Do not accept ID tokens as access tokens.
9. Enforce `scope`, tenant, and subject authorization in the application.
10. Never trust `X-Auth-Request-*` or similar identity headers from the internet.

Clients validating ID tokens must also verify `nonce`, `state` (their own), `aud` equal to
their client ID, `azp` when multiple audiences are present, and the token's age relative to
the authorization request.

## 10. Session, cookie, and CSRF recommendations

- Session cookies are host-only, `Secure`, `HttpOnly`, `SameSite=Lax`, `Path=/`, and use the
  `__Host-` prefix. No `Domain` attribute. No parent-domain cookies.
- OAuth access and refresh tokens are not stored in browser-accessible storage. Browser
  applications use a BFF. See [UI stack](ui-stack.md).
- Session tokens are opaque, high-entropy, hashed at rest, and rotated on login, privilege
  change, and organization switch.
- Idle and absolute timeouts are enforced server-side. Logout revokes the session row and
  clears the cookie.
- CSRF protection uses a synchronizer token for authenticated forms and signed double-submit
  for pre-authentication forms, plus `Origin` checks and `SameSite=Lax`. No state-changing
  GET.
- Auth pages and token responses use `Cache-Control: no-store`.
- Authorization and consent pages send `frame-ancestors 'none'` and a strict CSP to prevent
  clickjacking and script injection.
- Do not put tokens, authorization codes, session IDs, or CSRF tokens in logs, referrers, or
  analytics.
- `state` is required for application CSRF protection even though AuthKit treats it as
  opaque. AuthKit echoes it and never uses it for authorization.
- The token endpoint is not CSRF-protected because it does not use cookies; client
  authentication and PKCE provide the relevant protections. Browser-based public clients
  still need PKCE and exact redirect URI matching.

## 11. Explicitly deferred

The following are not in v1. They must not appear as half-implemented options in the UI or
metadata.

| Feature | Status | Rationale |
| --- | --- | --- |
| SAML 2.0 SP/IdP | Deferred | Enterprise protocol surface, XML canonicalization, metadata, and certification cost. |
| SCIM 2.0 | Deferred | Provisioning is a separate product with its own schema and conflict semantics. |
| LDAP / Active Directory bind | Deferred | Network appliance integration, bind semantics, and directory-specific schema. |
| Outposts / connectors | Deferred | Trust and deployment complexity; contradicts the direct OIDC integration model. |
| Auth proxy / forward-auth | Deferred | Header trust, traffic coupling, and host-only cookie conflicts. |
| Visual flow builder | Deferred | Product complexity and a large policy engine; AuthKit ships opinionated flows. |
| Implicit and hybrid flows | Not supported | Deprecated by the security BCP; tokens in URLs. |
| Resource owner password credentials | Not supported | Teaches password collection by clients; incompatible with MFA and federation. |
| Device authorization grant | Deferred | Useful for constrained CLIs, but loopback PKCE covers the initial CLI use case. |
| Dynamic client registration | Deferred | Admin-managed clients are safer for a self-hosted product. |
| Token exchange (RFC 8693) | Deferred | Impersonation and delegation semantics need a separate design. |
| JWT bearer grant | Deferred | Trust configuration and replay handling are out of scope. |
| PAR, JAR, JARM | Deferred | Added complexity; revisit if request objects become an interoperability requirement. |
| DPoP and mTLS-bound tokens | Deferred | Sender-constrained tokens are valuable but require client and resource-server support. |
| CIBA | Deferred | Out of scope for developer-platform authentication. |
| Front-channel / back-channel logout | Deferred | Browser restrictions and protocol complexity; RP-initiated logout is supported. |
| OIDC session management iframe | Deferred | Third-party cookie restrictions make it unreliable. |
| Pairwise subject identifiers | Deferred | Public subjects are the v1 default. |
| Custom domains per organization | Deferred | One issuer per deployment; host-only cookies. |
| Per-organization issuers | Not supported | Organizations are tenants, not issuers. |

Deferred does not mean rejected forever. It means no compatibility promise and no UI
affordance in v1. Revisiting requires a design document, threat model, and conformance plan.

## 12. Conformance and test approach

### 12.1 Certification target

The target is OpenID Provider certification for the profiles AuthKit implements, using the
OpenID Foundation conformance suite. Candidate profiles:

- OP Basic.
- OP Config (discovery/metadata).
- RP-Initiated Logout.
- Dynamic OP only if dynamic client registration is later added.

AuthKit must not claim certification before the suite passes and the results are published.
**Decision pending:** whether certification is a v1 requirement or a post-v1 milestone.

### 12.2 Test layers

1. **Unit tests:** request parsing, parameter validation, PKCE verification, scope handling,
   redirect URI matching, claim construction, error mapping, and token lifetime rules.
2. **Domain/property tests:** refresh rotation and reuse detection, code single-use, session
   rotation, last-owner invariants, and permission algebra. Use a fake clock and deterministic
   IDs.
3. **Adapter contract tests:** run the same repository and command-batch suite against
   SQLite, Postgres, and D1. Verify guarded writes, conflict behavior, and uniqueness.
4. **Protocol integration tests:** drive the authorization endpoint with a real browser
   session using a test client; exchange codes; validate tokens against JWKS; refresh;
   revoke; logout.
5. **Conformance suite:** run the OpenID Foundation tests against a dedicated deployment with
   test clients and keys. Store logs and diffs as artifacts.
6. **Interoperability tests:** at least one Rust, one Python, one JVM, and one JavaScript
   OIDC client. Include a CLI loopback client and a BFF. Do not rely on a single client
   library's quirks.
7. **Security tests:** authorization code replay, PKCE downgrade, redirect URI mismatch,
   open redirect, CSRF, session fixation, token reuse, algorithm confusion, JWKS rotation,
   expired-token acceptance, cross-tenant access, and logout redirect abuse.
8. **Runtime matrix:** native SQLite, native Postgres, Workers-lite D1. The same protocol
   tests run where the feature is supported; unsupported features are asserted to fail
   closed.
9. **Load and soak tests:** login, authorization, token exchange, refresh, JWKS, and
   revocation under realistic concurrency; measure D1 and Postgres behavior separately.

### 12.3 Required negative tests

- Authorization request with an unregistered `redirect_uri` does not redirect.
- Authorization request with `response_type=token` is rejected.
- Code exchange without PKCE verifier fails for a public client.
- Code replay fails and is audited.
- Refresh reuse revokes the family.
- Token request with two client authentication methods fails.
- Token request with credentials in the query string fails.
- ID token used as an access token is rejected by the resource server.
- `alg=none` and algorithm substitution are rejected.
- Unknown `kid` triggers a bounded JWKS refetch, not an unbounded loop.
- Logout with an unregistered post-logout URI does not redirect.
- Cross-tenant reads and writes fail even with a valid session and a forged tenant ID.
- CSRF-less POST to an admin or consent route fails.
- A GET request cannot revoke a session, delete a client, or log out.

### 12.4 Conformance evidence

For each release, retain:

- the conformance suite version and profile list;
- the discovery document and JWKS used;
- pass/fail results with logs;
- known deviations and their security rationale;
- the runtime matrix coverage;
- a signed or reproducible build identifier.

This is evidence for users, not marketing. A passing basic OP suite does not prove tenancy,
authorization, or operational security; those require the custom tests above.

## 13. Open standards decisions

1. Whether PKCE S256 is mandatory for confidential clients.
2. Whether `nonce` is mandatory for all OIDC code requests.
3. The exact namespaced tenant claim and whether it appears in ID tokens as well as access
   tokens.
4. Access-token resource/audience defaults and whether RFC 8707 `resource` is required for
   multi-resource clients.
5. Refresh-family absolute lifetime, ID-token reissue on refresh, and logout revocation
   semantics.
6. Consent auto-approval policy for first-party clients.
7. Introspection support and its authentication/rate-limit model.
8. Whether `form_post` response mode is needed.
9. OpenID certification as a v1 requirement.
10. Whether any deferred feature (device flow, PAR, DPoP, back-channel logout) is promoted
    before v1.

See [Architecture](architecture.md) for runtime context, [Domain model](domain-model.md) for
the persisted grant and session state, and [UI stack](ui-stack.md) for the login, consent,
and logout pages that implement this profile.
