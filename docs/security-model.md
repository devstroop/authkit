# AuthKit security model

AuthKit is an open-source, self-hosted identity provider for developer
platforms, built around a Rust core with native Axum/SQLx deployments and a
Cloudflare Workers variant, plus an Askama/HTMX UI. This document is the
engineering baseline for how AuthKit protects identities, credentials,
sessions, tokens, and tenant data. It is written for implementers, operators,
and reviewers. It describes required properties and the reasoning behind them;
it is not a certification, audit report, or legal guarantee.

Related documents:

- [Threat model](threat-model.md) — adversaries, attack paths, and residual risks.
- [Operations](operations.md) — deployment, backups, migrations, rotation, and incident response.
- [AI Gateway migration](migration-ai-gateway.md) — one optional pilot and its account-linking rules.

`Decision pending` marks a choice that is not final. A pending decision must not
be silently replaced by an implementation accident; record the choice and its
rationale in the relevant design or operations record.

## 1. Security objectives and non-goals

### Objectives

1. Authenticate users and service principals without exposing reusable secrets
   to applications, logs, or the browser.
2. Keep organizations/workspaces isolated. An application is an OAuth client,
   not a tenant boundary.
3. Make privilege explicit: system administration, organization membership, and
   application-scoped roles are separate concepts.
4. Protect the administrator plane more strongly than ordinary user flows.
5. Make compromise detectable, containable, and recoverable: revoke sessions,
   rotate keys, preserve audit evidence.
6. Be safe by default in both native deployments and Cloudflare Workers.

### Non-goals

- Protecting a user whose browser, device, or email account is already fully
  compromised. Controls reduce impact; they cannot make a compromised endpoint
  trustworthy.
- Guaranteeing email deliverability or treating email as a second factor.
- Protecting a relying party from its own application vulnerabilities.
- Preventing a fully privileged operator with database and key-management
  access from reading or changing data. Audit and separation of duties reduce
  this risk; they do not eliminate it.
- Making a legal compliance claim. Operators remain responsible for deciding
  which laws, contracts, and retention rules apply to them.

## 2. Trust boundaries

```text
 user browser / device                     system-admin browser
        |                                          |
        | HTTPS, host-only cookies                 | HTTPS, MFA, step-up
        v                                          v
 +--------------------- edge / reverse proxy / WAF ---------------------+
 | TLS, request limits, coarse rate limits, access logs                 |
 +-------------------------------+--------------------------------------+
                                 |
                                 v
 +------------------------ AuthKit issuer ----------------------------+
 | auth.<apex>                                                        |
 | OIDC/OAuth2 endpoints, login, reset, admin UI, audit read          |
 |                                                                    |
 |  native: Axum + SQLx          worker: workers-rs + D1              |
 +----------+--------------------------+-----------------------------+
            |                          |
            | SQL, private network     | provider APIs / queues
            v                          v
 +----------------------+      +----------------------+
 | database             |      | email, jobs, KMS     |
 | SQLite / Postgres /  |      | secrets, observability|
 | D1                   |      +----------------------+
 +----------+-----------+
            ^
            | audit export, backups
 +----------+-----------+
 | SIEM / object store  |
 +----------------------+

 relying parties (applications) <---- authorization code / tokens ---- issuer
```

| Boundary | What crosses it | Required controls |
| --- | --- | --- |
| Browser to issuer | Passwords, session cookie, CSRF token, authorization requests | TLS, host-only `Secure` cookies, CSRF checks, origin checks, request-size limits |
| Issuer to database | Password hashes, session digests, tenant data, audit records | Private network or binding, least-privilege DB role, TLS where supported, encrypted backups |
| Issuer to email/jobs | Reset links, verification links, notification content | Provider API over TLS, short-lived single-use tokens, redacted logs, idempotent jobs |
| Admin browser to admin plane | Privileged mutations, audit export, key operations | Mandatory MFA, step-up reauthentication, short admin sessions, separate cookie, full audit |
| Issuer to relying party | Authorization codes, ID/access/refresh tokens | Exact redirect allowlist, PKCE, state/nonce, short token lifetimes, audience restriction |
| Operator/CI to deployment | Secrets, migrations, configuration | Secret manager or encrypted env, review, least privilege, audit of deploys |
| Worker to D1/queues/secrets | Queries, jobs, private keys | Binding-level isolation, secret bindings, no secrets in D1/KV, consistency strategy |
| Tenant to tenant | Requests and tokens carrying an organization | Server-side membership checks, `org_id` scoping, no client-selected tenant trust |

Assumptions:

- The issuer is served over HTTPS at a canonical origin, recommended as
  `auth.<apex>`. Production cookies are host-only; no cookie is set for a shared
  parent domain.
- The database and secret store are not exposed to the public internet.
- The operator can read the database. Database read access is therefore treated
  as a potential credential-compromise event, not as a safe place to keep raw
  secrets.
- Relying parties validate issuer, audience, signature, expiry, and nonce
  according to their client type.

## 3. Identity, tenancy, and authorization

### Core concepts

| Concept | Meaning | Security consequence |
| --- | --- | --- |
| User | A person known to the issuer | Global identity; may belong to zero or more organizations |
| Organization / workspace | Tenant boundary | Every tenant-scoped row and authorization decision is scoped by `org_id` |
| Application | A registered relying party/client configuration | Not a tenant. Enabling an application for an organization is a separate grant |
| OAuth client | A credential and redirect configuration belonging to an application | Public clients have no secret and must use PKCE |
| Membership | A user's relationship to an organization, with roles | Removal or disablement takes effect server-side; tokens are not the sole authority |
| Role | A named bundle of permissions | Composable; application-scoped where applicable |
| Permission | A fine-grained capability | Checked by AuthKit and asserted in tokens for relying parties |
| System administrator | Built-in administrative principal for the issuer | Never granted by organization membership; separately bootstrapped and audited |

Applications are not tenants. Do not use `application_id` or `client_id` as the
tenant key. An application may be available to many organizations; an
organization's data is isolated by `org_id` and membership.

### Authorization rule

For a tenant-scoped operation, the server must evaluate all of the following:

```text
principal is active
and session or token is valid for this issuer and audience
and membership(principal, org_id) is active
and the membership's role set grants the required permission
and the application is enabled for org_id
and the client belongs to that application
and any resource-specific ownership rule passes
```

System administrators bypass organization membership only for explicit system
operations. Those operations require an admin session with sufficient
authentication level and are audited with the target `org_id` and reason. A
system administrator is not automatically an organization administrator in the
product model, even if the implementation gives them an emergency path.

### Token claims

Access and ID tokens should carry only what relying parties need:

| Claim | Use |
| --- | --- |
| `iss` | Canonical issuer, `https://auth.<apex>` |
| `sub` | Stable user or service-principal identifier; never an email address |
| `aud` | Intended resource/API audience |
| `org_id` | Active tenant for this token; must match the resource being accessed |
| `app_id` / `client_id` | Calling application context |
| `roles`, `permissions` | Authorization hints for the relying party; keep small |
| `sid` | Session identifier or revocation handle, when safe to expose |
| `auth_time`, `acr`, `amr` | Authentication freshness and method, for step-up decisions |
| `iat`, `exp`, `jti`, `nonce` | Lifetime, replay detection, and OIDC binding |

Do not put passwords, raw tokens, full audit details, or unnecessary personal
data in tokens. Treat tokens as readable by the client and potentially by the
browser: they are integrity-protected, not confidential from the holder.

For destructive or high-risk operations, AuthKit's own UI and admin API must
re-check current membership and account status rather than trusting a claim
minted earlier. Relying parties get the same protection from short token
lifetimes and from calling AuthKit for sensitive checks where needed.

## 4. Passwords and machine credentials

### 4.1 Password storage

Baseline requirements:

- Use **Argon2id** with a per-password random salt. Store the complete PHC
  string, including algorithm, version, parameters, salt, and output, so old
  hashes remain verifiable after a parameter change.
- Initial target: Argon2id v=19, `m=19456 KiB`, `t=2`, `p=1`, 16-byte salt,
  32-byte output. Calibrate on deployment hardware to a defensible cost
  (roughly 100–250 ms per verification under expected load). The final target
  is `Decision pending` if deployment classes differ materially.
- Do not truncate passwords. Accept at least 12 characters and at most 128
  characters (by Unicode scalar value). Length limits exist to bound work, not
  to impose composition rules. Imported credentials that predate the current
  minimum remain verifiable, but the policy for requiring a change on next use
  or through a reset is `Decision pending`.
- Verify in constant time through the password-hash library. For an unknown
  account, perform a dummy verification against a fixed valid hash so the
  response time does not reveal account existence.
- Never log, serialize, cache, or place passwords in audit details, error
  messages, traces, or crash reports.
- Rehash on successful login when the stored algorithm or parameters are below
  the current target. Never bulk-rehash without plaintext; imported hashes are
  upgraded lazily. If rehashing fails, keep the old hash and continue.
- Password change requires the current password (unless performed by an
  authorized administrator reset flow), revokes all sessions and refresh tokens
  for that principal, and sends a notification to the account's verified email.
- A server-side pepper is recommended for defense against offline cracking after
  a database leak. If used, apply a versioned construction (for example
  HMAC-SHA-256 with a key from the secret manager before Argon2) and store the
  pepper version with the hash. Pepper construction and rotation are
  `Decision pending`.
- Breach-list checking at registration/password change is `Decision pending`.
  If added, use a privacy-preserving range query and fail open only for
  availability reasons that are explicitly accepted.

### 4.2 Machine credentials

- OAuth client secrets are generated with at least 256 bits of CSPRNG entropy,
  shown once at creation/rotation, and stored only as a keyed digest or a
  slow hash appropriate to the credential's entropy. Public clients must not
  receive a secret and must use PKCE.
- API keys, if AuthKit issues them, are high-entropy, prefixed, shown once,
  stored as digests, owned by a principal, scoped to permissions/audiences,
  optionally expiring, and individually revocable. They must never appear in
  URLs, referrers, or logs.
- Machine credentials are rate-limited separately from interactive login.
  Possession of a key is not an administrator session; key role mappings must be
  explicit. In an optional API-gateway pilot, gateway API keys are not AuthKit
  system administrator credentials. See the [migration mapping](migration-ai-gateway.md#3-target-mapping).
- Whether AuthKit or the consumer owns data-plane API key issuance after a
  pilot is `Decision pending`. Until decided, the consumer may keep enforcing its
  existing keys while AuthKit owns human identity and membership.

## 5. Sessions

AuthKit has two related but distinct session layers:

1. **AuthKit browser session** at `auth.<apex>`: an opaque server-side session
   used for the hosted login, account, organization, and admin surfaces.
2. **Relying-party session**: the application's own session or token handling
   after OIDC login. A relying party on another host cannot read AuthKit's
   host-only cookie; it must use the authorization code flow and establish its
   own session. This is intentional.

### Session token requirements

- Generate at least 256 bits of CSPRNG entropy. Use an opaque value; never encode
  user data or privileges in it.
- Store only a digest at rest (SHA-256 or HMAC-SHA-256 with a server-side
  pepper). A database reader must not be able to replay a session.
- Accept the token only from the designated cookie. Do not accept session IDs
  from query strings, request bodies, or client-supplied headers.
- Rotate the session identifier at login, after MFA/step-up, after a privilege
  or organization change, and after password change. Revoke the previous record.
- Never upgrade an anonymous or pre-authentication session into an authenticated
  one. Mint a new session after successful authentication. This prevents session
  fixation.
- Enforce both an idle timeout and an absolute lifetime. Suggested baseline:
  ordinary users 12 hours idle / 7 days absolute; administrators 15–30 minutes
  idle / 8 hours absolute. Final values are `Decision pending` and must be
  documented per deployment. Shorter admin sessions are required regardless of
  the exact numbers.
- On every authenticated request, look up the active session, verify the
  principal is still active, verify the relevant membership/tenant context, and
  check expiry and revocation. A successful password check alone is not a
  continuing authorization decision.
- Revoke all sessions and refresh tokens for a principal on password
  change/reset, account disablement, administrator-forced logout, role
  downgrade that removes access, and suspected compromise.
- Provide a session list (user agent summary, approximate location if collected,
  creation and last-seen times) and "sign out other sessions". Whether users can
  see IP addresses in full is `Decision pending`; minimize retained personal
  data.
- Cap concurrent sessions per principal only if the product needs it; the cap
  and eviction policy are `Decision pending`. A cap must not let an attacker
  silently evict a legitimate session without a notification.
- Store CSRF state with the session (see section 7). Rotate the CSRF token when
  the session is rotated.
- Clean up expired/revoked sessions on a schedule. Retain revoked records only
  as long as needed for investigation, then delete them.

### Theft detection

User-agent and IP changes are risk signals, not authentication factors. Hard
binding to an IP breaks mobile networks, IPv6 privacy addresses, and corporate
proxies. Use changes to trigger step-up, notification, or revocation according
to policy; do not silently treat a changed IP as proof of theft. Never put the
session token in a place where JavaScript, analytics, or a third-party script
can read it.

### Administrator sessions

Administrator sessions are a separate realm from ordinary user sessions:

- Separate cookie name and, where possible, separate host or path.
- `SameSite=Strict`, shorter idle lifetime, and mandatory MFA.
- Step-up reauthentication for sensitive mutations (section 12).
- No cross-realm acceptance: a user session can never be interpreted as an
  administrator session, even if identifiers collide.
- Admin actions record the admin principal, authentication method, target, and
  request correlation ID.

## 6. Cookies

Production cookie rules:

| Property | Requirement |
| --- | --- |
| `Secure` | Always in production. Local HTTP development uses an explicit override that must fail closed in production. |
| `HttpOnly` | Always for session cookies. JavaScript must not read them. |
| `SameSite` | `Lax` for ordinary sessions; `Strict` for administrator sessions. SameSite is defense-in-depth, not a CSRF substitute. |
| `Domain` | Omitted. Host-only cookies only. Never set a cookie for `.example.com`. |
| `Path` | `/` for the issuer session; narrower only if the application is genuinely isolated under a path. |
| Prefix | Prefer `__Host-` names in production, which require `Secure`, `Path=/`, and no `Domain`. Proposed names are `__Host-authkit_session` and `__Host-authkit_admin_session`; final names are `Decision pending`. Local development may use non-prefixed names but must never deploy them. |
| Lifetime | `Max-Age` consistent with the server-side idle/absolute policy. Delete server-side state on logout, not just the cookie. |
| Caching | Authentication, token, session, and admin responses use `Cache-Control: no-store` and `Vary: Cookie`. Personalized HTML must not be cached by a CDN. |

Additional rules:

- Do not store access tokens, refresh tokens, ID tokens, or passwords in
  `localStorage` or `sessionStorage`. The browser session cookie is the only
  bearer secret held by the browser for AuthKit itself.
- A relying party at `app.<apex>` gets its own host-only cookie after OIDC
  login. It does not read or share AuthKit's cookie, even though both are under
  the same apex.
- Logout clears the cookie with the same attributes used to set it and revokes
  the server-side session. A client-side cookie deletion alone is not logout.
- OIDC `response_mode=form_post` may require `SameSite=None` on a cross-site
  POST. Prefer authorization code in a query parameter where possible. If
  `form_post` is required, keep `Secure`, `HttpOnly`, strict state/nonce
  validation, and origin checks; document the exception. `Decision pending` for
  the supported response modes.
- Do not reflect cookie values into HTML or logs. Set a strict
  `Referrer-Policy` (`no-referrer` on token/reset pages) so tokens in URLs do not
  leak to third parties.

## 7. CSRF and browser request integrity

- Require a per-session CSRF token on every state-changing request that is
  authenticated by a cookie: `POST`, `PUT`, `PATCH`, `DELETE`. Compare in
  constant time.
- Deliver the CSRF token in the page or API response body and require it in a
  header (for example `X-CSRF-Token`) or a hidden form field. Do not accept it
  from the query string.
- Rotate the CSRF token with the session. A token from a pre-login session must
  not authorize a post-login action.
- Check `Origin` (and `Referer` as a fallback) against the issuer origin and
  configured trusted origins for browser unsafe methods. Reject missing or
  ambiguous origins for cookie-authenticated browser requests. Non-browser
  clients should use authorization headers or client authentication instead of
  cookies.
- SameSite cookies and custom-header requirements are defense-in-depth. Do not
  rely on either alone. CORS is not a CSRF defense.
- Login CSRF: issue a pre-session CSRF token on the login page, validate it on
  submission, and always rotate the session on success. Do not let an attacker
  log a victim into an attacker-controlled account.
- Logout is `POST` with CSRF protection. A GET logout is a denial-of-service and
  CSRF vector.
- For JSON endpoints, require `Content-Type: application/json` and reject
  simple-form content types unless the endpoint is explicitly a form endpoint.
- HTMX and Askama forms must include the CSRF value in every mutating form or
  configure a trusted `hx-headers` value. Do not exempt HTMX routes from CSRF
  checks.
- Set `Content-Security-Policy` with `frame-ancestors 'none'` (or a documented
  allowlist), `X-Frame-Options: DENY` for older browsers, and a strict
  `script-src`. Do not allow user-controlled HTML in admin or account pages.
- Avoid `Access-Control-Allow-Origin: *` on authenticated endpoints. If CORS is
  needed, use exact origins, `Vary: Origin`, and no credentials unless required.

## 8. OIDC/OAuth2 tokens and flows

### Flows

- Authorization code flow only. Require PKCE with `S256` for public clients and
  strongly prefer it for confidential clients.
- Do not enable implicit flow, resource owner password credentials, or a
  password grant. Client credentials are limited to service principals and
  explicitly scoped APIs.
- Match redirect URIs exactly against the registered allowlist. No wildcards, no
  path traversal, no fragments, and HTTPS except for loopback development
  clients. Normalize and compare using a URL parser, not string prefix checks.
- Generate and validate `state` and OIDC `nonce`. Bind the authorization code to
  the client, redirect URI, and PKCE verifier. Codes are single-use and
  short-lived.
- Validate ID tokens: signature against current JWKS, allowed algorithm, `iss`,
  `aud`, `exp`, `iat`, `nonce`, and authorized party where applicable. Reject
  unknown `kid` rather than trying arbitrary keys.
- Never put tokens in URLs, referrers, or logs. Token responses use
  `Cache-Control: no-store` and `Pragma: no-cache`.

### Token lifetimes and replay resistance

| Token | Baseline | Notes |
| --- | --- | --- |
| Authorization code | 60 seconds, single use | Bound to client, redirect, PKCE; consumed atomically |
| Access token | 5–15 minutes | Audience-restricted; short enough that revocation delay is bounded |
| ID token | 5–15 minutes | For authentication only; not an API authorization token |
| Refresh token | Opaque, rotating, absolute lifetime | Hash at rest; reuse revokes the token family; client-bound |
| Browser session | Idle + absolute | Server-side; see section 5 |

Final lifetimes are `Decision pending` per client class. Access tokens should
not be accepted after expiry even if a revocation call has not reached every
cache. Include `jti` where replay detection or audit correlation is needed.

Refresh token rules:

- Store only a digest. Rotate on every use. If an already-rotated token is
  presented, revoke the family and record a security event.
- Bind to the client and, where possible, to a sender constraint such as DPoP
  or mTLS. Sender-constrained refresh is `Decision pending` for the first
  release; it is recommended for high-value confidential clients.
- Revoke on logout (for the relevant client), password change/reset, account
  disablement, and administrator action.
- Do not use refresh tokens as a substitute for reauthentication on
  high-risk operations. Admin actions require a fresh authentication level.

### Signing and validation

- Sign with an asymmetric algorithm. Ed25519 is the proposed default; ES256 is
  an acceptable alternative for client compatibility. The final algorithm set is
  `Decision pending`. Do not use `HS256` with third-party relying parties.
- Publish public keys at a JWKS endpoint with stable `kid` values. Private keys
  never leave the key service or encrypted keystore.
- Maintain an algorithm allowlist per client and reject `none`, algorithm
  confusion, and keys not currently published for signature verification.
- Use a bounded clock-skew allowance (for example 60 seconds). Do not extend
  token lifetime to compensate for unreliable clocks.

## 9. Key management and secrets

### Key inventory

| Key material | Purpose | Storage | Rotation impact |
| --- | --- | --- | --- |
| OIDC signing private key | Sign ID/access tokens | KMS/HSM or encrypted keystore; never in the database | New `kid`; old public key stays published until tokens expire |
| Session pepper / HMAC key | Protect session digests | Secret manager or KMS-wrapped key | Old sessions may need revocation or dual-read support |
| Email/reset token pepper | Protect one-time token digests | Secret manager | Outstanding links may be invalidated |
| OAuth client secrets | Confidential client authentication | Keyed digest in database; raw shown once | Overlap old/new secret during rotation |
| API key digests | Machine authentication | Database, digest only | Old key revoked; new key shown once |
| Database encryption keys | Encryption at rest | KMS/secret manager | Rewrap data keys; no plaintext export |
| SMTP/email/provider credentials | Send verification/reset mail | Secret manager or Worker secret | Provider-side rotation; resend queued mail |
| Admin bootstrap token | First system administrator | One-time secret, consumed on use | Invalid after bootstrap; reissue only through recovery |

Rules:

- Never commit secrets to the repository, container image, build logs, or
  Terraform state. Use a secret manager, KMS, or platform secret binding.
- On Workers, use the platform's secret store/bindings for private keys and
  provider credentials. D1 and KV are not approved for signing keys or other
  long-lived secrets. KV may be acceptable for public configuration only.
- Use separate keys and credentials per environment. Production keys must never
  be usable in development, test, or CI.
- Encrypt secrets at rest with envelope encryption where the platform does not
  provide a managed secret store. Keep the key-encryption key separate from the
  data store.
- Enforce least privilege on key access. Log key use where the KMS supports it.
  Separate the ability to deploy from the ability to read signing keys where
  practical.
- Validate required keys and their identifiers at startup. Fail closed if a
  signing key is missing, malformed, expired, or of a disallowed algorithm. Do
  not fall back to a development key.
- Redact secrets in logs, traces, error pages, and panic output. A request
  logger must never print `Authorization`, `Cookie`, `Set-Cookie`, passwords, or
  token request bodies.
- Back up key material separately from the database, encrypted, with access
  restricted to recovery operators. A database backup without the corresponding
  keys may be unusable for sessions or tokens; plan both together. See
  [Operations](operations.md#4-backups-and-restore).
- Rotation procedures, including emergency rotation, are in
  [Operations](operations.md#6-key-and-secret-rotation).

## 10. Email verification and password reset

Email is an identifier and a recovery channel, not an authentication factor.

### One-time tokens

- Generate at least 256 bits of CSPRNG entropy. Store only a digest with a
  purpose and user binding.
- Bind the token to purpose (verify, reset, email change, invitation), user,
  and where relevant the target email address. A reset token for one purpose
  must not work for another.
- Single use: consume atomically before changing the password or verifying the
  address. Expired or already-used tokens return a generic failure.
- Suggested lifetimes: password reset 30 minutes; email verification 24 hours;
  invitation 7 days. Final values are `Decision pending`. Shorter is safer;
  resend is cheap.
- Invalidate outstanding tokens for the same purpose when a new one is issued.
- Do not put sensitive data in the token or in the URL beyond the opaque value.
  Use `Referrer-Policy: no-referrer` on pages that receive tokens.
- Rate-limit issuance and consumption per account, per IP, and per recipient
  domain where appropriate.

### Password reset

- The request response is identical whether or not the account exists. Do not
  reveal account status in timing, text, or email delivery behavior.
- On successful reset: revoke all sessions and refresh tokens, invalidate other
  reset tokens, record an audit event, and notify the account's verified email.
- Default to requiring the user to sign in after reset. Auto-login from a reset
  link is `Decision pending`; if enabled, it must mint a fresh session, be
  single-use, and still revoke other sessions.
- Require reauthentication for an email change. Verify the new address before it
  becomes primary, and notify the old address. Whether both addresses must
  confirm is `Decision pending`; the old-address notification is mandatory.
- Never merge accounts because two rows share an email address. Account linking
  requires proof of control and an authenticated session, or an audited
  administrator action. See the [migration linking policy](migration-ai-gateway.md#7-account-linking-policy).

### Email infrastructure

- Configure SPF, DKIM, and DMARC for the sending domain and monitor bounces and
  complaints. These improve deliverability and reduce spoofing; they do not make
  email confidential.
- Do not include passwords, session tokens, or sensitive personal data in email
  subjects or bodies beyond the minimum needed.
- Treat the email provider as a trust boundary. A provider compromise or a
  mailbox takeover can lead to account takeover. Compensating controls are
  short token lifetimes, notification of security-relevant changes, MFA, and
  the ability to revoke sessions quickly.
- On Workers, send through a provider API, Email Workers, or a queue-backed
  worker. Make sends idempotent and retry-safe; do not hold a request open for a
  slow provider. See [Operations](operations.md#workers-deployment).

## 11. Rate limiting, lockout, and abuse controls

Rate limiting is layered. No single counter is trusted.

| Layer | Scope | Purpose |
| --- | --- | --- |
| Edge/WAF | IP, ASN, path, request rate | Absorb floods and obvious bots before application work |
| Login | Per account and per client IP | Slow targeted guessing and spraying |
| Token endpoint | Per client, per IP, per grant type | Prevent secret guessing and token farming |
| Password reset/verification | Per account, per IP, per recipient domain | Prevent mail bombing and token guessing |
| Admin API | Per admin session and per IP | Limit damage from a stolen admin session |
| OIDC authorize | Per IP and per client | Limit authorization-request abuse |

Baseline interactive login limits, consistent with the documented pilot:

- 5 failed attempts per account per 5 minutes.
- 20 failed attempts per client IP per 5 minutes.
- Return `429` with `Retry-After`; use generic error text.
- Clear the account counter only after a successful, fully authenticated login.
  Do not clear the IP counter on success, or an attacker can interleave attempts.

These are starting values; tune them with observed traffic. Final values are
`Decision pending` per deployment.

Rules:

- Prefer temporary throttling over permanent account lockout. Permanent lockout
  lets an unauthenticated attacker deny service to a known account. If lockout
  is required by policy, make it time-bounded, notify the user, and provide a
  recovery path.
- Do not reveal whether the account exists through a different status code,
  message, or response time.
- Apply limits to successful-looking requests too where abuse is possible
  (email sends, invitation creation, authorization requests).
- Honor `X-Forwarded-For` only from configured trusted proxies. Otherwise use
  the direct peer address. A spoofable header makes IP limits meaningless.
- On Workers, use edge rate limiting or a Durable Object keyed by account/IP.
  Per-isolate memory counters are not shared and are bypassable across
  locations. D1 counters are not a strong consistency primitive; do not rely on
  them alone for lockout.
- CAPTCHA or proof-of-work for repeated failures is `Decision pending`; it adds
  privacy and accessibility trade-offs. If used, do not make it the only
  control.
- Alert on spikes in failed logins, 429s, reset requests, and token-endpoint
  errors. Distinguish credential stuffing (many accounts, few passwords) from
  targeted guessing (one account).

## 12. Administrator protections and MFA expectations

### Bootstrap and recovery

- The first system administrator is created by an explicit bootstrap command or
  a one-time bootstrap secret, only when no system administrator exists. There
  is no default username/password.
- Require MFA enrollment at first administrator sign-in, before the account can
  create applications, issue client secrets, or read audit data.
- Store recovery codes hashed, show them once, and require regeneration after
  use. Offline break-glass material is stored outside the application database.
- The last active system administrator cannot be disabled or deleted. The
  check and the mutation must be atomic, including on D1 (batch or a single
  conditional statement), so two concurrent demotions cannot remove all admins.
- Administrator password reset requires a strong recovery process. Resetting an
  administrator's MFA requires dual control or a documented break-glass
  procedure, and is audited.

### MFA expectations

| Principal | Expectation | Notes |
| --- | --- | --- |
| System administrator | MFA mandatory; WebAuthn/passkeys preferred, TOTP fallback | Final mandatory methods are `Decision pending`; SMS is not a default |
| Organization owner/admin | MFA required by default; organization policy may enforce methods | Application admins inherit the organization's policy |
| Application/service principal | No interactive MFA; use client credentials or scoped keys | Sender constraint recommended for high-value clients |
| Ordinary user | Optional unless the organization or application requires it | Offer WebAuthn and TOTP; recovery codes |

MFA rules:

- Prefer phishing-resistant WebAuthn/passkeys for administrators. TOTP is an
  acceptable fallback but is phishable in real time.
- Rate-limit MFA attempts and prevent push-notification fatigue. If push is
  supported, use number matching or a comparable confirmation.
- Do not treat email or SMS as a strong second factor by default. Their use is
  `Decision pending` and must be documented as a risk decision.
- Step-up reauthentication is required for: signing-key operations, client
  secret reveal/rotation, system-admin creation/removal, organization deletion,
  bulk user export, audit export, MFA reset, and other destructive operations
  defined by policy. A step-up older than 15 minutes should not authorize a
  new high-risk action; final freshness is `Decision pending`.
- Impersonation is disabled by default. If enabled, require explicit user or
  organization consent where feasible, show a persistent banner, time-box the
  session, forbid password/MFA changes while impersonating, and audit start and
  end. `Decision pending`.

### Administrator plane

- Serve the admin plane on a separate host (for example
  `admin.auth.<apex>`) or, at minimum, a clearly separated path with its own
  host-only cookie and CSP. Separate host is preferred. `Decision pending` for
  the first release.
- Admin sessions use `SameSite=Strict`, shorter idle lifetime, and a separate
  audience for admin APIs.
- Admin APIs do not accept browser cookies from ordinary user sessions. Machine
  admin clients use client credentials or scoped keys with an explicit admin
  audience, never a user session token.
- Restrict admin access by VPN, IP allowlist, or an enterprise SSO policy where
  the deployment supports it. These are additional controls, not replacements
  for MFA.
- Audit every admin mutation, failed authorization, MFA change, and session
  revocation with actor, target, reason, and request ID.

## 13. Tenant isolation

Tenant isolation is enforced in the data model, query layer, and token model.

Data model:

- Every tenant-scoped table carries `org_id` as a non-null foreign key. Unique
  constraints include `org_id` where uniqueness is tenant-local.
- Memberships are unique per `(org_id, user_id)` and carry status and roles.
- Application enablement is a separate row per `(org_id, application_id)`.
  An application's client configuration is not tenant data.
- Audit rows carry `org_id` when the action is tenant-scoped, plus the target
  resource and acting principal.
- Soft-deleted or disabled organizations remain referenced by audit and
  retention records; access is denied before any data is returned.

Query and authorization rules:

- Resolve the organization from the route/resource, then verify membership and
  permission server-side. Never trust an `org_id` supplied only by a query
  parameter, form field, or token claim.
- Include `org_id` in every read and write of tenant data, including list,
  search, export, and background-job queries.
- Cross-tenant lookups return `404` rather than confirming that a resource
  exists in another tenant. Log the denied attempt with the actor and target.
- Cache keys include `org_id`; never share a cached object across tenants. CDN
  caches must not store authenticated responses.
- Background jobs and webhooks carry the tenant context explicitly and re-check
  membership/status at execution time where the action is sensitive.
- On Postgres, row-level security may be used as defense-in-depth in addition to
  application checks. On SQLite and D1, the query layer is the enforcement
  point; tests must cover every tenant-scoped query.
- System-administrator cross-tenant access is an explicit support operation with
  a reason, time limit, and audit trail. It is not an ordinary organization
  role. `Decision pending` for whether support access requires dual approval.

Testing:

- IDOR matrix for every object type: read, list, update, delete, export.
- Token-claim tampering: change `org_id`, `sub`, `roles`, or `aud` and verify
  rejection.
- Membership revocation while a session/token is live.
- Cross-tenant unique-constraint collisions (for example duplicate slugs or
  client names) must not leak existence.
- D1 consistency tests: a membership change followed immediately by a
  tenant-scoped request must not use a stale read for authorization.

## 14. Audit

Audit is a security control, not just a log. It must answer who did what, to
which tenant/resource, when, from where, and with what result.

Required fields:

| Field | Notes |
| --- | --- |
| `id` | Monotonic or otherwise stable cursor; unique |
| `occurred_at` | UTC timestamp from the event source; preserve imported timestamps |
| `recorded_at` | When AuthKit persisted the event |
| `actor_type` | `user`, `system_admin`, `service`, `system`, `migration` |
| `actor_id` | Stable principal ID; never an email as the sole identifier |
| `org_id` | Required for tenant-scoped events |
| `app_id` / `client_id` | When the action is application-scoped |
| `action` | Stable machine-readable name, for example `user.disable` |
| `target_type`, `target_id` | Affected object |
| `outcome` | `success`, `denied`, `failure` |
| `reason` | Short code or operator-supplied reason for privileged actions |
| `request_id` | Correlates with logs/traces without exposing secrets |
| `session_id` / `jti` | Optional, hashed or non-replayable identifiers only |
| `ip`, `user_agent` | Minimize/retain according to policy; never trust as identity |
| `detail` | Redacted, non-secret context; schema-versioned |

Minimum events:

- Login success/failure, MFA challenge success/failure, logout, session
  revocation, password change/reset request and completion.
- User create/update/disable/delete, email change/verification, membership and
  role changes.
- Organization create/update/delete, application create/update/delete, client
  secret create/rotate/revoke, redirect URI changes.
- API key create/rotate/revoke, key use failures, scope changes.
- Signing-key rotation, secret/config changes, migration start/end, bootstrap.
- Admin read/export of audit data and user data.
- Authorization denials for tenant and admin operations.

Integrity and handling:

- The application role can append audit records but cannot update or delete
  them through the application. Retention deletion runs as a separate,
  restricted maintenance operation.
- Write the audit record in the same transaction as a SQL-backed mutation where
  possible. On D1, use a batch or a single conditional statement; do not leave a
  mutation committed without its audit row. If the audit write fails for a
  high-risk mutation, fail the mutation. The failure policy for low-risk events
  is `Decision pending`.
- Never place passwords, raw tokens, client secrets, API keys, or full request
  bodies in `detail`. Hash or fingerprint identifiers if correlation is needed.
- Consider a hash chain or periodic signed checkpoints for tamper evidence.
  This is `Decision pending`; it adds cost and complicates retention. Database
  access controls and offsite export are required regardless.
- Export and retention are covered in [Operations](operations.md#8-audit-export-and-retention).

## 15. Data retention and deletion

Retention is an operator policy constrained by security needs and applicable
law. The values below are starting defaults, not legal advice. Exact periods are
`Decision pending` per deployment.

| Data | Suggested default | Notes |
| --- | --- | --- |
| Active sessions | Until idle/absolute expiry | Revoked records retained briefly for investigation |
| Expired/revoked sessions | 30 days | Then purge; do not retain raw tokens (only digests exist) |
| Password reset tokens | 30 minutes after issue or on use | Purge promptly |
| Email verification tokens | 24 hours after issue or on use | Purge promptly |
| Authentication/security logs | 30–90 days | Redacted; correlate with audit via request ID |
| Audit records | 180 days to 1 year (longer if required) | Export before retention deletion |
| Disabled/deleted users | 30-day grace, then delete/anonymize | Preserve audit references with pseudonymous IDs |
| Backups | 30–90 days | Encrypted; retention independent of live deletion |
| Exported audit/SIEM data | Operator-defined | Protect as sensitive; access-controlled |

Deletion rules:

- Deleting a user revokes sessions and refresh tokens, removes memberships, and
  records a tombstone audit event. Whether the user row is hard-deleted or
  pseudonymized is `Decision pending`; audit references must remain coherent.
- Deleting an organization disables access first, then removes or archives
  tenant data according to policy. Do not leave orphaned credentials or
  sessions.
- Backups age out on their own schedule. Do not promise immediate deletion from
  immutable backups; document the limitation.
- Legal holds and regulatory retention are operator decisions (`Decision
  pending`). AuthKit should provide export and deletion tooling, not a legal
  conclusion.

## 16. Secure defaults

The following defaults are required unless an operator explicitly changes them
with a documented risk decision:

- Closed registration by default. Organization creation and invitations are
  restricted by policy.
- Deny by default: no implicit access from a valid session or token; every
  operation needs a permission.
- Exact redirect URI matching; PKCE required for public clients; no implicit or
  password grants.
- Short access-token lifetimes; rotating refresh tokens; revocation on password
  change and disablement.
- Host-only, `Secure`, `HttpOnly` cookies in production; no parent-domain
  cookies; no tokens in web storage.
- CSRF protection on all cookie-authenticated mutations; origin checks; strict
  CSP and framing protection.
- Administrator MFA mandatory; short admin sessions; step-up for destructive
  actions; last-admin protection; no default credentials.
- Password hashing with Argon2id at a calibrated cost; generic authentication
  errors; dummy verification for unknown accounts.
- Rate limits at the edge and in the application; trusted-proxy configuration
  required before honoring forwarded IP headers.
- Audit enabled and written transactionally for privileged mutations; secrets
  redacted everywhere.
- TLS required; HSTS enabled after confirming all subdomains are HTTPS-ready;
  no plaintext HTTP listener in production.
- Database and secret store private; least-privilege credentials; encrypted
  backups.
- Dependency versions pinned and reviewed; build artifacts reproducible where
  practical; no secrets in build logs.
- Worker deployments use secret bindings, not D1/KV, for private keys, and route
  CPU-heavy password verification to an approved runtime if the Worker limits
  cannot support Argon2 safely.

## 17. Worker-specific security risks

Cloudflare Workers change the threat surface. The following controls are
required where the corresponding feature is used.

| Risk | Why it matters | Required control |
| --- | --- | --- |
| No SQLx / different DB driver | Query behavior and transaction semantics differ from native | Use a D1 data layer with explicit SQL, parameter binding, and tests against D1 semantics. Do not assume Postgres behavior. |
| D1 has no interactive transactions | Multi-step read-modify-write can interleave or partially apply | Use `batch()` for atomic statement groups, single conditional `UPDATE ... WHERE`, unique constraints, and idempotency keys. Never hold a logical transaction across requests. |
| D1 read replication lag | A revoked session, disabled user, or changed membership may be read stale | Route authorization-critical reads to the primary or use D1 session bookmarks/`first-primary` semantics; keep access tokens short; use a strongly consistent revocation registry (for example a Durable Object) for immediate logout. See [Threat model](threat-model.md#d1-consistency-and-revocation). |
| Argon2 CPU and memory | Password verification can exceed Worker CPU/memory budgets or cause noisy-neighbor failure | Prefer running password endpoints on the native origin over a private, authenticated internal path, or use a platform-supported password service. Do not lower Argon2 parameters to unsafe levels without an explicit, documented risk acceptance. Whether password auth is allowed directly on Workers is `Decision pending`. |
| Secret storage differences | D1/KV are not appropriate for private signing keys | Use Worker secret bindings or the platform secret store. Keep signing keys out of D1, KV, and source. |
| Email and background jobs | No long-running process, no local filesystem, provider latency | Use Email Workers/provider APIs, Queues, and Cron Triggers. Make jobs idempotent; retry with backoff; never block a login response on email delivery. |
| Rate limiting | Per-isolate memory is not shared across locations | Use edge rate limiting or a Durable Object keyed by account/IP/client. Do not rely on in-memory counters for security limits. |
| Static UI and caching | Askama/HTMX pages may be cached or personalized incorrectly | Bundle templates at build time, set `no-store` on authenticated pages, vary on cookies, and never cache a response containing a CSRF token or personal data at the edge. |
| Subrequest/CPU/time limits | Complex authorization or token flows can exceed budgets | Set explicit query/request budgets, avoid unbounded loops and regexes, cap body size, use queues for fan-out, and fail closed on timeout. |
| Logging and observability | Worker logs may be sampled or exported differently | Structured logs with redaction; correlate via request ID; do not log headers or token bodies. |
| Cold starts and clock skew | Latency spikes and timestamp differences | Use bounded clock skew, timeouts, and retries; never weaken token expiry validation to hide skew. |
| Admin plane on Workers | Higher-value target on a shared platform | Prefer a separate Worker/host with stricter access, MFA, and rate limits. Decide explicitly whether the admin plane is Worker-hosted: `Decision pending`. |
| Backup/export differences | D1 recovery is not a file copy | Use D1 export/time-travel features and periodic encrypted exports. Test restore. See [Operations](operations.md#4-backups-and-restore). |

If a control cannot be met on Workers, the feature must be disabled there or
served from the native deployment. Do not silently degrade a security property
to preserve feature parity.

## 18. Security invariants and review checklist

Security invariants:

1. No raw password, session token, refresh token, client secret, or API key is
   stored in plaintext or written to logs.
2. A user session can never become an administrator session by changing a
   cookie, claim, or route.
3. Every tenant-scoped query is constrained by `org_id`; an application is
   never used as a tenant key.
4. Every cookie-authenticated mutation has CSRF and origin protection.
5. Production session cookies are host-only, `Secure`, and `HttpOnly`.
6. Redirect URIs are exact-match and PKCE is required for public clients.
7. Access tokens are short-lived and audience-restricted; refresh tokens rotate
   and detect reuse.
8. Password changes, resets, and disablement revoke sessions and refresh tokens.
9. Administrators use MFA and reauthenticate for high-risk actions; the last
   active system administrator cannot be removed.
10. Signing keys and private secrets live in a key service/secret store, never
    in the database or repository.
11. Audit records for privileged mutations are written with the mutation and
    never contain secrets.
12. Startup fails closed on missing keys, invalid configuration, or an
    unsupported database schema version.
13. Worker deployments do not weaken password hashing, revocation, or rate
    limiting to fit platform limits.
14. Account linking is explicit; email equality alone never merges identities.
15. Migration never imports sessions or grants system administration from
    legacy application roles.

Review checklist for security-relevant changes:

- Does the change add a new credential, token, cookie, or trust boundary?
- Does it add a tenant-scoped table or query without `org_id` enforcement?
- Does it introduce a new redirect, callback, webhook, or CORS origin?
- Does it change password hashing, session lifetime, or token signing?
- Does it add a Worker path with CPU-heavy work or new D1 reads on the
  authorization hot path?
- Does it add an admin action without step-up, audit, and last-admin safety?
- Does it change account linking, email verification, or password reset?
- Are errors generic and logs redacted?
- Are rollback and key-rotation impacts understood?

Update the [threat model](threat-model.md) when a change adds a new actor,
asset, trust boundary, or externally reachable flow, or when it changes a
mitigation listed there.
