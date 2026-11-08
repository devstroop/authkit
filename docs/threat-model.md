# AuthKit threat model

This threat model describes what AuthKit is trying to protect, who might attack
it, where trust changes hands, and which controls reduce each risk. It is a
living engineering document, not a certification or a guarantee that an attack
will fail.

Related documents:

- [Security model](security-model.md) — required controls and secure defaults.
- [Operations](operations.md) — deployment, recovery, rotation, and incident response.
- [AI Gateway migration](migration-ai-gateway.md) — one optional consumer migration, with lessons that apply to any legacy import.

Risk ratings are qualitative and relative to a normally configured deployment.
They are not actuarial estimates. Re-rate them for the operator's threat
environment and data sensitivity.

## 1. Scope and assumptions

In scope:

- AuthKit issuer, hosted login/account/admin UI, OIDC/OAuth2 endpoints, session
  handling, password and MFA authentication, email verification/reset, tenant
  authorization, audit, key management, and the native/Workers deployment
  differences.
- An optional first-party migration as one pilot. The core is not tied to any consumer.

Out of scope:

- Vulnerabilities in relying-party applications after they receive valid tokens.
- Compromise of the user's device, browser extensions, or operating system.
- Physical attacks on operator premises or Cloudflare infrastructure.
- Legal, regulatory, or contractual compliance conclusions.
- Denial-of-service attacks large enough to saturate the upstream network
  provider. Application-level abuse controls are in scope; volumetric DDoS is
  delegated to the edge provider.

Assumptions:

- Production traffic uses HTTPS at a canonical issuer, recommended as
  `auth.<apex>`.
- Production cookies are host-only; no cookie is scoped to a shared parent
  domain.
- The database and secret store are private and access-controlled.
- Operators are trusted to deploy and configure AuthKit, but insider misuse is
  still modeled because it is a realistic high-impact threat.
- Relying parties validate issuer, audience, signature, nonce, and expiry.
  AuthKit cannot force a broken client to validate tokens correctly.

## 2. Assets

| Asset | Why it matters | Impact if compromised |
| --- | --- | --- |
| Password hashes | Reuse and offline cracking can lead to account takeover | High: credential compromise across AuthKit and possibly other services |
| Plaintext passwords in transit | Immediate account takeover and password reuse | High |
| Session tokens/cookies | Bearer access to authenticated sessions | High: impersonation, including admin if the realm is compromised |
| OIDC signing private keys | Forge tokens for any relying party that trusts the issuer | Critical: ecosystem-wide impersonation |
| OAuth client secrets and API keys | Machine access to APIs and admin surfaces | High: data access, quota abuse, privileged operations |
| System-administrator capability | Control over all tenants, clients, keys, and audit | Critical |
| Tenant data and membership records | Confidential customer/workspace data and authorization state | High |
| Audit records | Detection, investigation, and accountability | High: loss of evidence and inability to reconstruct incidents |
| Email channel and reset tokens | Account recovery and verification | High: account takeover, especially for administrators |
| Configuration and deployment secrets | Database, email, KMS, and provider access | Critical |
| Migration mapping and legacy credentials | Bridge between a legacy deployment and AuthKit | High: mis-linking, privilege inflation, duplicate identities |
| Availability and CPU budget | Login and token issuance for all applications | Medium–High: outage and denial of service |

## 3. Actors

| Actor | Capability | Motivation |
| --- | --- | --- |
| Anonymous internet user | Can reach public endpoints, register if enabled, send arbitrary requests | Opportunistic access, scraping, spam, disruption |
| Automated bot / credential stuffer | Large lists of breached credentials, distributed IPs, high request volume | Account takeover, resale, fraud |
| Targeted attacker | Reconnaissance, phishing, social engineering, exploit development | Specific account, tenant, or administrator |
| Registered user | Valid low-privilege account, can manipulate their own requests and tokens | Privilege escalation, cross-tenant access, data theft |
| Malicious tenant administrator | Legitimate control of one organization | Access another tenant, escalate to system admin, exfiltrate data |
| Malicious or compromised relying party | Valid client credentials and redirect URI; may serve malicious JS | Token theft, phishing, confused-deputy attacks |
| Compromised dependency or build system | Code execution in the issuer or CI | Backdoor, secret exfiltration, signing-key theft |
| Malicious or careless insider/operator | Deployment, database, secret-store, or support access | Data theft, unauthorized support access, sabotage |
| Email attacker | Controls a user's mailbox, domain, or the email provider | Password reset, verification bypass, account takeover |
| Cloud/platform adversary or failure | D1 replication, Worker limits, provider outage, control-plane compromise | Availability loss, stale authorization, data exposure |

## 4. Trust boundaries

The detailed boundary table is in the [security model](security-model.md#2-trust-boundaries).
Threat-relevant crossings:

| Boundary | Primary threats |
| --- | --- |
| Browser → issuer | Credential stuffing, phishing, CSRF, session theft, open redirect |
| Issuer → database | SQL injection, over-broad queries, backup exposure, stale reads |
| Issuer → email/jobs | Reset-token abuse, mail bombing, provider compromise, queued PII |
| Admin browser → admin plane | Admin takeover, CSRF, privilege escalation, session theft |
| Issuer → relying party | Code interception, token replay, redirect manipulation, audience confusion |
| Tenant → tenant | IDOR, claim tampering, missing `org_id` filters, cache leakage |
| Operator/CI → deployment | Secret leakage, supply-chain compromise, unauthorized key access |
| Worker → D1/queues/secrets | Consistency bugs, CPU exhaustion, secret exposure through bindings |

## 5. Threat catalog

| ID | Threat | Scenario | Impact | Primary mitigations | Residual risk |
| --- | --- | --- | --- | --- | --- |
| T-01 | Credential stuffing | Attacker replays breached username/password pairs across many accounts | Account takeover; one successful admin account is critical | Per-account and per-IP rate limits, breached-password checks (pending), MFA, anomaly alerts, generic errors | Users reuse passwords; distributed low-and-slow attempts can evade thresholds |
| T-02 | Targeted password guessing | Attacker focuses on one known account | Takeover of a valuable user/admin | Argon2id cost, temporary throttling, MFA for admins, notifications, lockout policy | Weak chosen passwords; denial-of-service via lockout if misconfigured |
| T-03 | Phishing and MFA fatigue | Fake login page or repeated push prompts | Session/token theft or MFA approval | WebAuthn/passkeys, number matching, origin education, short sessions, step-up | TOTP and push remain phishable; users can be socially engineered |
| T-04 | Session fixation | Attacker plants a known session ID and waits for the victim to authenticate | Full session hijack | Never accept client-supplied session IDs; rotate on login/step-up; bind CSRF to session | A bug in rotation can reintroduce the issue; test coverage required |
| T-05 | Session theft via XSS/third-party script | Malicious script reads or exfiltrates credentials/session material | Impersonation; admin compromise if admin session | `HttpOnly` cookies, strict CSP, no tokens in web storage, dependency review, no user HTML | Browser/extension compromise bypasses all web controls |
| T-06 | Session leakage via URLs/logs/referrers | Token appears in a query string, referrer, proxy log, or error report | Replay by anyone with log/URL access | No tokens in URLs, `Referrer-Policy`, redacted logs, `no-store`, short TTL | Misconfigured third-party analytics or proxies can still capture URLs |
| T-07 | CSRF | Malicious site triggers a state-changing request with the victim's cookie | Unauthorized password/email/role/admin changes | Per-session CSRF token, origin checks, SameSite, POST-only mutations, no GET logout | Browser bugs or overly permissive CORS/origin allowlists |
| T-08 | Open redirect / redirect URI manipulation | Attacker changes `redirect_uri` or a post-login return URL to an attacker host | Code/token theft, phishing, account takeover | Exact redirect allowlist, URL parsing, no wildcards, relative-only return paths, state validation | A compromised or malicious registered client can still redirect its own users |
| T-09 | Authorization code interception/replay | Code stolen from logs, referrer, or a malicious app and redeemed | Token issuance to attacker | PKCE S256, single-use short-lived codes, exact redirect match, code binding, no codes in logs | Malicious client on the same device/browser can still phish the user |
| T-10 | Token replay / audience confusion | Stolen access/ID token replayed to a different API or issuer | Unauthorized API access; cross-service impersonation | Short TTL, `aud`/`iss` validation, `jti` where needed, per-API audience, TLS, no tokens in URLs | APIs that fail to validate audience remain vulnerable; bearer tokens are replayable by design |
| T-11 | Tenant escape | User changes an ID, `org_id`, or claim and reads another tenant's data | Cross-tenant data breach | Server-side membership checks, `org_id` in every query, 404 on cross-tenant access, tests, optional RLS | A single missing filter can expose data; code review and tests must be systematic |
| T-12 | Admin compromise / privilege escalation | Stolen admin session, role confusion, or a user promoted through a bug | Full tenant or issuer control | Separate admin realm, mandatory MFA, step-up, last-admin guard, explicit role model, audit, short sessions | A compromised admin endpoint or browser remains high impact |
| T-13 | Insider admin misuse | Operator uses support access to read/modify tenant data | Confidentiality/integrity loss | Least privilege, audited support access, dual control (pending), separation of duties, retention | A privileged insider with database and KMS access can bypass application controls |
| T-14 | Email takeover / reset abuse | Attacker controls the mailbox or intercepts a reset token | Account takeover, including admin if email recovery is allowed | Short single-use tokens, hash at rest, revoke sessions on reset, notify old address, MFA, generic responses | Email is not confidential; provider/mailbox compromise defeats recovery |
| T-15 | Signing key compromise | Private key stolen from a host, secret store, or backup | Forged tokens accepted by all clients | KMS/HSM or encrypted keystore, least privilege, rotation overlap, emergency rotation, monitoring | A stolen key can mint valid tokens until clients refresh JWKS and old keys are removed |
| T-16 | Secret leakage in CI/logs/backups | Secret committed, printed, or included in an artifact | Database, email, or signing-key compromise | Secret scanning, redaction, secret manager, least-privilege CI, encrypted backups, rotation | Human error and third-party tooling can still leak secrets |
| T-17 | Supply-chain compromise | Malicious crate/npm package, build action, or base image | Backdoor, secret exfiltration, data tampering | Pinned dependencies, lockfiles, review, provenance/SBOM where practical, least-privilege build, isolated deploy keys | A sophisticated upstream compromise may not be detected before deploy |
| T-18 | D1 consistency and revocation lag | Session revoked or membership removed, but a replica returns stale state | Continued access after logout/disablement | Primary/bookmark reads for authorization, short access tokens, Durable Object revocation registry, fail-closed sensitive checks | Platform replication behavior and cache TTLs leave a bounded window |
| T-19 | Workers CPU/limits denial of service | Argon2 or expensive queries exhaust CPU; requests time out or fail | Login outage, cost spike, degraded auth | Password endpoints on native origin or supported service, edge rate limits, query budgets, timeouts, queues, load shedding | A determined attacker can still consume allowed capacity or budget |
| T-20 | Audit tampering/repudiation | Attacker or insider deletes/alters audit rows to hide actions | Loss of detection and accountability | Append-only permissions, transactional writes, offsite export, restricted retention job, optional hash chain | A database/KMS administrator can alter data and backups; tamper evidence is not absolute |
| T-21 | Migration error | Auto-merge by email, imported sessions, or gateway admin mapped to system admin | Account takeover, privilege inflation, session hijack | No email auto-merge, no session import, explicit role mapping, dry runs, counts/checksums, rollback | Human mapping errors and edge-case duplicates remain possible |
| T-22 | User/account enumeration | Different errors or timing reveal registered emails/usernames | Targeted phishing and credential attacks | Generic responses, dummy password verification, uniform reset responses, rate limits | Side channels in email delivery or integrations can still leak |
| T-23 | Invitation/org takeover | Attacker intercepts an invitation or joins an org with a recycled email | Unauthorized membership or tenant access | Single-use invitation tokens, email binding, expiration, admin approval, no auto-merge, audit | Mailbox compromise or a careless admin approval |
| T-24 | Open registration abuse | Bots create accounts, consume email/quota, or squat names | Spam, cost, impersonation | Registration closed by default, invite-only, rate limits, verification, disposable-domain controls (pending) | Determined abusers can still create plausible accounts |
| T-25 | Application-level DDoS | Flood of login/token/authorize requests | Outage and cost | Edge DDoS protection, rate limits, request size/time limits, queues, autoscaling, graceful degradation | Volumetric attacks beyond provider capacity can still cause outage |

## 6. Priority threats in detail

### Account takeover and credential attacks

**Attack path:** attacker obtains a list of emails/usernames, tries common or
breached passwords, and looks for any account without MFA. A single reused
password can expose an organization if the account has broad membership.

**Controls that matter most:**

- Argon2id with calibrated cost and a server-side pepper where feasible.
- Per-account and per-IP throttling with distributed state. A per-process
  counter is bypassable across replicas and Workers locations.
- WebAuthn/passkeys for administrators and, where policy allows, ordinary users.
- Generic errors and dummy verification so account existence is not confirmed.
- Notifications for new devices, password changes, and MFA changes.
- Breach-password screening at registration/change if the privacy and
  availability trade-offs are accepted (`Decision pending`).

**Detection:** failed-login rate by account and ASN, success-after-many-failures,
impossible travel, new user-agent plus new IP, MFA denial spikes, password-reset
spikes.

**Residual:** password reuse, phishing, and low-and-slow distributed attempts
remain possible. MFA reduces but does not eliminate takeover.

### Session fixation and session theft

**Attack path:** fix a session identifier before login, steal a cookie through
XSS or a malicious extension, or obtain a token from a URL/log. The attacker
then acts as the victim until expiry or revocation.

**Controls:**

- Server-generated opaque sessions only; never accept an ID from the client.
- Rotate the session on login, step-up, privilege change, and password change.
- `HttpOnly`, host-only, `Secure` cookies; no tokens in web storage; strict CSP.
- Short idle/absolute lifetimes; admin sessions shorter.
- Session listing and "revoke all"; revoke on password reset and disablement.
- No tokens in URLs; `Referrer-Policy`; redacted logs.
- For Workers, a strongly consistent revocation path so logout is effective
  across replicas.

**Residual:** malware, a compromised browser, or a stolen device can act as the
user. Session binding to IP/UA is a signal, not a reliable control.

### Open redirect and OAuth redirect manipulation

**Attack path:** attacker supplies a `redirect_uri` or post-login `return_to`
that points to an attacker-controlled host, then steals the authorization code
or tricks the user into approving access.

**Controls:**

- Register exact redirect URIs per client; compare parsed URLs, not prefixes.
- Reject fragments, wildcards, credentials in URLs, and non-HTTPS schemes except
  loopback development clients.
- Use `state` and PKCE; bind the code to client and redirect URI.
- Restrict post-login `return_to` to relative paths or an explicit allowlist.
- Never redirect to a URL supplied only in an email or query parameter without
  validation.

**Residual:** a malicious registered client can redirect its own users; client
registration and review are therefore security-sensitive.

### Token replay and audience confusion

**Attack path:** a token issued for one API is replayed to another API, or an ID
token is used as an access token. If the resource server does not validate
audience and issuer, the token is accepted.

**Controls:**

- Separate audiences for user APIs, admin APIs, and services.
- Short access-token lifetimes; validate `iss`, `aud`, `exp`, `nbf`, signature,
  and algorithm.
- Do not accept ID tokens as API credentials.
- Use `jti` and server-side replay detection where a one-time token is intended.
- Rotate refresh tokens and revoke the family on reuse.
- Consider DPoP/mTLS for high-value clients (`Decision pending`).

**Residual:** bearer tokens are replayable if stolen. Resource servers that
ignore audience validation remain vulnerable regardless of issuer behavior.

### Tenant escape

**Attack path:** a user changes an object ID, `org_id`, or token claim, or calls
a list/export endpoint that forgets the tenant filter. A missing authorization
check exposes another workspace.

**Controls:**

- Every tenant row has `org_id`; every query filters it.
- Membership and permission checks happen server-side on each request.
- Tokens carry `org_id`, but the server compares it to the resource and current
  membership rather than trusting it blindly.
- Cross-tenant access returns 404; denied attempts are audited.
- Cache keys include tenant; authenticated responses are `no-store`.
- IDOR and claim-tampering tests are required for every object type.
- Postgres RLS is optional defense-in-depth; SQLite/D1 rely on the query layer.

**Residual:** one missed filter can cause a breach. Systematic tests, code review
checklists, and least-privilege database roles are essential. A system
administrator with support access can cross tenants by design; that path must be
explicit and audited.

### Admin compromise

**Attack path:** attacker phishes an administrator, steals an admin session, or
finds a role-mapping bug that grants system administration. The result is control
of tenants, clients, keys, and audit.

**Controls:**

- Separate admin realm, cookie, and preferably host; no cross-realm acceptance.
- Mandatory phishing-resistant MFA; TOTP fallback only where necessary.
- Step-up reauthentication for destructive actions.
- Short admin sessions; no "remember me" on admin.
- Last-active-admin guard; atomic demotion checks.
- Explicit system-admin bootstrap; no default credentials; no automatic mapping
  from application or legacy admin roles.
- Audit every admin action and denied attempt; alert on sensitive actions.
- Optional IP allowlist/VPN as defense-in-depth.

**Residual:** a compromised administrator endpoint or a malicious insider with
valid MFA can still cause damage. Dual control for the most destructive actions
is `Decision pending`.

### Email takeover and password reset abuse

**Attack path:** attacker controls the user's mailbox, intercepts a reset link,
or abuses a reset endpoint to lock the user out or take over the account.

**Controls:**

- Short-lived single-use reset tokens, stored only as digests and bound to the
  user and purpose.
- Generic responses for reset requests; rate limits per account, IP, and
  recipient domain.
- Revoke all sessions and refresh tokens after reset; notify the old address.
- Require reauthentication and verification of the new address for email changes.
- MFA and recovery codes reduce reliance on email for administrators.
- No automatic account merge based on matching email addresses.

**Residual:** email is not confidential. A mailbox or email-provider compromise
can lead to takeover. Administrators should use phishing-resistant MFA and a
recovery process that does not depend solely on email.

### D1 consistency and revocation

**Attack path:** a user logs out, is disabled, or loses a membership. The write
reaches the D1 primary, but an authorization read is served from a stale replica
or cache. The old session continues to work until replication catches up.

**Controls:**

- Route authorization-critical reads to the primary or use D1 session bookmarks
  that guarantee read-your-writes for the relevant session.
- Keep access tokens short-lived so a stale read cannot extend access for long.
- Use a strongly consistent revocation registry for immediate logout: for
  example, a per-user Durable Object or a revocation epoch checked on sensitive
  operations.
- Fail closed for destructive/admin actions and high-value reads if consistency
  cannot be established.
- Test the revocation window explicitly; document the bound.
- Cache revocation state only with a short TTL and a clear invalidation path.

**Residual:** a bounded window may remain for low-risk reads. The exact
consistency mechanism and acceptable window are `Decision pending`. Without a
primary/DO check, "logout everywhere" cannot be immediate on Workers.

### Workers CPU and platform limits

**Attack path:** an attacker floods login or password-reset endpoints.
Argon2 verification consumes CPU and memory; Workers hit CPU/time limits, queue
backlogs grow, and legitimate logins fail. Cost limits may also be exhausted.

**Controls:**

- Run password verification on the native origin or a platform-supported
  password service if Worker limits cannot safely accommodate Argon2.
- Do not lower Argon2 parameters to unsafe levels just to fit a runtime.
- Edge rate limits before expensive work; per-account/IP/client limits in a
  shared store (Durable Object or edge).
- Cap request body size, query complexity, and email send rates.
- Use queues for email, cleanup, and exports; do not block login on them.
- Load-shed with `429`/`503` and `Retry-After`; monitor CPU and subrequest
  budgets.
- Separate the admin Worker from the high-volume login Worker if practical.

**Residual:** an attacker can still consume the operator's allowed capacity or
budget. Platform CPU accounting and limits can change; load testing is required
for each deployment.

### Supply-chain compromise

**Attack path:** a malicious dependency, build action, or compromised maintainer
introduces code that exfiltrates signing keys or modifies authentication logic.

**Controls:**

- Pin dependency versions and commit lockfiles; review upgrades.
- Minimize dependencies in the authentication and key paths.
- Use least-privilege CI credentials; separate build and deploy permissions.
- Generate an SBOM/provenance where practical; scan for known vulnerabilities.
- Require review for changes to login, session, crypto, and key code.
- Store production secrets outside CI logs and artifacts; rotate after any
  suspected build compromise.
- Use isolated deploy credentials that cannot read tenant data or signing keys.

**Residual:** a sophisticated upstream compromise or a malicious maintainer can
evade review. Build reproducibility, runtime monitoring, and rapid key rotation
reduce but do not eliminate the risk.

### Migration-induced takeover

**Attack path:** during a migration from a legacy deployment, two accounts with the same
email are merged automatically, a legacy session is imported, or a gateway admin
is mapped to AuthKit system admin. The result is an unintended identity or
privilege.

**Controls:**

- No automatic merge by email. Link only through an explicit legacy-ID mapping
  or a user-initiated, verified linking flow.
- Do not migrate session rows or cookie values. Force a fresh login.
- Map gateway administrators to a gateway application admin role, never to
  AuthKit system administrator.
- Rehearse with production-like data; compare counts, identifiers, roles, and
  password-hash formats; verify sample logins.
- Feature-flag the cutover and keep a tested rollback path.
- Audit every import and mapping decision; preserve legacy IDs.

**Residual:** edge-case duplicates, stale legacy email verification flags, and
operator error can still mis-map an account. See the
[migration document](migration-ai-gateway.md#7-account-linking-policy) for the
required policy and acceptance criteria.

## 7. Risk register

Ratings: L = likelihood, I = impact, H/M/L. "Inherent" is before the listed
controls; "residual" is after them in a normally configured deployment. Re-rate
per environment.

| ID | Risk | L | I | Inherent | Residual L | Residual I | Residual | Treatment |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| T-01 | Credential stuffing | H | H | High | M | H | High | Rate limits, MFA, breach checks, monitoring |
| T-02 | Targeted password guessing | M | H | High | L | H | Medium | Argon2id, throttling, MFA |
| T-03 | Phishing / MFA fatigue | H | H | High | M | H | High | WebAuthn, number matching, education |
| T-04 | Session fixation | L | H | Medium | L | M | Low | Rotation, no client IDs, tests |
| T-05 | Session theft via XSS | M | H | High | L | M | Medium | HttpOnly, CSP, dependency review |
| T-06 | Session leakage via URLs/logs | M | H | High | L | M | Medium | No tokens in URLs, redaction |
| T-07 | CSRF | M | H | High | L | M | Low | CSRF tokens, origins, SameSite |
| T-08 | Open redirect | M | H | High | L | M | Low | Exact allowlists, PKCE, state |
| T-09 | Code interception/replay | M | H | High | L | M | Low | PKCE, single-use codes, binding |
| T-10 | Token replay/audience confusion | M | H | High | M | M | Medium | Short TTL, audience checks, sender constraints |
| T-11 | Tenant escape | M | H | High | L | H | Medium | org_id enforcement, tests, audit |
| T-12 | Admin compromise | M | H | High | L | H | Medium | Separate realm, MFA, step-up |
| T-13 | Insider admin misuse | L | H | Medium | M | H | Medium | Audit, least privilege, dual control |
| T-14 | Email takeover | M | H | High | M | H | High | Short tokens, MFA, notifications |
| T-15 | Signing-key compromise | L | H | High | L | H | Medium | KMS, rotation, monitoring |
| T-16 | Secret leakage | M | H | High | L | H | Medium | Secret manager, scanning, redaction |
| T-17 | Supply-chain compromise | M | H | High | M | H | High | Pinning, review, least-privilege CI |
| T-18 | D1 revocation lag | M | H | High | M | M | Medium | Primary reads, DO, short TTL |
| T-19 | Workers CPU DoS | M | M | Medium | M | M | Medium | Origin hashing, edge limits, queues |
| T-20 | Audit tampering | L | H | Medium | M | M | Medium | Append-only, offsite export |
| T-21 | Migration error | M | H | High | L | H | Medium | Explicit mapping, dry run, rollback |
| T-22 | Enumeration | H | M | Medium | L | L | Low | Generic errors, dummy verify |
| T-23 | Invitation/org takeover | L | H | Medium | L | M | Low | Token binding, expiry, approval |
| T-24 | Registration abuse | M | M | Medium | L | L | Low | Invite-only, limits, verification |
| T-25 | Application-level DDoS | M | M | Medium | M | M | Medium | Edge protection, rate limits, queues |

The risk register is not a promise that residual risk is acceptable. It records
the current treatment so an operator can make an explicit acceptance decision.
Risk acceptance ownership and review cadence are `Decision pending`.

## 8. Residual risks

These risks remain after the controls above. They are explicit so they are not
mistaken for solved problems.

1. **Compromised endpoint.** Malware, a malicious browser extension, or a
   compromised device can read what the user sees and act with the user's
   session. `HttpOnly` cookies do not protect against a compromised browser.
   *Compensating controls:* short sessions, step-up for sensitive actions,
   device/session listing, revocation, user notification.
2. **Email account takeover.** Email remains a recovery channel. A compromised
   mailbox can receive reset links and approvals. *Compensating controls:*
   short single-use tokens, revoke-on-reset, notification of the old address,
   MFA that does not depend on email for administrators.
3. **Malicious relying party.** A registered client can phish its own users or
   mishandle tokens. AuthKit can enforce redirect and PKCE rules but cannot make
   a client trustworthy. *Compensating controls:* client review, scoped tokens,
   short lifetimes, audit, revocation.
4. **Privileged insider.** An operator with database, KMS, and deployment access
   can bypass application authorization. *Compensating controls:* least
   privilege, separation of duties, audited support access, encrypted backups,
   dual control for key operations where practical.
5. **D1 replication window.** A stale read can preserve access briefly after
   revocation. The exact bound depends on the consistency mechanism.
   *Compensating controls:* primary reads for authorization, short access
   tokens, a Durable Object revocation registry, fail-closed sensitive checks.
6. **Worker CPU exhaustion and platform limits.** An attacker can consume the
   allowed CPU or budget even with rate limits. *Compensating controls:* edge
   protection, origin-side password hashing, queues, load shedding, spend
   alerts.
7. **Supply-chain zero-day.** A malicious or compromised dependency can evade
   review. *Compensating controls:* dependency minimization, pinning, runtime
   monitoring, rapid key rotation, isolated build credentials.
8. **Phishing-resistant MFA gaps.** TOTP fallback and email recovery can be
   phished or intercepted. *Compensating controls:* WebAuthn preferred, recovery
   codes, step-up, alerts, administrative review of MFA resets.
9. **Audit is not mathematically tamper-proof.** A sufficiently privileged
   insider can alter the database and backups. Offsite export and optional hash
   chains improve detection but do not prove integrity against all insiders.
10. **Migration mapping errors.** Duplicate emails, stale verification flags, or
    a mistaken role mapping can create an unintended identity or privilege.
    *Compensating controls:* explicit legacy-ID mapping, dry runs, counts,
    sample login tests, dual-run, rollback.
11. **Sibling-subdomain risk.** Host-only cookies prevent cookie sharing across
    subdomains, but a compromised sibling application can still phish users or
    exploit browser-level trust in the apex. *Compensating controls:* HTTPS
    everywhere, HSTS, strict CSP, user education, separate admin host.
12. **Password reuse.** A breach at another service can expose credentials that
    users reused at AuthKit. Argon2id and rate limits reduce the speed of
    offline/online attacks but do not fix reuse.
13. **Denial of service.** Application-level limits do not stop a volumetric
    attack that saturates the provider. Availability depends on the edge and
    upstream provider.
14. **Logs, backups, and exports.** These copies can outlive deletion in the
    primary database and may contain personal data. Retention and encryption
    reduce exposure; they do not make deletion instantaneous everywhere.
15. **No legal/compliance guarantee.** The controls here are engineering
    measures. Whether they satisfy a particular law, contract, or certification
    is an operator determination, not a claim made by this document.

## 9. Abuse-case test scenarios

These are implementation-level tests that should exist before a production
pilot. They are not a substitute for independent review.

| Scenario | Expected result |
| --- | --- |
| Login with a valid username and wrong password, repeated | Generic failure, throttled after the configured threshold, no account-existence difference |
| Login with unknown username and a password | Same response shape and comparable timing as a wrong password |
| Attacker supplies their own session cookie value before login | Rejected; a fresh session is issued after login |
| Session token replayed after logout | Rejected; server-side record is revoked/deleted |
| Password reset for an account | All sessions and refresh tokens revoked; old reset tokens invalidated; notification sent |
| CSRF token missing, wrong, or from another session on a mutation | Rejected with no state change |
| Cross-site form POST with a valid session cookie | Rejected by CSRF/origin checks |
| `redirect_uri` changed to an attacker host or a lookalike suffix | Rejected before authentication |
| `return_to` set to `//evil.example`, encoded URL, or absolute URL | Rejected or reduced to a safe relative path |
| Authorization code reused | Rejected; no second token issuance |
| Refresh token reused after rotation | Token family revoked; security event recorded |
| User changes `org_id` in a request or token claim | Denied; no cross-tenant data returned |
| Tenant admin attempts a system-admin action | Denied; audited |
| Gateway admin logs in after migration | Has gateway application admin role, not AuthKit system admin |
| Two accounts share an email in legacy data | Remain distinct; no automatic merge or implicit linking |
| Revoke a session, then immediately validate it | Denied via primary/DO path; bounded stale-read behavior documented and tested |
| Flood login endpoint | Rate limited before Argon2 work; no unbounded CPU/memory growth |
| Audit append fails during a privileged mutation | Mutation fails or is explicitly queued per policy; no silent untracked change |
| Worker CPU/time limit reached | Fail closed with `503`/`429`, no partial authorization or partial write |

## 10. Open decisions

| Decision | Why it matters | Current default until decided |
| --- | --- | --- |
| Final signing algorithm set | Client compatibility vs modern defaults | Ed25519 proposed; ES256 compatibility path |
| Admin host and cookie names | Isolation and host-only cookie behavior | Same issuer host under `/admin`; `__Host-authkit_session` and `__Host-authkit_admin_session` in production |
| Session idle/absolute lifetimes | Usability vs theft window | 30m/12h user; 15m/8h admin |
| Mandatory MFA scope | Security vs onboarding friction | System admins mandatory; org policy for others |
| Password endpoints on Workers | Argon2 CPU/memory feasibility | Native origin preferred; Worker password auth pending |
| Rate-limit state store | Bypass resistance and availability | Native shared store; Workers Durable Object/edge |
| D1 revocation consistency | Immediate logout vs platform constraints | Primary/bookmark reads plus short tokens; DO pending |
| Refresh-token sender constraint | Replay resistance vs client complexity | Optional; recommended for high-value clients |
| Audit tamper evidence and retention | Investigation vs cost | Append-only + offsite export; hash chain pending |
| Machine-credential ownership after a pilot | Clear authority and revocation path | Consumer enforces existing keys; AuthKit ownership pending |
| Account-linking proof requirements | Duplicate identities vs takeover risk | Explicit linking only; verification requirements pending |
| Breach-password screening | Credential quality vs privacy/availability | Pending |
| Dual control for destructive admin actions | Insider risk vs operational speed | Pending |

## 11. Review triggers

Revisit this threat model when:

- A new authentication method, token type, or credential is added.
- A new tenant-scoped resource or cross-tenant admin feature is added.
- The deployment moves between native and Workers, or changes D1 consistency
  behavior.
- Signing keys, session storage, or password hashing changes.
- A relying party with new redirect/webhook capabilities is registered.
- A security incident, near miss, or penetration-test finding occurs.
- A dependency with access to authentication or key material changes
  materially.
- Any consumer migration enters a new phase or changes its account-linking
  policy.
