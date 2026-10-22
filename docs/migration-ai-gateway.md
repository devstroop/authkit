# Migrating AI Gateway auth to AuthKit

AI Gateway is one optional AuthKit pilot. This document inventories the gateway's
current authentication, defines the target mapping, and specifies a phased
migration with dual-run, rollback, audit continuity, and acceptance criteria.

Related documents:

- [Security model](security-model.md) — controls the target must preserve.
- [Threat model](threat-model.md) — migration-specific threats and residual risks.
- [Operations](operations.md) — backups, migrations, key rotation, and incident response.

No schedule is implied. Phases are ordered by dependencies, not by a
schedule. Items that are not final are marked `Decision pending`.

## 1. Goals and non-goals

### Goals

1. Make AuthKit the source of human identity for the AI Gateway admin and web
   consoles.
2. Preserve existing access without silently merging identities or inflating
   privileges.
3. Map existing gateway administrators to **gateway application administrators**,
   never to AuthKit system administrators.
4. Preserve audit continuity across the cutover.
5. Keep a tested rollback path until the legacy auth path is decommissioned.
6. Avoid exposing password hashes, API keys, sessions, or reset tokens during
   export/import.

### Non-goals

- Migrating existing sessions or CSRF tokens. Sessions are intentionally not
  portable.
- Auto-merging users because they share an email address.
- Granting any legacy gateway role the AuthKit system-administrator role.
- Redesigning gateway authorization or data-plane API-key semantics in the same
  cutover.
- Making the gateway multi-tenant. The pilot uses one gateway
  organization/workspace; additional workspaces are a later product decision.
- Changing the gateway's LLM proxy behavior.

### Invariants

- No session row, cookie value, or CSRF token is imported into AuthKit.
- No two identities are merged by email equality alone.
- Gateway admins become members of a gateway organization with a gateway
  application admin role.
- AuthKit system administrators are bootstrapped separately.
- Password hashes are imported only as verifiable Argon2id PHC strings; invalid
  hashes force a reset, never a bypass.
- Gateway API keys remain valid under a single authority; no period has two
  independent validators with divergent revocation.
- Every imported identity and audit record retains a traceable legacy ID.

## 2. Current AI Gateway auth inventory

The inventory below reflects the gateway's current implementation. Verify it
against the exact release being migrated; schema or behavior may have changed.

### 2.1 Identity tables

| Table | Fields | Current behavior | Migration relevance |
| --- | --- | --- | --- |
| `admin_users` | `id` (`adm_…`), `username` (case-insensitive unique), `password_hash`, `role` (currently `admin`), `disabled`, `created_at`, `updated_at`, `last_login_at` | Username/password login for `/admin`; Argon2id hashes; bootstrap from environment only when the table is empty; last active admin cannot be disabled/deleted | Maps to AuthKit user + gateway organization membership + `gateway_admin` role |
| `web_users` | `id` (`usr_…`), `email` (case-insensitive unique), `password_hash`, `display_name`, `email_verified` (defaults to true for admin-created users), `disabled`, `created_at`, `updated_at`, `last_login_at` | Email/password login for the web console; no self-registration; admin-managed accounts | Maps to AuthKit user + membership + `gateway_user` role; verification state needs care |
| `auth_sessions` | `token_hash` (SHA-256), `realm` (`admin`/`web`), `principal_id`, `csrf_token`, `created_at`, `last_seen_at`, `expires_at`, `revoked_at`, `user_agent`, `ip` | Opaque server-side sessions; admin TTL 12 hours, web TTL 7 days; token digest stored; separate realms; password change/disable/reset revokes sessions | **Do not migrate.** Delete or ignore at cutover; force fresh login |
| `managed_keys` | `name` (primary key), `hash` (`sha256:<hex>`), `role` (`admin`/`user`), `owner`, `scopes`, `models`, `quota_bucket`, `created_at`, `last_used_at` | Runtime-managed gateway API keys; raw value shown once with `sk-gw-` prefix; only digest stored; rotate resets `last_used_at` | Keep gateway as validator for the pilot; optionally import digest later. Never import as a human password |

### 2.2 Cookies and session mechanics

| Item | Current value / behavior |
| --- | --- |
| Admin cookie | `gw_admin_session`; `HttpOnly`; `SameSite=Strict`; host-only (no `Domain`); `Secure` when the request is HTTPS or `GATEWAY_COOKIE_SECURE` forces it |
| Web cookie | `gw_web_session`; `HttpOnly`; `SameSite=Lax`; host-only; `Secure` under the same conditions |
| Session token | 32 random bytes, hex encoded; only `sha256:<hex>` stored |
| CSRF | Per-session token returned with the session payload; required in `x-csrf-token` for unsafe methods when authenticated by cookie |
| Logout | Deletes the server-side session; clears the cookie |
| Password change | Verifies the current password, hashes the new one, revokes all sessions for that principal |
| Admin actions on users | Create/update/disable/delete/reset password; guarded against removing the last active admin |
| Rate limiting | 5 failed attempts per account per 5 minutes; 20 per client IP per 5 minutes; process-local in-memory counters (cleared on restart) |

### 2.3 Password handling

- Argon2id via the Rust `argon2` crate with a fresh random salt and the PHC
  string stored in `password_hash`.
- Minimum 12 characters, maximum 128; length-only policy.
- Malformed hashes are treated as a non-match; they are not a panic.
- The current bootstrap creates a first admin from environment variables only
  when `admin_users` is empty. There is no default account.

### 2.4 API keys

| Class | Storage | Identity / role | Notes |
| --- | --- | --- | --- |
| Legacy `api_keys` | Raw values in configuration; hashed at load; never persisted raw | Unnamed; identity is `key:<fingerprint prefix>` | Static deployment keys |
| Named `[[keys]]` | Raw `key` (hashed at load) or pre-hashed `key_hash`; configuration is immutable at runtime | `name`, `role` (`admin`/`user`), `owner`, scopes, models, quota bucket | Admin-role keys may call `/api/admin/*` |
| Runtime managed keys | `managed_keys` table, SHA-256 digest only | `name`, `role`, `owner`, scopes, models, quota bucket, `last_used_at` | Created/rotated/revoked through the admin API; raw value returned once |

Key roles are gateway roles. "admin" for a key means it can call gateway admin
APIs; it is not the AuthKit system-administrator role and must not be mapped to
one.

### 2.5 Audit

- `audit_log` is append-only from the application: `id` (autoincrement cursor),
  `at` (Unix seconds), `actor`, `action`, `target`, `detail` JSON.
- Admin mutations (key create/rotate/revoke, proxy changes, console user
  changes, session eviction) append an entry. When the mutation is a database
  write, the audit row is written in the same transaction.
- Actor is typically a key identity (`key:<name>` or fingerprint) or `open` in
  open mode. Passwords and raw keys are not supposed to appear in `detail`.
- Retention is capped by configuration (`max_entries`); older rows are dropped.
- A legacy JSONL file may have been imported once; the database is authoritative
  afterward.

### 2.6 What the gateway does not have

- No organizations/workspaces or tenant boundary beyond the single deployment.
- No OIDC/OAuth2 clients or external identity providers.
- No composable roles/permissions; roles are coarse `admin`/`user` values for
  keys, and admin users are always `admin`.
- No email verification delivery or self-service password reset in the current
  local-auth flow. Web accounts are created as verified by an administrator.
- No shared parent-domain cookies; cookies are already host-only.

## 3. Target mapping

### 3.1 Tenant and application model

| Gateway concept | AuthKit concept | Rule |
| --- | --- | --- |
| Gateway deployment / workspace | Organization (workspace) named `ai-gateway` | One organization for the pilot. Separate AuthKit organizations for separate environments/deployments, not per application |
| Admin console | Application `ai-gateway-admin` | Application is a relying party, not a tenant. Enabled for the `ai-gateway` organization |
| Web console | Application `ai-gateway-web` | Separate application preserves the current admin/web realm separation |
| Gateway admin user | User + membership in `ai-gateway` + `gateway_admin` role | Never a system administrator |
| Gateway web user | User + membership in `ai-gateway` + `gateway_user` role | Never a system administrator |
| Gateway API key | Gateway machine credential, optionally linked to a service principal | Keep gateway validation for the pilot; do not convert a key role to AuthKit system admin |
| AuthKit system administrator | Separate AuthKit principal, bootstrapped with MFA | **No legacy gateway row maps to this role.** Gateway admins are application admins only |

Applications are not tenants. The gateway's data is scoped by the `ai-gateway`
organization. A future multi-workspace gateway must create one organization per
workspace and enforce `org_id` on every query.

### 3.2 Roles and permissions

Create gateway-specific roles in AuthKit. Names are illustrative; keep them
stable once clients depend on them.

| AuthKit role | Scope | Suggested permissions | Maps from |
| --- | --- | --- | --- |
| `gateway_admin` | `ai-gateway` organization + admin application | `gateway.admin.console`, `gateway.users.manage`, `gateway.keys.manage`, `gateway.proxies.manage`, `gateway.audit.read`, `gateway.sessions.manage` | `admin_users.role = 'admin'` |
| `gateway_auditor` | Organization + admin application | `gateway.audit.read`, `gateway.users.read` | Optional; create only if needed |
| `gateway_user` | Organization + web application | `gateway.web.console`, `gateway.usage.read` | Every `web_users` row |
| `gateway_service` | Organization + service/API client | `gateway.api.invoke`, plus existing key scopes/models | Machine principals, if API keys move to AuthKit |

Rules:

- `gateway_admin` is an application/organization role. It is not
  `system_admin` and does not grant access to other organizations or AuthKit
  signing keys.
- Do not grant `gateway_admin` to every web user, and do not infer it from an
  email domain.
- Keep the permission set narrow. The gateway must continue to enforce its own
  data-plane rules (models, quotas, scopes) even when AuthKit asserts roles.
- The role mapping is explicit per legacy row. Unknown role values stop the
  import for that row and require an operator decision; they are not silently
  defaulted.

### 3.3 Field mapping

| Legacy field | AuthKit target | Notes |
| --- | --- | --- |
| `admin_users.id` | `legacy_identity_map.authkit_user_id` with `legacy_realm='admin'`, `legacy_id` preserved | Do not reuse the legacy ID as the AuthKit `sub`; keep a mapping |
| `admin_users.username` | Login handle / `preferred_username`; optionally a separate username field | If it looks like an email, do not mark it as a verified email or use it for linking |
| `admin_users.password_hash` | Password credential, scheme `argon2id-legacy-gateway` | Import PHC as-is if valid; lazy rehash |
| `admin_users.role` | `gateway_admin` membership role | Never `system_admin` |
| `admin_users.disabled` | User disabled state and membership inactive | Do not disable a different AuthKit user with the same email |
| `admin_users.created_at`, `updated_at`, `last_login_at` | Preserve as legacy metadata; AuthKit tracks its own timestamps | `last_login_at` is informational after cutover |
| `web_users.id` | `legacy_identity_map.authkit_user_id` with `legacy_realm='web'` | Same person may have both admin and web rows; keep separate unless explicitly linked |
| `web_users.email` | User email/identifier | Preserve the normalized value; do not merge on equality |
| `web_users.password_hash` | Password credential | Same Argon2id import rules |
| `web_users.display_name` | Display name | Optional; preserve if present |
| `web_users.email_verified` | Verification metadata `legacy_asserted` | The gateway defaults this to true; treat it as untrusted for linking/privileged recovery. Final policy is `Decision pending` |
| `web_users.disabled` | User disabled state and membership inactive | Per-row mapping only |
| `auth_sessions.*` | **Discard** | No session import; no cookie translation |
| API key rows | Gateway remains authority for the pilot | Digest import only if/when ownership moves; never import as a user password |
| `audit_log.*` | AuthKit audit with `legacy_source='ai-gateway'` and preserved `legacy_id`/`occurred_at` | Actor is a legacy key identity, not a fabricated human |

### 3.4 Identity mapping table

Use an explicit mapping table rather than matching on email. Sketch:

```sql
CREATE TABLE legacy_identity_map (
    source           TEXT NOT NULL,          -- 'ai-gateway'
    legacy_realm     TEXT NOT NULL,          -- 'admin' or 'web'
    legacy_id        TEXT NOT NULL,          -- original adm_… / usr_… id
    authkit_user_id  TEXT NOT NULL,
    legacy_email     TEXT,                   -- informational, normalized; not a key
    link_method      TEXT NOT NULL,          -- 'migration', 'user_verified', 'admin_assisted'
    linked_at        INTEGER NOT NULL,
    PRIMARY KEY (source, legacy_realm, legacy_id),
    UNIQUE (authkit_user_id, source, legacy_realm)
);
```

The mapping is sensitive: it links old and new identities. Restrict access,
encrypt backups, and audit reads/exports. Do not expose it through a public API.

The gateway should store its own `authkit_sub` → local principal mapping (or
equivalent) so its existing database references remain stable. Do not change
legacy foreign keys across the gateway database during the auth cutover.

### 3.5 Claim and session mapping

- AuthKit issues an ID token/access token with `sub`, `org_id`, `app_id`/`client_id`,
  roles, and permissions.
- The gateway validates issuer, audience, signature, nonce/state, and expiry via
  AuthKit JWKS.
- The gateway resolves `sub` through its local mapping to the legacy principal
  and then applies its existing authorization rules.
- The gateway keeps its own host-only session cookie after OIDC login. It cannot
  read AuthKit's host-only cookie on a different host. Its session has its own
  CSRF token and logout behavior.
- Do not accept an AuthKit token for the admin console if its audience is the
  web application, and vice versa. Use separate clients/audiences.
- Confirmed client type for each console (server-side confidential BFF vs public
  SPA with PKCE) is `Decision pending`. A BFF keeps the client secret off the
  browser and is preferred if the gateway already serves the console.

## 4. Phased migration

Each phase has an exit criterion. Do not start the next phase because a
checklist says so; start it when the criterion is actually met.

### Phase 0 — Inventory, freeze, and rehearsal

- Take a verified gateway database backup and an audit export.
- Record row counts and checksums for `admin_users`, `web_users`,
  `managed_keys`, and `audit_log`.
- List duplicate emails across admin and web realms. Do not resolve them by
  merging.
- Inventory API keys by class, role, owner, and last use. Identify keys that
  must remain valid across the cutover.
- Confirm the gateway release and schema version to migrate.
- Provision a staging AuthKit environment and rehearse the import with a
  production-like copy.
- Define feature flags, rollback trigger thresholds, and operator roles.
- Confirm the canonical issuer and the gateway redirect URIs.
- Decide the account-linking policy exceptions (`Decision pending`) before
  importing, not during an incident.

Exit: production-like import succeeds; counts reconcile; sample logins work; no
system admin was created by the import; rollback is rehearsed.

### Phase 1 — AuthKit provisioning and identity import

- Create the `ai-gateway` organization, the two applications, OAuth clients,
  roles, permissions, and exact redirect URIs.
- Bootstrap a separate AuthKit system administrator with MFA. Do not reuse a
  migrated gateway admin account for this purpose; create a distinct
  system-admin identity for that person, separate from their gateway
  application admin membership.
- Import `admin_users` and `web_users` into distinct AuthKit users and
  memberships. Preserve legacy IDs in the mapping table.
- Import password hashes as Argon2id PHC strings. Mark invalid hashes for reset.
- Import audit records with source/legacy IDs. Do not import sessions, CSRF
  tokens, cookies, or rate-limit counters.
- Keep AuthKit login disabled for imported users, or restrict it to a test
  allowlist. Import alone must not open a new login path.

Exit: user/membership counts match source (plus any explicitly documented
exceptions); hash validation passes; roles are correct; no system admin was
created; audit counts reconcile.

### Phase 2 — Shadow and canary

- Run AuthKit in shadow mode: identities and roles are present, but the gateway
  continues to authenticate locally.
- For a small canary of administrators, enable AuthKit OIDC login behind a
  feature flag. The gateway validates tokens and creates its own session.
- Monitor login success, token validation errors, mapping misses, role
  mismatches, and admin actions.
- Do not allow password changes in both systems. Choose a single credential
  authority per realm during the canary (`Decision pending`).
- Reconcile any identity or role discrepancies before expanding.

Exit: canary admins complete real work; no privilege inflation; rollback to
local login works; no audit gaps.

### Phase 3 — Admin console cutover

- Announce that admin users will be signed out and must sign in through AuthKit.
- Put the gateway admin auth path in maintenance or read-only mode if needed.
- Enable AuthKit OIDC for all admin users. Disable local admin login.
- Clear/revoke old `gw_admin_session` sessions and reject the old cookie path.
- Verify: login, MFA/step-up, user management, key management, proxy
  management, audit access, logout, password reset, and session revocation.
- Keep `admin_users` and its hashes intact for rollback; do not drop them.

Exit: all active admins can authenticate through AuthKit; local admin login is
disabled; rollback is still available; audit is continuous.

### Phase 4 — Web console cutover

- Repeat the cutover for `web_users` and `gw_web_session`.
- Communicate the sign-out and the new login flow. Expect higher support volume
  than the admin cutover.
- Verify ordinary user login, display name, disabled-account behavior, and
  organization membership.
- Keep the web legacy table and password hashes until acceptance and rollback
  windows pass.

Exit: active web users can authenticate; disabled users stay disabled; no
cross-realm access; local web login is disabled; rollback remains available.

### Phase 5 — Decommission legacy auth

- Disable and remove local login/reset/bootstrap endpoints from the gateway.
- Remove `GATEWAY_ADMIN_USERNAME`/`GATEWAY_ADMIN_PASSWORD` and other legacy auth
  secrets from deployment configuration.
- Archive `admin_users`, `web_users`, and `auth_sessions` according to retention
  policy, or drop them after the rollback window and required retention.
- Remove stale cookies and any old callback routes.
- Decide API-key ownership. Until it is moved, keep the gateway as the sole
  validator and document that it is a legacy component.
- Verify no traffic reaches legacy auth endpoints, then remove dead code.
- Rotate secrets that were used by the legacy path.

Exit: legacy auth is unreachable and removed; AuthKit is the only human auth
path; API-key ownership is documented; audit export is complete.

## 5. Dual-run and feature flags

### Flag model

Use explicit, server-side flags. Do not rely on a client-side toggle.

| Flag / mode | Effect |
| --- | --- |
| `AUTH_MODE=legacy` | Gateway local auth only; AuthKit login disabled |
| `AUTH_MODE=shadow` | AuthKit identities imported/read-only; gateway local auth remains authoritative |
| `AUTH_MODE=authkit` | AuthKit OIDC is the only human login path; local login disabled |
| `AUTH_CANARY_USERS` | Explicit allowlist for canary login (server-side) |
| `AUTH_ADMIN_ENABLED` / `AUTH_WEB_ENABLED` | Independent realm switches for phased cutover |
| `MIGRATION_READ_ONLY` | Blocks password/email/role writes in AuthKit during import validation |

Feature flags must fail closed. If the AuthKit provider is unavailable after
cutover, do not silently fall back to legacy password login unless an operator
has explicitly enabled a time-bounded emergency mode. That mode must be audited
and removed after use; the final policy is `Decision pending`.

### Single credential authority

At any time, exactly one system is authoritative for password changes in a given
realm:

- During shadow, the gateway is authoritative. AuthKit is read-only for imported
  credentials.
- During canary, choose the authority per realm. If AuthKit is authoritative,
  do not accept password changes through the legacy gateway path.
- After cutover, AuthKit is authoritative. The legacy path is disabled.

Do not implement bidirectional password-hash synchronization. It creates
conflicting hashes, race conditions, and ambiguous rollback.

### Gateway session after OIDC

AuthKit and the gateway are different hosts even under the same apex. Host-only
cookies are not shared. After a successful OIDC code exchange, the gateway:

1. Validates the ID token/access token and `state`/`nonce`.
2. Resolves `sub` to the local principal via the mapping table.
3. Checks the principal is active and has the expected membership/role.
4. Creates its own server-side session and host-only cookie with a CSRF token.
5. Redirects to the console without putting tokens in the URL.

The gateway's session TTL can be shorter than AuthKit's. Logout should revoke
the gateway session and, where practical, trigger AuthKit logout or token
revocation. Cross-domain logout is `Decision pending`; do not pretend a gateway
cookie deletion logs the user out of AuthKit.

### Reconciliation during dual-run

- Reconcile counts and role assignments after every import batch.
- Record mapping exceptions with a reason and owner.
- Compare audit action counts; do not duplicate rows on retries.
- Monitor legacy endpoint hits after cutover; each hit is a regression.
- Review admin actions performed through the new path with the same rigor as
  before.

## 6. Rollback

### Before cutover

- Set `AUTH_MODE=legacy` (or disable the canary allowlist).
- Keep legacy tables and password hashes intact.
- No session migration means users simply log in again with their existing
  gateway password.
- Investigate the AuthKit issue without blocking gateway access.

### After admin or web cutover

- Re-enable the legacy auth path for that realm behind the flag.
- Restore the old callback/routes if they were removed; do not drop the tables
  until acceptance.
- Old gateway sessions were revoked at cutover, so users must sign in again.
  This is expected and is preferable to reviving unknown sessions.
- If passwords were changed in AuthKit during the AuthKit-authoritative period,
  those changes do not exist in the gateway. Rollback requires either a password
  reset or an explicit one-way hash copy from AuthKit to the gateway for the
  affected accounts. The latter is `Decision pending` and must be audited; it is
  not a routine path.
- If roles or memberships changed in AuthKit, export the changes and decide
  whether to reapply them in the gateway. Do not assume rollback preserves them.

### After decommission

Rollback requires restoring the gateway database/backup and re-enabling the old
code. Treat it as a full incident, not a flag flip. Sessions and passwords
changed after decommission are not in the old backup.

### Rollback triggers

- Sustained login failure or a large increase in support incidents.
- Any gateway admin mapped to system admin or another tenant.
- Mapping misses that block legitimate users.
- Audit gaps or duplicate audit rows.
- Security regression in cookies, CSRF, redirect validation, or token validation.
- AuthKit availability below the agreed threshold.

## 7. Account-linking policy

### Default: no automatic merge

Each legacy row becomes its own AuthKit user:

- An `admin_users` row and a `web_users` row with the same email are **not**
  merged.
- Duplicate emails within a legacy table are **not** merged automatically. They
  block the import for manual resolution.
- An email match with an existing AuthKit user is **not** a link. It may be a
  different person, a recycled address, or an attacker who pre-registered.
- A gateway API-key `owner` string is **not** an identity link unless it maps to
  a known legacy ID.

### Explicit linking

Linking is a separate, audited action:

1. The user initiates linking from an authenticated session, or an authorized
   administrator starts an assisted flow.
2. The user proves control of both identities: an active session/password for
   each, or a fresh verification of both email addresses after reauthentication.
   The exact proof required is `Decision pending`.
3. Linking an administrator requires MFA and a step-up. Linking to a system
   administrator is prohibited unless the system administrator initiates it and
   the action is separately approved.
4. Both legacy IDs remain in the mapping table. Prefer adding an external
   identity to one AuthKit user over destructively merging two users.
5. Record `link_method`, actor, timestamp, and reason in audit.
6. Revoke sessions for the linked identities and require a fresh login.
7. Provide an unlink procedure with the same audit requirements. Unlinking must
   not silently drop memberships; resolve roles explicitly.

### Email verification after migration

The gateway's `web_users.email_verified` defaults to true and was set by an
administrator, not by proof of mailbox control. Therefore:

- Do not treat legacy `email_verified = 1` as sufficient proof for account
  linking, self-service password reset, or privilege changes.
- Allow normal password login for imported users if the password hash is valid;
  do not lock everyone out solely because verification is legacy.
- Use an admin-assisted reset or a fresh email verification for recovery.
- Whether legacy verified addresses can receive a reset link immediately is
  `Decision pending`; the safer default is to require fresh verification before
  email-based recovery.

### Duplicate email constraint

If AuthKit enforces globally unique email addresses, duplicate legacy emails
cannot all be imported without a decision. Options:

- Allow separate login handles and nullable/duplicate email with an explicit
  uniqueness scope (`Decision pending`).
- Resolve duplicates manually with user contact and documented evidence.
- Use an admin username that looks like an email as a username, not an email.

Do not satisfy a uniqueness constraint by merging rows. Merging to make an
import pass is an account-takeover risk.

## 8. Password hash import and rehash

### Importing password hashes

- Read password hashes with a least-privilege migration account. Do not export
  them to CSV, logs, chat, or tickets.
- Validate each hash is a well-formed Argon2id PHC string. Preserve the exact
  string and record `scheme = 'argon2id-legacy-gateway'` plus import metadata.
- Reject malformed, empty, or unknown-algorithm hashes. Mark those accounts
  `must_reset`; do not allow login and do not substitute a default password.
- Do not rehash during import. Bulk hashing requires plaintext, which is not
  available and must not be collected.
- Verify a random sample with known test credentials in a staging environment.
  Never create test passwords for production users without a reset flow.

### First login and lazy rehash

- Verify with Argon2id and constant-time comparison. For unknown accounts, use a
  dummy verification to reduce enumeration.
- On successful login, if the stored parameters are below the current target,
  the algorithm is legacy, or the pepper version differs, rehash with the
  current policy and update the credential. If rehash fails, keep the old hash
  and allow login.
- On Workers, run verification where Argon2 fits the CPU/memory budget (native
  origin or supported password service). Do not lower parameters silently.
- Rate-limit first logins after migration and monitor failures; a mass failure
  can indicate a bad hash import or an encoded-string issue.

### Password changes during migration

- Only the authoritative system accepts password changes for a realm.
- If AuthKit is authoritative, the gateway must not accept a legacy password
  change that AuthKit will not see.
- If the gateway remains authoritative for a canary, AuthKit must be read-only
  for that realm.
- After cutover, a changed password in AuthKit is final. Rollback requires reset
  or an explicitly approved hash copy.

### Forced resets

A forced reset for all imported users is a last resort. If used:

- Communicate the reason and the recovery path.
- Rate-limit reset issuance and email sends.
- Do not reveal which accounts had invalid hashes.
- Provide an admin-assisted path for users who cannot receive email.
- Record the policy and exceptions (`Decision pending`).

## 9. API keys

### Pilot recommendation

Keep the gateway as the sole validator for existing data-plane API keys during
the pilot. The keys authenticate the gateway API, not the AuthKit issuer. This
avoids a new runtime dependency on AuthKit for every LLM request and avoids two
validators with divergent revocation.

- Preserve legacy config keys and `managed_keys` unchanged.
- Preserve each key's role, owner, scopes, models, and quota bucket.
- Resolve `owner` to a legacy principal only through the explicit mapping; do
  not resolve by email.
- A gateway key with `role="admin"` remains a gateway API administrator for
  gateway APIs. It is not an AuthKit system administrator and gains no AuthKit
  admin session.
- Do not print raw keys during inventory. Fingerprints are sufficient.
- If an owner is linked to an AuthKit user, the link is informational unless the
  gateway explicitly uses it for authorization.

### Later ownership option

If AuthKit becomes the API-key authority:

- Import only digests (`sha256:<hex>` or a versioned scheme). Raw keys are not
  needed and must not be requested from users.
- Preserve key identity, owner mapping, scopes, and last-used metadata.
- Add expiry and explicit audience if AuthKit will own the lifecycle; the
  current gateway keys have no expiry field. `Decision pending`.
- Change the gateway to validate through AuthKit (introspection or a signed
  token) or to trust an AuthKit-issued machine token. This is a separate
  migration with its own rollback.
- Ensure only one validator accepts a key at a time during the transition.
  Two validators mean a revoke in one system may not stop the other.

### Revocation ownership

Document, per key class, which system can revoke and how quickly the gateway
observes it. “Revoked in AuthKit but still accepted by the gateway” is a
security defect, not a caching detail.

## 10. Sessions are not migrated

This is deliberate and mandatory:

- Do not copy `auth_sessions` rows, token hashes, CSRF tokens, or cookie values.
- Do not translate `gw_admin_session`/`gw_web_session` into AuthKit cookies.
- Do not import `last_seen_at`/`expires_at` as active AuthKit sessions.
- At cutover, revoke or delete old gateway sessions and clear the old cookies.
- Users sign in again through AuthKit. This is the expected cost of changing the
  authentication authority.
- Rollback does not restore old sessions; users sign in with their legacy
  password, which remains in the retained legacy table.
- CSRF tokens are session-bound and are never reused across systems.

Acceptance: presenting an old cookie to the gateway after cutover must not
authenticate; presenting an AuthKit cookie to the gateway must not authenticate
unless the gateway explicitly implements a validated OIDC flow and its own
session.

## 11. Audit continuity

### Importing audit records

- Export gateway audit rows with original `id`, `at`, `actor`, `action`,
  `target`, and `detail`.
- Import into AuthKit audit with:
  - `legacy_source = 'ai-gateway'`
  - `legacy_id =` original gateway id
  - `occurred_at =` original `at`
  - `recorded_at =` import time
  - `actor_type = 'legacy'` or a mapped `service`/`user`, never a fabricated
    human
  - a stable `legacy_actor` value (for example `key:<name>`)
- Preserve the original action names (for example `key.create`) or record a
  mapping. Do not rewrite history to look like an AuthKit-native action.
- Verify `detail` contains no raw secrets. If legacy data is found to contain a
  secret, redact it during import and record the redaction, rather than copying
  it into the new audit store.
- Use a unique constraint on `(legacy_source, legacy_id)` so retries are
  idempotent.
- Do not reuse gateway autoincrement IDs as AuthKit primary IDs; keep them as
  legacy references to avoid collisions.

### Dual-run

- While both paths are active, write audit to the system that owns the action.
  If a central view is required, mirror with a dedupe key and mark the source.
- Do not double-count the same action as two independent events.
- Include a correlation/request ID that links the gateway request to the AuthKit
  login/authorization event.

### Verification

- Source count equals imported count plus documented exceptions.
- Every legacy ID appears exactly once in the mapping/audit tables.
- Timestamps are preserved; ordering by `occurred_at` is sensible.
- Actor mapping is explainable; no gateway key becomes a human administrator.
- Audit export before decommission is stored in an immutable/offsite location.
- The gateway audit table remains read-only and available until acceptance.

### Retention

AuthKit retention applies after import. The imported history may have different
retention requirements from the gateway. Decide whether to keep the legacy
export for the longer of the two periods (`Decision pending`). Do not delete the
only copy of the legacy audit when decommissioning the gateway database.

## 12. Cutover runbook

1. Confirm the rollback owner, maintenance window, and communication channel.
2. Back up the gateway database and export audit; verify restore.
3. Freeze legacy auth changes or confirm the single credential authority.
4. Re-run identity/audit import in idempotent mode; reconcile counts.
5. Validate sample password verification, role mapping, and no system admin.
6. Deploy the gateway with OIDC support but the cutover flag off; smoke-test the
   callback and JWKS in staging.
7. Enable the admin canary; verify login, CSRF, logout, key/user/proxy actions,
   audit, and step-up.
8. Revoke old admin sessions, clear the old admin cookie, and enable all admin
   users.
9. Repeat for web users after admin stability is confirmed.
10. Watch login failures, mapping misses, token errors, audit writes, and legacy
    endpoint hits.
11. Disable legacy login endpoints only after acceptance.
12. Keep legacy tables and code through the rollback window, then decommission
    according to retention.

## 13. Acceptance criteria

- [ ] All `admin_users` rows are mapped to distinct AuthKit users and
      `gateway_admin` memberships, except explicitly documented and approved
      exceptions.
- [ ] All `web_users` rows are mapped to distinct AuthKit users and
      `gateway_user` memberships, except explicitly documented exceptions.
- [ ] No account was merged by email. Duplicate emails are either distinct or
      resolved with documented evidence and user/admin action.
- [ ] Zero legacy users have the AuthKit system-administrator role. System
      administrators were bootstrapped separately with MFA.
- [ ] Gateway administrators can perform their existing admin actions but cannot
      access another organization or AuthKit key material.
- [ ] Every imported password hash is a valid Argon2id PHC string; invalid hashes
      are `must_reset` and cannot log in.
- [ ] Sample imported users log in with their existing passwords in staging, and
      rehash-on-login works when parameters differ.
- [ ] No session, cookie, or CSRF token was migrated. Old cookies fail after
      cutover; new OIDC sessions work.
- [ ] AuthKit cookies are host-only, `Secure`, `HttpOnly`, and correctly
      `SameSite`-scoped; no parent-domain cookie exists.
- [ ] CSRF is enforced on all gateway and AuthKit cookie-authenticated mutations.
- [ ] Admin and web application audiences are separate; an admin token cannot be
      used for the web application or vice versa.
- [ ] Password reset and email verification do not trust the legacy
      `email_verified` flag for linking or privileged recovery.
- [ ] Existing API keys still work under a single documented authority; no key
      was widened, and no key role became a system admin.
- [ ] Audit counts reconcile; legacy IDs/timestamps are preserved; no secrets
      were imported; the legacy audit is exported offsite.
- [ ] Rollback to the legacy path is tested for each realm, including the
      password-change edge case.
- [ ] Monitoring covers login failures, token/mapping errors, legacy endpoint
      hits, audit failures, and admin actions.
- [ ] Legacy auth code, secrets, endpoints, and tables are removed or archived
      only after the rollback window and retention requirements are satisfied.
- [ ] Operators have signed off on every `Decision pending` item that affects
      production.

## 14. Decisions pending and migration risks

| Decision / risk | Impact | Interim rule |
| --- | --- | --- |
| AuthKit email uniqueness scope | Duplicate legacy emails may not fit a global unique constraint | Do not merge; block the row for manual resolution or allow distinct login handles |
| Trusting legacy `email_verified` | Reset/linking takeover risk | Allow password login; require fresh verification for linking/recovery |
| OIDC client type (BFF vs SPA) | Secret handling and CSRF/session design | BFF preferred if the gateway has a server; final decision pending |
| Gateway token validation vs introspection | Revocation latency and runtime dependency | Validate short-lived tokens with JWKS; introspect for sensitive actions if needed |
| API-key ownership | Two validators or broken keys | Gateway remains sole validator during the pilot |
| MFA enrollment for imported admins | Admin lockout vs security | Require enrollment at first AuthKit admin login; provide recovery |
| Password reset availability for imported users | Support load and account recovery | Admin-assisted reset until fresh verification is possible |
| Rollback after password changes | Rollback may not restore current passwords | Freeze changes or accept reset; no bidirectional sync |
| Audit retention after decommission | Loss of investigation history | Keep an immutable export for the longer applicable period |
| Cross-domain logout | User may remain signed in at one of the two hosts | Document behavior; revoke both where practical |
| Whether Workers can host password verification | CPU/memory limits and cost | Use native origin/service; do not weaken Argon2 |
| D1 consistency for gateway authorization | Revocation may lag | Short tokens, primary/DO checks for sensitive actions |

Migration-specific residual risks:

- A duplicate email or recycled address is linked to the wrong person.
- An operator maps a gateway admin to system admin despite the rule.
- A legacy password hash is malformed or uses unknown parameters and the user
  cannot log in.
- A password changes in the non-authoritative system during dual-run and is lost
  on rollback.
- Old sessions are accidentally left valid in the gateway after cutover.
- Audit rows are duplicated or dropped during retries.
- API keys are accepted by both systems with different revocation state.
- The gateway's OIDC callback or redirect validation is misconfigured, creating
  an open redirect or token leak.

Each risk needs an owner and an explicit acceptance or mitigation before
production cutover. The security acceptance criteria above are the minimum; they
do not replace a review of the actual migration run.
