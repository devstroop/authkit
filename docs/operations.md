# AuthKit operations

This document describes how to deploy, back up, migrate, rotate keys, observe,
and recover AuthKit. It assumes the controls in the
[security model](security-model.md) and the adversaries in the
[threat model](threat-model.md). It is an engineering runbook, not a
certification or a legal compliance statement.

Related documents:

- [Security model](security-model.md) — required controls and secure defaults.
- [Threat model](threat-model.md) — adversaries, attack paths, and residual risks.
- [AI Gateway migration](migration-ai-gateway.md) — one optional pilot cutover and rollback plan.

No schedule is implied. Decisions that are not final are marked
`Decision pending`.

## 1. Deployment model

### Common topology

A production deployment has:

- One canonical issuer origin, recommended as `https://auth.<apex>`. Every
  client, token, cookie, and discovery document uses this origin.
- TLS terminated at the edge or reverse proxy. Plaintext HTTP is not served in
  production.
- A private database and secret store.
- A separately protected administrator plane. Prefer a separate host such as
  `admin.auth.<apex>`; a dedicated path is the fallback. The final choice is
  `Decision pending`.
- Host-only cookies. Do not set cookies for `.example.com` or any shared parent
  domain.
- A single migration runner per schema change. Application replicas must not
  race to migrate.
- Immutable application images/binaries with configuration and secrets injected
  at deploy time.

### Native self-host deployment

```text
Internet
  |
  v
TLS edge / reverse proxy  --->  AuthKit (Axum)
                                   |  SQLx
                                   v
                         SQLite file  or  Postgres
                                   ^
                                   |
                         one-shot migration job

Admin access via VPN/allowlist/SSO ---> admin host ---> AuthKit admin plane
```

- **Postgres** is the default for multiple application replicas, high
  availability, and larger tenants. Use a connection pool sized for the
  database, not for the number of CPU cores alone.
- **SQLite** is supported for single-node or low-write deployments. It has one
  writer; do not run multiple application instances against a shared SQLite file
  over a network filesystem. Keep the database on a local, durable volume.
- Run the migration job before starting the new application version. For
  Postgres, use an advisory lock so only one migration runs. For SQLite, stop
  writers and back up before migrating.
- Rate limiting must be shared across replicas. A per-process limiter is useful
  only as a secondary brake. Use a database-backed limiter or edge rate limits;
  the final shared-limiter design is `Decision pending`.
- The admin plane should be reachable only from trusted networks where the
  deployment supports it. This is additional to MFA, not a replacement.

### Workers deployment

```text
Internet
  |
  v
Cloudflare edge (TLS, WAF, rate limits)
  |
  +--> Auth Worker (workers-rs) ---> D1
  |         |                    \--> Durable Object (rate limit / revocation)
  |         |                    \--> Queues / Cron (email, cleanup, export)
  |         |                    \--> Secrets / KMS (signing, peppers)
  |         |
  |         +--> private native origin for password verification (if required)
  |
  +--> Admin Worker (separate host, stricter access)
```

Workers constraints and their operational consequences:

- **No SQLx.** Use the D1 client and test queries against D1 semantics. Do not
  assume Postgres behavior for types, locking, or `RETURNING`.
- **No interactive transactions.** Use `batch()` for atomic statement groups,
  single conditional `UPDATE ... WHERE`, unique constraints, and idempotency
  keys. Do not implement a logical transaction across requests.
- **Read replication.** Authorization-critical reads must use the primary or a
  bookmark that guarantees the required consistency. See
  [D1 consistency and revocation](threat-model.md#d1-consistency-and-revocation).
- **CPU and memory limits.** Argon2 verification may be too expensive for the
  Worker budget. Prefer a private native origin or a platform-supported password
  service. Whether password endpoints run directly on Workers is
  `Decision pending`.
- **Secrets.** Use Worker secret bindings or the platform secret store for
  signing keys, peppers, and provider credentials. D1 and KV are not approved
  for private keys.
- **Email and jobs.** Use a provider API or Email Workers, Queues, and Cron
  Triggers. Do not block a login request on email delivery.
- **Rate limiting.** Use edge rate limits or a Durable Object keyed by
  account/IP/client. Per-isolate memory does not provide a global limit.
- **Static UI.** Askama/HTMX templates are bundled at build time. Authenticated
  pages must be `no-store`; do not let the edge cache a response containing a
  CSRF token, session-specific data, or personal information.
- **Backups.** D1 export/time-travel is not a file copy. Run periodic encrypted
  exports to object storage and test restore. The available time-travel window
  is platform-dependent; verify it for the deployment.

If a security property cannot be met on Workers, disable the feature there or
serve it from the native deployment. Feature parity must not come at the cost of
weaker hashing, revocation, or rate limiting.

### Deployment invariants

- One issuer origin per environment; do not mix production and staging data.
- Production cookies are `Secure` and host-only. Local HTTP overrides are
  explicit and fail closed in production.
- The admin plane is not served from the same cookie scope as ordinary user
  sessions. Prefer a separate host.
- The database and secret store are not publicly reachable.
- Migrations run before traffic; the application refuses to start on an
  unsupported schema version.
- No startup with missing signing keys, malformed configuration, or default
  credentials.
- Health checks do not expose secrets, versions with known vulnerabilities, or
  tenant data.

## 2. Configuration and secrets

Configuration names below are the implemented native names where available; secret and
provider settings that are not implemented yet remain working names. Treat this as a
checklist of values the deployment must define, not a frozen schema.

| Setting | Purpose | Default / requirement |
| --- | --- | --- |
| `AUTHKIT_ISSUER` | Canonical public origin | `https://auth.<apex>`; must match discovery and tokens; HTTPS required in production |
| `AUTHKIT_BIND_ADDR` | Native bind address | Loopback or private interface behind proxy |
| `AUTHKIT_DATABASE_URL` / D1 binding | Data store | Private; least-privilege credentials |
| `AUTHKIT_DATABASE_MAX_CONNECTIONS` | Native connection pool limit | Positive integer; size for the database, not CPU count alone |
| `AUTHKIT_SIGNING_KEY_FILE` | Encrypted native keyring | Absolute path in production; `0600`; separate encrypted backup |
| `AUTHKIT_SIGNING_KEY_KEK` | Keyring key-encryption key | 32-byte base64url secret from a secret manager; never inline in config files |
| `AUTHKIT_SIGNING_KEY_RETIRED_PUBLISH_SECS` | Retired public-key overlap | `1`-`86400`; default `900` |
| `AUTHKIT_SESSION_PEPPER` | Session digest protection | Secret manager; key-ring version |
| `AUTHKIT_EMAIL_TOKEN_PEPPER` | Reset/verification digest protection | Secret manager; versioned |
| `AUTHKIT_ENCRYPTION_KEK` | Envelope encryption of stored secrets | KMS/secret manager |
| `AUTHKIT_TRUSTED_PROXIES` | Which peers may set forwarded IP headers | Explicit CIDRs; empty by default |
| `AUTHKIT_COOKIE_SECURE` | Force `Secure` cookies | True in production; explicit dev override only |
| `AUTHKIT_ADMIN_BOOTSTRAP_TOKEN` | First system admin | One-time, consumed; empty after bootstrap |
| `AUTHKIT_SMTP_URL` / email provider | Verification/reset delivery | Secret manager; TLS required |
| `AUTHKIT_RATE_LIMIT_BACKEND` | Shared limiter | Edge, database, or Durable Object; never per-process only |
| `AUTHKIT_REGISTRATION_MODE` | Open/invite/closed | Closed by default |
| `AUTHKIT_DEFAULT_ORG_POLICY` | Membership and MFA defaults | Least privilege |
| `AUTHKIT_AUDIT_EXPORT_TARGET` | Offsite audit copy | Encrypted object storage/SIEM |
| `AUTHKIT_MIGRATION_MODE` | Legacy/dual-run/cutover flags | Off by default; explicit enablement |
| `AUTHKIT_LOG_FORMAT` / `RUST_LOG` | Structured logging and filter | JSON in production, redacted; no secrets |
| Worker bindings | D1, KV (public config only), queues, secrets | Least privilege per environment |

Rules:

- Keep secrets out of the repository, container image, build logs, Terraform
  state, and shell history.
- Inject native secrets from a secret manager or a root-readable file with
  restrictive permissions. Prefer short-lived credentials where the platform
  supports them.
- On Workers, use secret bindings. Do not store private keys or long-lived
  credentials in D1 or KV. KV is acceptable only for public, non-secret
  configuration.
- Separate secrets and keys per environment. Never copy production keys to
  staging or CI.
- Validate configuration at startup: issuer is HTTPS (except explicit local
  development), the signing keyring decrypts with exactly one active ES256 key,
  cookie settings are safe, database is reachable, schema version is supported.
  Fail closed.
- Redact configuration dumps. Never print a secret to a log, even at debug
  level. Do not include request headers or token bodies in error reports.
- If a secret may have leaked, rotate it first and investigate second. See
  [Key and secret rotation](#6-key-and-secret-rotation).

## 3. Provisioning and first boot

A safe first boot follows this order:

1. Create DNS and TLS for the issuer host. Decide whether the admin plane is a
   separate host. Confirm host-only cookie behavior.
2. Provision the database and a least-privilege application role. Enable
   encryption at rest and automated backups.
3. Create the secret store entries: signing keyring KEK, session pepper,
   email-token pepper, email provider credentials, and the one-time admin
   bootstrap token. On first start the server creates the encrypted signing
   keyring with one active ES256 key; back it up with the KEK.
4. Run the schema migration as a one-shot job. Verify the schema version and
   backup before and after.
5. Start AuthKit with traffic disabled or the edge returning a maintenance
   response. Check readiness, JWKS, discovery, and a synthetic login page.
6. Bootstrap the first system administrator using the one-time token. Do not
   create a default account. Sign in and enroll MFA immediately.
7. Create the organization/workspace, applications, OAuth clients, roles,
   permissions, and exact redirect URIs. Do not enable wildcard redirects.
8. Configure email sending and verify delivery to a controlled mailbox.
9. Confirm registration is closed or invite-only unless the product explicitly
   needs open registration.
10. Enable edge rate limits, WAF rules, and trusted-proxy configuration.
11. Run smoke tests: discovery, authorization request, login, MFA, token
    issuance, refresh, logout, session revocation, password reset, CSRF
    rejection, and cross-tenant denial.
12. Take a verified backup and enable monitoring/alerts before opening traffic.
13. Enable traffic gradually. Watch authentication failures, latency, database
    health, and audit writes.

The bootstrap secret must be single-use. If it is lost before use, reissue it
through a controlled recovery procedure; do not fall back to a default password.

## 4. Backups and restore

### What to back up

| Item | Why | Notes |
| --- | --- | --- |
| Database | Users, memberships, clients, sessions, audit | Encrypted; consistent snapshot |
| Signing private key | Token issuance after restore | Separate encrypted backup; KMS export may be restricted |
| Session pepper / HMAC key | Validate existing session digests | Losing it invalidates sessions; plan for that |
| Email-token pepper | Validate outstanding reset/verification links | Losing it invalidates links |
| Encryption KEK | Decrypt stored secrets/data keys | Store in KMS/offline escrow, not with the database |
| OAuth client secrets | Only digests are stored; raw values are not recoverable | Reissue/rotate if lost; do not expect backup recovery |
| Non-secret configuration | Reproducible deploy | Version-controlled template; no secrets |
| Audit exports | Investigation and retention | Immutable/offsite copy where possible |
| Migration mapping | Legacy-to-AuthKit identity mapping | Highly sensitive; encrypt and restrict |

### Native backups

SQLite:

- Use the SQLite backup API, `VACUUM INTO`, or a filesystem snapshot that
  includes a consistent WAL state. Do not copy a live database file while
  writers are active unless the snapshot mechanism guarantees consistency.
- Run `PRAGMA integrity_check` on the backup, not only on the live database.
- Restrict file permissions and encrypt the backup at rest.
- Keep the database and its keys in separate backup domains so one compromised
  storage account does not expose both.

Postgres:

- Use `pg_dump` in a custom/directory format for logical backups and continuous
  WAL archiving for point-in-time recovery.
- Verify that the backup includes roles, extensions, and schema version
  metadata.
- Restore into an isolated environment before relying on the backup.
- Ensure the backup user has only the permissions needed to read the database.

### Workers/D1 backups

- Use D1 export/time-travel features where available, and schedule periodic
  encrypted exports to object storage. Platform time-travel windows are finite
  and can change; verify the current window and do not treat it as long-term
  retention.
- Export schema and data together, including migration/version metadata.
- Store exports with object-lock/immutability where available. If not
  available, use a separate account with restricted delete permissions and an
  audit trail.
- Test restore into a separate D1 database and run a schema/version check plus
  representative queries.

### Restore runbook

1. Declare the restore and freeze writes or route traffic to a maintenance page.
2. Preserve the current database, logs, audit, and configuration for
   investigation. Do not overwrite evidence.
3. Restore the database into a new instance where possible, then verify schema
   version, row counts, audit continuity, and key references.
4. Restore or unlock the required keys. Confirm the signing `kid`, key
   algorithm, session pepper version, and email-token pepper version.
5. Run pending migrations only if the restored schema is older and the migration
   is known safe. Never run an unknown migration on a restored production
   database without a backup.
6. Treat restored sessions and tokens as suspect. Rotate the session pepper or
   delete all sessions, and rotate the signing key if the restore crosses a
   compromise boundary. This forces reauthentication.
7. Verify admin access, MFA, organization membership, client configuration, and
   audit export.
8. Start a canary instance, run smoke tests, and then restore traffic gradually.
9. Record what was restored, the data-loss window, the key actions taken, and
   follow-up work. Do not claim a recovery point until verification passes.

Recovery point objective (RPO), recovery time objective (RTO), backup frequency,
and retention are `Decision pending` per deployment. The operator must choose
them based on acceptable data loss and outage cost.

## 5. Schema migrations

Migration rules:

- Migrations are forward-only and immutable once applied. Do not edit an applied
  migration; add a new one.
- Version the schema and have the application refuse to start if the database is
  newer than the binary understands. A newer binary may migrate an older
  database; an older binary must not serve a newer schema.
- Run migrations as a one-shot job before starting application replicas. On
  Postgres, take an advisory lock. On SQLite, stop writers and back up first.
- Use expand/contract for compatibility: add nullable columns/tables, backfill,
  switch reads/writes, then remove old structures in a later release. Avoid
  destructive changes in the same release as the code change.
- Keep the previous application version compatible with the migrated schema for
  the rollback window. The exact compatibility window is `Decision pending`.
- Test migrations on a production-like copy, including row counts, lock time,
  index build time, and application smoke tests.
- On D1, use batched, idempotent statements. There is no interactive
  transaction, so a multi-step migration must tolerate retry and partial
  progress. Record applied migration ids in a table with a unique constraint.
- Do not run long backfills in a request handler. Use a bounded job with
  checkpoints and idempotency.
- Back up before every production migration. A down migration is not a rollback
  strategy; prefer restore or a forward fix.

Preflight checklist:

- Verified backup and restore path.
- Schema version and expected migration plan reviewed.
- Disk space, connection limits, and lock time estimated.
- D1 export/bookmark taken; Workers deployment pinned.
- Application replicas drained or canary-only.
- Rollback decision made before starting.
- Audit note created for the migration window.

If a migration fails: stop, preserve logs and the partial state, do not start the
new application against a partially migrated schema, and choose between restore
and a reviewed forward fix. Record the outcome in the audit/operations log.

## 6. Key and secret rotation

### Rotation inventory

| Secret | Scheduled rotation | Emergency trigger | Notes |
| --- | --- | --- | --- |
| OIDC signing key | Per security policy | Suspected key exposure, issuer compromise | Overlap new public key before switching signing |
| Session pepper | Per security policy | Database/backup exposure, mass session theft | Key ring; old sessions may need revocation |
| Email-token pepper | Per security policy | Token database exposure | Outstanding links may be invalidated |
| Encryption KEK | Per security policy | KMS compromise | Rewrap data keys; no plaintext export |
| OAuth client secrets | Per client policy | Client compromise, staff departure | Overlap old/new at the client |
| API keys | Per key policy | Key leakage, owner departure | Create new, deploy, revoke old |
| Email/provider credentials | Per provider policy | Provider compromise, leakage | Update provider first, then AuthKit |
| Admin bootstrap token | One-time | Loss or suspected exposure | Reissue through controlled recovery |
| Database credentials | Per platform policy | Leak, role change | Rotate with connection-pool drain |
| Worker secret bindings | Per platform policy | Leak, deploy compromise | Deploy new secret version; verify old is rejected |

Exact rotation intervals are `Decision pending` and should be risk-based.

### Signing-key rotation

The native keyring supports `next`, `active`, `retired`, and `compromised`
entries. Automated generation and switching is tracked in #35; until then, a
rotation is a reviewed keyring update with the server stopped.

1. Generate a new key in the KMS/keystore with a new `kid`. Do not overwrite the
   old key.
2. Publish the new public key in JWKS while the old key is still published.
3. Wait for the JWKS cache of relying parties to refresh. The overlap must
   exceed the maximum token lifetime plus the longest reasonable JWKS cache.
4. Switch the issuer to sign with the new key. Keep the old public key for
   verification until all tokens signed with it have expired.
5. Monitor signature-validation failures and JWKS fetches. If clients fail,
   restore the old signing key only if it is still trusted and the incident
   allows it.
6. Remove the old public key after the overlap. Remove the old private key from
   the active keystore and retain it only in an encrypted archive if policy
   requires.
7. Audit the rotation and record key ids and timestamps (not key material).

Emergency rotation (suspected signing-key compromise):

1. Immediately stop using the compromised key and publish a new key.
2. Remove the compromised public key from JWKS after a short, explicit
   transition, or immediately if clients can refresh. Do not keep accepting
   forged tokens to preserve availability.
3. Revoke sessions and refresh tokens if the attacker could also obtain session
   material. Force reauthentication.
4. Notify relying parties through the incident process and ask them to refresh
   JWKS and clear cached tokens.
5. Preserve logs, audit, and key-access records. Determine the exposure window
   and what tokens may have been forged.
6. Rotate adjacent secrets: session pepper, client secrets, API keys, and
   deployment credentials if the host or CI may be compromised.

### Session and email-token pepper rotation

- Use a versioned key ring: new records use the new version; old records remain
  verifiable until they expire or are revoked.
- For sessions, the overlap must be at least the maximum session lifetime. If
  that is unacceptable, rotate and revoke all sessions at once. The choice is
  `Decision pending`; immediate revocation is required after a suspected
  database compromise.
- For email/reset tokens, prefer invalidating all outstanding tokens on
  emergency rotation. For scheduled rotation, dual-read old and new versions
  until the maximum token lifetime elapses.
- Remove old versions from the active key ring after the overlap and archive
  them only if required.

### Client secrets and API keys

- Create the new secret/key, distribute it through a secure channel, deploy the
  consumer, verify successful authentication, then revoke the old credential.
- Monitor `last_used_at`/authentication failures during the overlap. Do not
  leave both credentials valid indefinitely.
- For OAuth clients, support at least two active secrets during rotation.
- For API keys, preserve the owner and scope mapping; do not silently widen
  permissions during rotation.

### Worker secret updates

- Update the secret binding and deploy/restart the Worker. Verify the new
  version is active and the old value is rejected before removing the old
  version from the platform.
- Keep a rollback plan: if the new key is wrong, restore the previous binding
  only if it has not been compromised. Never roll back to a known-compromised
  secret.
- Test JWKS, token issuance, session validation, and email sending after the
  update.

## 7. Observability

### Metrics

Collect at least:

| Area | Metrics |
| --- | --- |
| HTTP | Request rate, latency, 4xx/5xx by route class; avoid user IDs as labels |
| Authentication | Login attempts, successes, failures by generic reason, MFA challenges, lockouts/429s |
| Sessions | Active sessions, validations, revocations, cleanup lag |
| Tokens | Issued, refreshed, revoked, refresh-reuse detections, JWKS requests/cache hit rate |
| Accounts | Password resets requested/completed, verification sends, email bounces/complaints |
| Tenancy | Authorization denials by route class, cross-tenant attempts, membership changes |
| Admin | Admin logins, MFA failures, step-ups, sensitive mutations, audit exports |
| Database | Connection pool, query latency, errors, deadlocks/retries, replica/bookmark lag |
| D1/Workers | Rows read/written, query duration, CPU time, subrequests, queue backlog, DO latency |
| Audit | Append failures, export lag, retention job failures |
| Keys | Signing-key age, JWKS errors, key-load failures, rotation status |
| Platform | Certificate expiry, disk usage, backup success, restore-test success |

Do not put emails, usernames, tokens, or raw IP addresses in metric labels.
Use aggregated route/action classes.

### Logs

- Structured JSON with timestamp, severity, service, environment, request ID,
  route class, status, latency, actor type, and tenant identifier where
  appropriate.
- Never log passwords, cookies, `Authorization` headers, token request/response
  bodies, client secrets, API keys, password-reset tokens, or full email
  contents.
- Sanitize user-controlled values to prevent log injection. Keep logs
  access-controlled and retained according to policy.
- Correlate logs, traces, and audit by request ID, not by embedding secrets.

### Traces

Sample traces for login, token, session validation, admin mutation, and email
jobs. Propagate a request ID. Do not attach credentials or token bodies to spans.
Trace sampling must not hide rare security events; alert from metrics/audit, not
only from sampled traces.

### Alerts

Alert on:

- Sustained increase in failed logins, 429s, MFA failures, or password-reset
  requests.
- Spike in 5xx errors, database connection failures, query timeouts, or D1
  errors.
- Audit append failure or export lag.
- JWKS/signature-validation errors or missing signing key.
- Email delivery failure, bounce/complaint spike, or queue backlog.
- D1 replication/bookmark lag beyond the documented bound.
- Worker CPU/time-limit errors or cost budget threshold.
- Certificate expiry approaching, backup failure, or failed restore test.
- Sensitive admin actions outside expected patterns (new system admin, MFA
  reset, signing-key rotation, bulk export).

Thresholds and on-call ownership are `Decision pending`. Every alert should link
to a runbook, not just a dashboard.

Service-level objectives for availability, login latency, and token issuance are
`Decision pending`. Measure before committing to a target.

## 8. Audit export and retention

### Export interface

- Provide an authenticated admin/CLI export with filters by time range, actor,
  organization, action, and target. Require MFA and step-up for bulk export.
- Use a stable cursor/id ordering. Bound page size and total export size; large
  exports run as a job.
- Emit JSONL (one event per line) with a schema version and an explicit
  `exported_at`. CSV may be offered for humans but is not the canonical format.
- Include a per-page or per-file checksum and a manifest with row counts and
  cursor bounds. Do not include secrets in any field.
- Record an audit event for the export itself: actor, query, count, destination,
  and result.
- Support push to a SIEM/object store through a restricted service account.
  Encrypt in transit and at rest; apply retention/immutability at the
  destination.

### Retention

- Live audit retention is an operator policy. Suggested starting range: 180 days
  to one year, longer if required by the operator's obligations. Exact periods
  are `Decision pending`.
- Export before deleting old records. Retention deletion must be a separate,
  restricted maintenance operation, not something the application can do on
  behalf of an admin.
- Backups and SIEM copies have their own retention. Document that deletion from
  the live database does not instantly delete every copy.
- Preserve audit records needed for an open incident or investigation. Legal
  holds are an operator decision (`Decision pending`).

### Integrity

- Restrict update/delete privileges on the audit table. The application appends;
  a maintenance role trims.
- Keep an offsite copy in a separate account/domain with restricted delete
  access. Object lock or versioning is recommended where available.
- A hash chain or signed checkpoint is `Decision pending`. If implemented, it
  must be verified during export and must not block normal appends.

## 9. Health checks and readiness

| Endpoint | Purpose | Behavior |
| --- | --- | --- |
| `/healthz` (liveness) | Process is running | `200` if the process can serve; no database dependency; no secrets |
| `/readyz` (readiness) | Safe to receive auth traffic | Checks database connectivity; `503` if not ready. The signing keyring is decrypted before the listener binds. Schema-version and required-binding checks land with those features. |
| Admin diagnostics | Deeper operator view | Admin-only, redacted, rate-limited; never returns key material or tokens |

Rules:

- Keep health responses small and non-sensitive. Do not expose build secrets,
  database URLs, tenant counts, or stack traces.
- Use a short timeout for database checks. A slow database should fail readiness
  rather than hang the probe.
- Do not perform expensive migrations, email sends, or full-table counts in a
  health check.
- Cache `no-store`. Health endpoints must not be cached by a CDN.
- On Workers, readiness should verify the binding is present and a lightweight
  D1 query succeeds; do not run a heavy query on every probe.
- Startup should fail closed if keys/configuration/schema are invalid. Readiness
  is for traffic gating, not for silently running in a degraded security mode.
- Graceful shutdown stops accepting new requests, drains in-flight requests,
  flushes audit/queue writes, and closes database connections.

## 10. Capacity and limits

### Work profile

The expensive paths are:

- Password verification (CPU and memory bound; Argon2id).
- Login/session creation and rotation (database writes).
- Authorization-code exchange and refresh-token rotation (database writes).
- Session validation (database read or strongly consistent lookup).
- Tenant-scoped list/export queries (database read and serialization).
- Email sends and audit exports (external I/O; should be queued).

Token signing is comparatively cheap but still bounded by key-service latency.
Audit writes add a row per privileged mutation; plan database write capacity for
them.

### Native deployment

- **Postgres:** size the connection pool below the database's max connections,
  account for migration jobs and admin tools, and monitor pool wait time.
  Long-running exports should use a read path that does not starve logins.
- **SQLite:** one writer at a time. Keep write transactions short; throttle
  session `last_seen` updates; run cleanup in batches; avoid multiple app
  instances sharing the file. Plan for database size and WAL growth.
- **Argon2:** measure verification time on the actual CPU. Concurrency above the
  CPU budget increases latency and can cause timeouts. Rate limits protect the
  password path; a queue does not make CPU cheaper.
- **Disk:** monitor database, WAL, backups, and log volumes separately.

### Workers/D1

- D1 has row-read/write and query limits, and Workers have CPU, memory,
  subrequest, and request-duration limits. These are platform-defined and can
  change; verify the current limits rather than hard-coding assumptions.
- Batch writes where semantics allow; avoid unbounded `IN` lists and full-table
  scans.
- Use Durable Objects for strongly consistent rate limits/revocation where
  needed. Plan for DO location and hot-key contention.
- Queue email, exports, cleanup, and webhooks. Monitor backlog and dead-letter
  behavior.
- Watch cost: a login flood that reaches Argon2 can consume both CPU budget and
  money. Edge rate limits and origin-side hashing are capacity controls as much
  as security controls.

### Sizing and testing

Before a production pilot, load-test:

- A login burst with correct and incorrect passwords.
- Token refresh and session validation at expected peak.
- Admin list/export queries with realistic tenant sizes.
- Email send bursts and provider failure/retry.
- Database failover/replica lag behavior.
- Worker CPU/time-limit behavior under a login flood.

Capacity headroom targets are `Decision pending`. Do not size only from average
traffic; authentication endpoints are bursty and adversarial.

## 11. Self-host vs Workers differences

| Concern | Native self-host | Workers + D1 |
| --- | --- | --- |
| Runtime | Axum, long-lived process | workers-rs, per-request isolates |
| Database | SQLx + SQLite/Postgres | D1 client; no SQLx |
| Transactions | Full interactive transactions | No interactive transactions; batch/conditional writes |
| Consistency | Primary database semantics | Read replication; bookmarks/primary/DO needed for revocation |
| Migrations | One-shot job, advisory lock/lock file | Batched idempotent migrations, no interactive tx |
| Password hashing | Argon2id on owned CPU | CPU/memory constrained; native origin preferred |
| Sessions | Database lookup; shared across replicas | D1 plus DO/primary for immediate revocation |
| Rate limiting | Shared database/edge limiter | Edge/DO; per-isolate memory insufficient |
| Email/jobs | SMTP/provider + worker process | Provider API/Email Workers + Queues/Cron |
| Key storage | KMS/secret manager/file | Secret bindings/secret store; never D1/KV |
| Static UI | Askama/HTMX from disk | Bundled templates; no filesystem; edge cache rules |
| Backups | SQLite backup/Postgres PITR | D1 export/time travel + object storage |
| Observability | Standard logs/metrics/traces | Workers logs/metrics/traces; platform limits |
| Scaling | Vertical + replicas; SQLite single writer | Global edge; D1/DO capacity and hot keys |
| Admin plane | Separate host/VPN possible | Separate Worker/access policy strongly preferred |
| Failure modes | DB down, disk full, CPU saturation | D1 errors/lag, CPU limits, binding/secret misconfig |
| Operational owner | Operator manages runtime/DB | Shared responsibility with platform provider |

A deployment may intentionally differ in feature set. Document which features
are unavailable on each runtime and ensure the difference cannot be used to
bypass a security control.

## 12. Incident response basics

### Severity and roles

Use a simple severity scale (for example SEV-1 critical, SEV-2 high, SEV-3
moderate, SEV-4 low). Define roles before an incident:

- Incident commander: coordinates and decides.
- Security lead: investigates compromise and containment.
- Operations lead: applies changes and restores service.
- Communications lead: internal/external updates.
- Scribe: timeline, evidence, and decisions.

Notification obligations, regulatory reporting, and customer communication are
operator/legal decisions (`Decision pending`). Do not promise a notification
timeline in this document.

### Phases

1. **Detect and triage.** Confirm the signal, scope, affected tenants, and
   whether credentials/keys are involved.
2. **Contain.** Revoke sessions, disable accounts/clients, block sources, take
   the admin plane offline, or fail closed. Prefer containment that does not
   destroy evidence.
3. **Preserve evidence.** Snapshot logs, audit, database, key-access records, and
   relevant configuration. Record who did what.
4. **Eradicate.** Remove the cause: patch, rotate credentials, remove malicious
   clients, fix a misconfiguration.
5. **Recover.** Restore service carefully, verify data integrity, and monitor
   for recurrence.
6. **Review.** Write a blameless post-incident review with timeline, impact,
   root cause, detection gaps, and follow-up actions. Update the threat model
   and tests.

### Runbooks

#### Suspected signing-key compromise

- Stop using the key; publish a new key and update JWKS.
- Remove the old key after the explicit transition or immediately if clients can
  refresh. Accept the availability impact rather than continue trusting forged
  tokens.
- Revoke sessions/refresh tokens if session material may also be exposed.
- Notify relying parties, preserve key-access logs, determine the forgery
  window, and rotate adjacent secrets.

#### Administrator account takeover

- Disable the admin, revoke all sessions, reset password and MFA through a
  controlled recovery, and review audit for actions taken.
- Check for new system admins, OAuth clients, redirect URIs, API keys, and
  signing-key changes.
- If the admin plane or host is suspect, take it offline and rebuild from a
  trusted image.
- Notify affected tenants if their data or membership was changed.

#### Database or backup exposure

- Rotate database credentials and network access first.
- Rotate session pepper and invalidate sessions; rotate email-token pepper;
  rotate OAuth client secrets and API keys that were stored as digests only if
  the exposure allows offline attack or the raw values were present.
- Rotate signing keys if they were stored in or reachable from the same
  environment.
- Assess data scope, preserve evidence, and follow the operator's notification
  decision process.

#### Mass session theft or XSS

- Revoke all sessions or rotate the session pepper; force reauthentication.
- Identify and remove the source (dependency, script, CSP gap, malicious client).
- Review admin sessions separately and require step-up.
- Notify users and monitor for follow-on account changes.

#### Email provider or mailbox compromise

- Rotate provider credentials and invalidate outstanding reset/verification
  tokens.
- Require password/MFA review for privileged accounts; notify affected users.
- Monitor for reset and MFA-change spikes. Treat email-based recovery as
  untrusted until the provider is clean.

#### D1 outage, stale reads, or revocation failure

- Fail closed for admin and sensitive operations; route authorization reads to
  the primary or a consistent DO where available.
- Shorten access-token lifetimes or disable refresh if revocation cannot be
  enforced.
- Communicate degraded logout/revocation behavior explicitly; do not claim
  immediate revocation when it is not true.
- After recovery, force reauthentication if the stale window is unacceptable.

#### Bad migration or schema mismatch

- Stop the rollout, preserve the database and logs, and prevent old/new binaries
  from mixing against an incompatible schema.
- Restore the verified backup or apply a reviewed forward fix. Do not improvise
  destructive SQL in production.
- Verify counts, audit continuity, and login/token flows before reopening.

#### DDoS or CPU exhaustion

- Enable/raise edge protections and rate limits; shed load with `429`/`503`.
- Move password verification to the origin or reduce concurrency; protect the
  admin path separately.
- Scale within platform limits, queue non-essential work, and monitor cost.
- Do not disable MFA, CSRF, or token validation to recover availability.

## 13. Routine operations

Perform these as part of normal operation, without implying calendar dates:

- Review administrator accounts, MFA enrollment, recovery codes, and inactive
  accounts.
- Review OAuth clients, redirect URIs, scopes, client secrets, and API keys;
  remove unused credentials.
- Review audit for sensitive actions and denied cross-tenant attempts.
- Verify backups and perform restore drills on a separate environment.
- Test key rotation in staging, including JWKS overlap and client behavior.
- Update dependencies with security review; pin and rebuild images.
- Check certificate expiry, DNS, HSTS, cookie attributes, and CORS/redirect
  configuration for drift.
- Review rate-limit effectiveness and capacity headroom after traffic changes.
- Review Worker CPU/cost, D1 usage, queue backlog, and platform limit changes.
- Review incident runbooks and contact information.
- Revisit `Decision pending` items and record the chosen policy.

### Upgrade procedure

1. Read the release notes and schema/migration changes.
2. Back up and verify restore for the current version.
3. Test the upgrade in staging with production-like data and a full auth smoke
   test.
4. Run the migration job, then deploy the new version to a canary.
5. Monitor errors, latency, auth failures, JWKS, and audit writes.
6. Roll out gradually. If rollback is needed, prefer restoring the pre-upgrade
   backup or a reviewed forward fix; do not run an untested down migration.
7. Record the version, migration ids, and any incidents.

## 14. Operational acceptance checklist

Before a production pilot:

- [ ] Canonical issuer is HTTPS at the intended host; discovery and JWKS work.
- [ ] Production cookies are `Secure`, `HttpOnly`, host-only, and correctly
      scoped; no parent-domain cookie exists.
- [ ] Admin plane is separated and protected by MFA; no default admin exists.
- [ ] First system administrator was bootstrapped with a one-time secret and MFA.
- [ ] Signing keys, session pepper, email-token pepper, and provider credentials
      are in a secret store, not in the database or repository.
- [ ] Database is private, least-privilege, encrypted at rest, and backed up.
- [ ] A restore has been tested and the data-loss window is documented.
- [ ] Migrations run as a one-shot job and refuse an unsupported schema.
- [ ] Login, MFA, token issuance, refresh, logout, revocation, reset, and CSRF
      rejection pass smoke tests.
- [ ] Cross-tenant access is denied and audited.
- [ ] Rate limits are active at the edge and in the application; trusted proxies
      are configured.
- [ ] Audit is enabled, append-only for the app, and exported offsite.
- [ ] Alerts cover auth failures, 5xx, database/D1 errors, audit failures,
      signing keys, email, backups, and Worker CPU.
- [ ] Health/readiness endpoints are safe and do not leak secrets.
- [ ] Workers-specific limits are tested, or the affected feature is served from
      the native origin.
- [ ] Rollback and emergency key rotation are documented and rehearsed.
- [ ] `Decision pending` items have owners and interim defaults.

## 15. Decisions pending

| Decision | Operational impact | Interim default |
| --- | --- | --- |
| Admin host vs path | Cookie isolation, access policy, DNS/TLS | Separate host preferred; path fallback |
| Session and token lifetimes | Security window vs user experience | Security-model baseline values |
| Shared rate-limit backend | Multi-replica correctness, cost | Edge plus database/DO limiter |
| Worker password hashing path | CPU, cost, latency, feature parity | Native origin preferred |
| D1 revocation consistency mechanism | Immediate logout guarantee | Primary/bookmark reads; DO pending |
| Backup frequency, RPO, RTO, retention | Data-loss and recovery cost | Operator decision before pilot |
| Audit retention and tamper evidence | Investigation, storage cost | Append-only + offsite export |
| Key rotation intervals | Exposure window vs operational load | Risk-based policy |
| Notification/legal obligations | Incident communications | Operator/legal decision |
| Admin support-access approval | Insider risk vs support speed | Audited, time-bound access; dual control pending |
