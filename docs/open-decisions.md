# Open decisions

This register lists choices that are not final yet. It is a planning tool, not a source of
policy: once a decision is accepted, it becomes an ADR in [`docs/adr/`](adr/) and the
affected document is updated. A decision must be resolved before the milestone that
depends on it closes.

The "v1 default" column is the proposal used by the current documentation. It is safe to
implement against unless an ADR supersedes it. Items marked **RFC** need public discussion
because they change a public contract or are expensive to reverse.

## Product and governance

| ID | Decision | Options | v1 default | Needed by |
| --- | --- | --- | --- | --- |
| P1 | Project name and trademark | Keep AuthKit; rename | Keep as working name; no public launch until review | M0 |
| P2 | License | Apache-2.0; MIT; dual; other | **RFC.** Dual Apache-2.0/MIT is the common Rust default | M0 |
| P3 | MFA in v1 | Passkeys, TOTP, both, later | **RFC.** Ship passkeys first if either is in v1 | M4 |
| P4 | Upstream OIDC federation | In v1; after v1; never | After v1. It is identity brokering, not core | M4 |
| P5 | Consent policy | Always ask; auto-consent first-party | Auto-consent only for system-marked first-party clients, audited | M2 |
| P6 | System-admin authentication | Password + TOTP; passkey; step-up | Separate admin session, MFA mandatory | M4 |
| P7 | BFF distribution | Docs/sample only; maintained library | Docs plus a thin reference sample | M7 |
| P8 | Admin automation API | HTML forms + CLI; versioned JSON API; both | HTML forms + CLI in v1; evaluate a JSON API after v1 | M3 |

## Protocol

| ID | Decision | Options | v1 default | Needed by |
| --- | --- | --- | --- | --- |
| O1 | PKCE for confidential clients | Required; optional | **RFC.** Required for every client | M2 |
| O2 | `nonce` requirement | Required for all; recommended | Required for OIDC code requests | M2 |
| O3 | Tenant claim | `org_id`; namespaced; none | Namespaced `https://authkit.dev/org` (final name pending) | M2 |
| O4 | Refresh and ID-token semantics | Rotate ID token; not | Issue a new ID token on refresh only if requested by scope | M2 |
| O5 | Introspection | v1; later; never | Later. JWT + JWKS is the hot path | M2 |
| O6 | `form_post` response mode | Support; reject | Reject in v1; revisit on demand | M2 |
| O7 | OpenID certification | v1 requirement; later | Basic-profile test suite in v1; certification before 1.0 | M4 |
| O8 | Access-token format on Workers | JWT; opaque + introspection | JWT, with a documented revocation window | M6 |

## Domain and storage

| ID | Decision | Options | v1 default | Needed by |
| --- | --- | --- | --- | --- |
| D1 | ID format | UUIDv7; ULID; prefixed random | Prefixed UUIDv7 text (`usr_`, `org_`, ...) | M1 |
| D2 | System administrators | Dedicated table; system-scope binding | Dedicated `system_administrator` table with audited grants | M1 |
| D3 | Invitations | Standalone aggregate; membership state | Standalone invitation table | M1 |
| D4 | Application roles | Per application; org-owned with app scope | Org-owned definitions with optional application scope | M1 |
| D5 | Email change effect | Revoke sessions; keep | Revoke other sessions and notify the old address | M1 |
| D6 | Loopback redirects | Exact; RFC 8252 port wildcard | Exact host/path, any port for loopback only | M2 |
| D7 | Client-secret overlap | One active; current + previous | One previous secret with an explicit expiry | M2 |
| D8 | Organization deletion | Operator-only; self-service | Operator-driven, staged, audited | M4 |
| D9 | Retention defaults | Fixed; per deployment | 30d sessions, 90d audit, 1y refresh family cap | M4 |
| D10 | Audit tamper evidence | Hash chain; append-only + export | Append-only with signed exports in v1 | M4 |

## Runtime and operations

| ID | Decision | Options | v1 default | Needed by |
| --- | --- | --- | --- | --- |
| R1 | Workers-lite boundary | Password login; email-only; no login | Full native; Workers password login disabled until spike | M6 |
| R2 | Password hashing on Workers | WASM Argon2; PBKDF2; native service | Do not hash passwords on Workers in v1 | M6 |
| R3 | Signing algorithm | ES256; EdDSA; both | ES256 only; publish EdDSA when verified | M2 |
| R4 | Key custody | Encrypted DB + env; KMS; secret store | Encrypted DB with a master key from env/file | M2 |
| R5 | Cloudflare Containers | Supported; community | Community-supported, documented escape hatch | M6 |
| R6 | D1 read replication | Disable; primary reads; accept staleness | Primary reads for auth-critical paths | M6 |
| R7 | Rate-limit storage | In-process; database; platform service | Database-backed for multi-replica; in-process for single node | M4 |
| R8 | Audit export format | JSONL; CSV; both | JSONL with a stable schema and checksum | M4 |
| R9 | Issuer migration tool | In scope; not | Not in v1; document re-registration | M5 |
| R10 | Configuration names | Finalize env/TOML schema | Typed TOML plus environment overrides; names finalized in M2 | M2 |

## How a decision is resolved

1. Open an RFC issue using the RFC template. State the problem, options, security impact,
   operational cost, and migration path.
2. Discuss publicly. Record objections and the rationale for the chosen option.
3. A maintainer accepts, defers, or rejects the proposal. Accepted decisions become ADRs.
4. Update this register, the affected docs, and any implementation issue that referenced
   the old default.
5. Do not silently diverge from an accepted ADR. Supersede it with a new ADR instead.
