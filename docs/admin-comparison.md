# Admin area comparison: AuthKit vs Authentik vs WorkOS AuthKit

## Scope

- **AuthKit (this repo):** self-hosted identity provider. Admin is a small,
  server-rendered (`Askama` + HTMX) surface at `/admin` for system
  administrators, plus separate organization-scoped pages under
  `/organizations/{id}`.
- **Authentik:** self-hosted identity provider / IAM platform. Admin is a
  large SPA (`web/src/admin`) covering the whole platform.
- **WorkOS AuthKit:** SaaS. There is no self-hosted admin UI in the
  example repo; administration happens in the WorkOS dashboard and via the
  User Management API.

## High-level

| Area | AuthKit | Authentik | WorkOS AuthKit |
|---|---|---|---|
| Delivery | Self-hosted binary/container | Self-hosted (Python + Rust + web) | SaaS dashboard + SDKs |
| Admin UI tech | Server-rendered HTML (Askama/HTMX) | TypeScript/Lit SPA | Hosted (external) |
| Auth to admin | System admin account + mandatory TOTP | RBAC users/groups/roles | WorkOS dashboard login |
| Org/tenant mgmt | Dedicated `/organizations` pages (not under `/admin`) | Applications, providers, sources, outposts | Organizations via API/dashboard |
| Impersonation | Yes (cookie flag + audit) | Yes (admin interface) | Yes (dashboard/API) |
| Backup/restore | SQLite `VACUUM INTO` + upload restore | DB-level / blueprints | Managed by WorkOS |

## Feature matrix (system admin)

| Capability | AuthKit | Authentik | WorkOS |
|---|---|---|---|
| Dashboard overview (stats/health) | Partial (admins, keys, recent events) | Rich (charts, cards) | Dashboard |
| User management (list/view) | List users (email, status, verified) | Full CRUD + attributes | User Management API |
| Grant/revoke system admins | Yes (super-admin + TOTP step-up) | Role assignment | N/A (SaaS) |
| Disable admin | Yes (with last-admin guard) | Role removal | N/A |
| Audit log view | Yes, filter + CSV/JSON export | Events + policies/reports | Audit logs API |
| Signing key rotation | Yes (KeyRing rotate) | Crypto providers/certs | Managed |
| MFA for admins | TOTP enroll + verify | MFA stages/policies | Managed |
| Backup download | Yes (SQLite only) | DB backups | Managed |
| Restore upload | Yes (SQLite only, integrity check) | DB restore | Managed |
| Impersonate user | Yes | Yes | Yes |
| Branding | Recently added (brand domain) | Brands section | Theming in dashboard |
| Applications/OAuth clients | Org-scoped pages, not system admin | Full applications/providers | WorkOS apps |
| Flows / stages / policies | No | Yes (visual editor) | Hosted flows |
| Sources (LDAP/SAML/OAuth) | OIDC/OAuth only | Many sources | Many (SAML, SCIM) |
| Outposts/agents | No (ADR-0007) | Yes | N/A |
| Blueprints (declarative config) | No | Yes | N/A |
| Files/storage | No | Yes | N/A |
| RBAC granularity | Super-admin vs admin | Fine-grained RBAC | SaaS roles |
| Reports | No | Yes | Dashboard |

## Observations / gaps for AuthKit

1. **Admin UI is intentionally small.** AuthKit keeps `/admin` limited to
   platform-operator concerns (admins, keys, audit, backup) and pushes
   tenant/org management to org-scoped pages. Authentik instead centralizes
   everything in one admin SPA.
2. **No visual flow/policy editor.** Authentik's stages/policies/flows are a
   major differentiator; AuthKit has no equivalent. If needed, this would be
   a large addition.
3. **No fine-grained RBAC.** AuthKit has only `is_super_admin()` gating for
   destructive actions; Authentik has roles/permissions. Consider roles if
   multi-operator deployments grow.
4. **Backup/restore is SQLite-only.** Postgres deployments must use
   `pg_dump`/`pg_restore`; the web restore explicitly rejects non-SQLite.
5. **Branding and applications are org-scoped, not admin-managed.** This
   matches the tenant model (ADR-0003) but differs from Authentik where
   brands/applications are global admin objects.
6. **WorkOS is not a self-hosted comparator.** Its admin is a SaaS
   dashboard; the only relevant learnings are API/impersonation/domain-policy
   patterns (see `docs/workos-authkit-learnings.md`).

## Recommendation

Keep AuthKit's admin minimal and operator-focused; do not chase Authentik's
breadth. If a capability is needed, prefer adding it to the org-scoped pages
or exposing it via the HTTP API rather than expanding `/admin`, consistent
with the tenant-as-application model (ADR-0003) and the no-outposts stance
(ADR-0007).
