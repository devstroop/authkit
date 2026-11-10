# ADR-0011: Applications are tenants; organizations are removed

- Status: Accepted (supersedes [ADR-0003](0003-organizations-are-tenants.md))
- Date: 2026-11-09

## Context

AuthKit is deployed as a single shared identity provider — one instance serves many
products, e.g. `accounts.devstroop.com` in front of every project. This mirrors Google
Accounts (one login surface, many products) and Auth0 (tenant), Keycloak (realm), and
Authentik (tenant/brand), where the unit of isolation is the product-facing tenant.

ADR-0003 made the Organization the tenant and Applications surfaces inside it. That
forces every product to invent an organization even when the deployment operator owns
all projects, and couples the user pool to the organization, so two products cannot
have isolated user pools on one deployment.

## Decision

1. **The Application is the tenant.** An application owns: an isolated user pool
   (users carry `application_id`; emails are unique per application), its memberships,
   roles, and role bindings, its OAuth 2.0/OIDC clients, its primary domain, its audit
   events, and its OIDC issuer.
2. **The Organization aggregate is removed.** Grouping inside an application is
   expressed with memberships and roles. A dedicated lightweight group entity is a
   future option, not part of this change.
3. **Applications are provisioned by the system administrator**: name, slug, primary
   domain, first client credentials, and an initial owner. The application owner
   manages members, roles, and invitations within their application. End users manage
   only their profile, credentials, and sessions. Self-serve application creation may
   be added later behind deployment configuration.
4. **One primary domain per application.** The domain is the routing key: the request
   host resolves to the application. A path-based fallback (`/t/{slug}`) exists for
   development and tests. Wildcards are not allowed. Domains are validated lowercase
   hostnames and unique across applications.
5. **Per-application issuer.** `iss` is `https://{primary_domain}`; signing keys are
   shared across the deployment, and each application's discovery document points at
   the shared JWKS URI. Tenant resolution is explicit at every boundary via
   `TenantContext`, which now carries `application_id`.

Tenant isolation tests are mandatory at every repository and administrative route
boundary, keyed by `application_id`.

## Consequences

- Breaking schema change: `organizations` fold into `applications`; `org_id` becomes
  `application_id` on users, memberships, invitations, roles, role bindings, and audit
  events. Pre-release: migrations drop and recreate rather than carry data forward.
- Organization routes, templates, and permissions are removed; application management
  moves to the admin surface (provisioning) and owner surface (members/roles); the
  account surface becomes profile-only for end users.
- Per-domain TLS/hostname setup is a deployment responsibility.

## Security considerations

Tenant escape is restated in terms of applications and domains. A forged tenant ID or a
request to the wrong host must fail even with a valid session and a valid client.
Domain-to-application resolution is security-sensitive and must not trust unvalidated
forwarded headers. See [Threat model](../threat-model.md#tenant-escape).

## Alternatives considered

- **Keep organizations as tenants (ADR-0003).** Rejected: wrong unit of isolation for
  an operator-owned shared IdP.
- **Shared user pool across applications.** Rejected for now: credentials, sessions,
  and profile data would leak across products. Revisit only for explicit cross-product
  SSO needs.
- **Self-serve application creation.** Deferred behind configuration; unnecessary for
  operator-owned deployments. This is the one open tension carried forward from the
  original product framing and may be revisited for public-SaaS mode.

## Related

- Supersedes [ADR-0003](0003-organizations-are-tenants.md).
- Related: [Domain model](../domain-model.md), [Architecture](../architecture.md),
  [Security model](../security-model.md).
