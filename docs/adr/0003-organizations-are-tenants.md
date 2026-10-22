# ADR-0003: Organizations are tenants; applications are surfaces

- Status: Accepted
- Deciders: maintainers
- Related: [Domain model](../domain-model.md#2-aggregate-map), [Security model](../security-model.md#13-tenant-isolation)

## Context

Identity products use "tenant", "workspace", "organization", "project", and "application"
in overlapping ways. If an application is treated as a tenant, a user needs a separate
membership per surface, cross-application tokens become cross-tenant tokens, and
organization-wide roles become impossible to express. If an organization is treated as an
application, product surfaces with different clients, redirect URIs, and secrets collapse
into one registration.

## Decision

An **organization** is the tenant boundary. It owns memberships, applications, role
definitions, and tenant audit. A **user** is a deployment-global identity that can belong
to several organizations. An **application** is a product surface owned by exactly one
organization and may expose several OAuth clients (web, admin, native, service). OAuth
clients belong to an application; the client's tenant is derived from that application and
cannot be supplied by the client at runtime.

Every tenant-owned row carries `org_id`, and every tenant-scoped repository method requires
a `TenantContext`. System administration is a separate, deployment-level authorization path.

## Alternatives considered

- **Application as tenant.** Common in developer platforms, but it duplicates users and
  memberships per surface and makes shared organization roles awkward.
- **Flat deployment with groups.** Groups can model roles, but they do not provide a
  tenancy boundary for administration, audit, or data deletion.
- **One tenant per deployment.** Simplest, but it cannot serve an organization with
  multiple product surfaces or a platform with multiple customers.

## Consequences

- A user has one identity and one credential set across all organizations.
- Organization roles are shared across its applications; application-scoped bindings add
  narrower access where needed.
- Cross-organization access is not modeled in v1. A future partner/shared-application
  feature must be an explicit grant or organization link, not an application owned by two
  tenants.
- Tenant isolation tests are mandatory for every repository and administrative route.

## Security considerations

Tenant escape is a critical threat. The design makes the tenant explicit at every boundary
and forbids ambient "current organization" state. A forged tenant ID must fail even with a
valid session and a valid client. See [Threat model](../threat-model.md#tenant-escape).
