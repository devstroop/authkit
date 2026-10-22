# AuthKit product definition

AuthKit is a small, self-hostable identity and authentication service. It gives an
organization one place to manage users, sessions, applications, and roles, and gives each
application a standards-based OIDC/OAuth 2.0 integration instead of a bespoke login system.

It is designed to be useful in three shapes without becoming three products:

- **Standalone:** one team protects one application and wants a boring, auditable login
  service it can run itself.
- **Shared platform:** an organization runs several applications and wants one identity
  plane, one user directory, and one administration surface for all of them.
- **Embedded deployment:** a product ships AuthKit as part of its own stack, on a native
  server or on Cloudflare Workers.

The core product is consumer-agnostic. AI Gateway is one planned consumer and a useful
integration test, but no core feature depends on it.

> **Status: documentation and planning.** There is no production-ready code, release, or
> stable API yet. Do not deploy AuthKit or use it to protect real identities. The working
> name is provisional; see [Naming and licensing](#naming-and-licensing).

## The problem

Small teams accumulate authentication one application at a time: a users table here, a
password reset flow there, a session cookie with slightly different rules in each service,
and no shared answer to "who is this person, what may they do, and how do we revoke them?"

Buying a full identity platform solves the problem but brings enterprise features, a large
operational surface, and a vendor dependency that is hard to self-host. Building a minimal
OIDC server from scratch is deceptively hard: PKCE, refresh rotation, key management,
tenant isolation, CSRF, session theft detection, and audit are all load-bearing.

AuthKit occupies the space between those options:

- one deployable service, one database, one administration surface;
- a focused OIDC/OAuth 2.0 profile rather than a universal identity broker;
- organizations as tenants, applications as product surfaces;
- server-rendered UI that works without JavaScript;
- SQLite for a small deployment, Postgres when scale requires it;
- an optional Workers profile for edge deployments, with explicit limits.

## Design principles

1. **Boring beats clever.** Standard protocols, a small dependency surface, and readable
   code. Authentication is not the place for a novel abstraction.
2. **Secure by default.** Host-only cookies, short-lived tokens, hashed credentials,
   explicit redirect allowlists, fail-closed authorization, and no unsafe production
   defaults.
3. **Portable by contract.** The domain core is independent of HTTP, storage, templates,
   and runtime. Native and Workers adapters implement the same domain behavior.
4. **One tenant model.** An organization is the isolation boundary. An application is a
   surface inside it. Neither concept is overloaded to mean the other.
5. **Progressive UI.** Server-rendered pages and native forms first; HTMX enhances them.
   Core flows must work with JavaScript disabled.
6. **Operable by one person.** A single binary, a SQLite file, clear backups, and a
   documented key-rotation and recovery path.
7. **No accidental promises.** No release date, support window, or production-readiness
   claim before the corresponding policy and evidence exist.

## Personas

| Persona | Goal | What AuthKit gives them |
| --- | --- | --- |
| End user | Sign in, consent, manage their own account and sessions | A clear login, consent, profile, password, and session experience |
| Organization owner/admin | Run one tenant: people, applications, roles, audit | Tenant-scoped administration without deployment-level access |
| Application developer | Integrate an app without building auth | Discovery, OIDC code flow with PKCE, JWKS, userinfo, logout, and sample BFF code |
| System administrator/operator | Run the deployment safely | First-run setup, organizations, signing keys, health, backups, audit export, break-glass controls |
| Contributor/auditor | Understand and verify the system | Public docs, ADRs, threat model, conformance evidence, no hidden control plane |

## Core use cases

### Identity and session

- Sign up with email and password, verify the email, and sign in.
- Sign in with a passkey or TOTP second factor where the deployment enables it.
- Request a password reset without leaking whether an account exists.
- View and revoke active sessions; detect refresh-token and session theft.
- Suspend, disable, or delete an account with an auditable effect on sessions and tokens.
- Change an email address with re-verification and notification to the old address.

### Tenancy and authorization

- Create an organization, invite members, and assign roles.
- Define composable roles from granular permissions; keep a safe built-in owner/admin set.
- Protect the last owner from removal or demotion.
- Register applications and OAuth clients with exact redirect URIs and allowed scopes.
- Grant a user access through organization membership and application-scoped role bindings.

### OIDC/OAuth integration

- Discover the issuer and endpoints from `/.well-known/openid-configuration`.
- Run the authorization code flow with PKCE and a `state`/`nonce` round trip.
- Exchange codes at the token endpoint using a confidential BFF client or a public native
  client.
- Validate access tokens locally with JWKS; call userinfo only when needed.
- Rotate refresh tokens, detect reuse, and revoke a family.
- Support RP-initiated logout and token revocation.
- Issue service tokens with the client credentials grant.

### Administration and operations

- Complete a first-run setup without a hidden bootstrap account.
- Manage organizations, applications, clients, members, roles, and sessions from one UI.
- Review and export audit events.
- Rotate signing keys and client secrets with overlap windows.
- Back up, restore, upgrade, and monitor a deployment using documented runbooks.

## Scope

### v1

- OIDC authorization code flow with PKCE, refresh rotation, userinfo, revocation, and
  RP-initiated logout.
- Client credentials for service integrations.
- Organizations, applications, OAuth clients, memberships, invitations, roles, and
  permissions.
- Email/password authentication, email verification, password reset, and session
  management.
- Admin and account UI served by AuthKit with Askama and HTMX.
- Audit events, first-run setup, key rotation, and an administrative CLI.
- Native runtime with SQLite and Postgres.
- Documented security model, threat model, operations guide, and conformance evidence.

### After v1

- Passkeys/WebAuthn and TOTP MFA, if not included in v1.
- Upstream OIDC federation for deployments that need an external identity source.
- An outbound webhook/event stream for provisioning and security automation.
- Optional introspection and opaque access tokens for applications that cannot validate
  JWTs.
- A supported Cloudflare Workers profile after the compatibility spike and feature gates.
- A migration/import toolkit for common identity providers.

### Not planned

- SAML, SCIM, LDAP, or an enterprise directory suite.
- An outpost, connector, forward-auth proxy, or per-application gateway.
- A visual authentication-flow builder.
- A React single-page application as the default UI.
- Parent-domain cookies, shared cross-subdomain sessions, or implicit flow.
- Billing, subscription management, or a hosted multi-tenant SaaS control plane.

## Deployment profiles

| Profile | Database | Best for | Limits |
| --- | --- | --- | --- |
| Native single node | SQLite | Small teams, single region, simplest operations | One writer; no horizontal scale |
| Native scaled | Postgres | Multiple replicas, larger audit volume, managed backups | More operational work |
| Workers preview | D1 | Cloudflare-native deployments with small tenants | Reduced feature set; see runtime targets |

The native runtime is the reference implementation. Workers support is a preview until the
compatibility checklist in [Runtime targets](runtime-targets.md) is complete.

## What makes it different

- **Narrower than an enterprise IdP.** AuthKit does not try to be an identity broker, an
  auth proxy, or a workflow engine.
- **More complete than a login library.** It owns users, sessions, clients, keys, and
  audit, not just password hashing.
- **Tenant model built in.** Organizations and applications are first-class; tenancy is
  not bolted on through groups or custom claims.
- **Operationally small.** A single binary and SQLite are a supported production shape,
  not a demo mode.
- **Auditable surface.** A finite protocol profile, an explicit threat model, and ADRs for
  decisions that are expensive to reverse.

AuthKit is not a drop-in replacement for Authentik, Keycloak, or Zitadel. It deliberately
implements less. The intended trade is fewer features, a smaller attack surface, and a
deployment an ordinary team can understand.

## Success criteria for v1

- An OIDC basic-profile conformance run passes, and the evidence is published with the
  release.
- A new operator can go from an empty host to a working login for a sample BFF in under an
  hour using the documentation.
- A single-node SQLite deployment can be backed up and restored without downtime tools.
- All security invariants in the [security model](security-model.md) have automated
  negative tests.
- No critical or high findings remain open from the pre-release security review.
- Every public configuration option is documented and has a safe default.
- Core login, consent, and account flows work with JavaScript disabled.

## Naming and licensing

AuthKit is a working name. WorkOS AuthKit is an existing product, so naming and trademark
review must complete before packages, domains, or a public launch use the name. The license
is not selected yet; no license is granted until a `LICENSE` file is added. Both are
tracked as open governance items in [GOVERNANCE.md](../GOVERNANCE.md#access-continuity-and-open-items).
