# ADR-0004: OIDC/OAuth 2.0 only in v1

- Status: Accepted
- Deciders: maintainers
- Related: [Standards](../standards.md), [Product](../product.md#scope)

## Context

Enterprise identity suites compete on protocol breadth: SAML, SCIM, LDAP, WS-Federation,
Kerberos, and proprietary connectors. Supporting them well requires metadata parsing,
certificate handling, directory synchronization, vendor-specific quirks, and a much larger
support surface. That breadth is the opposite of AuthKit's goal.

## Decision

V1 implements a focused OIDC/OAuth 2.0 profile:

- authorization code + PKCE, refresh rotation, client credentials;
- discovery, JWKS, userinfo, revocation, RP-initiated logout;
- email/password login, email verification, password reset, and session management;
- organizations, applications, clients, roles, and audit.

SAML, SCIM, LDAP, WS-Federation, device flow, PAR, DPoP, and back-channel logout are out of
scope. Upstream OIDC federation is deferred until after v1. The project does not advertise a
protocol it has not implemented and tested.

## Alternatives considered

- **Add SAML/SCIM in v1.** Rejected: it delays a usable core and adds a large parser and
  certificate surface.
- **Become an identity broker.** Rejected: brokering is a different product with different
  failure modes and a much larger configuration model.
- **Implement a draft OAuth 2.1 profile and claim it.** Rejected: follow stable RFCs and
  the security BCP, and state deviations explicitly.

## Consequences

- Some buyers will be excluded until a later integration or a bridge exists.
- The protocol surface stays small enough to test and review thoroughly.
- A future SAML or SCIM feature must be an RFC and an ADR; it must not be smuggled in as a
  "small" extension.
- Applications that need unsupported flows can use a separate gateway, but AuthKit will not
  pretend to provide them.

## Security considerations

Every supported flow has a defined threat model and negative tests. Unsupported parameters
are rejected rather than ignored. Dynamic client registration and request objects are not
supported in v1, so the metadata must not advertise them.
