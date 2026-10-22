# ADR-0007: No auth proxy or outposts

- Status: Accepted
- Deciders: maintainers
- Related: [Architecture](../architecture.md#8-why-no-auth-proxy-and-no-outposts)

## Context

Some identity products protect applications by putting a reverse proxy in front of them and
injecting identity headers (`X-Auth-Request-User`, `X-Forwarded-Email`, and similar). Others
deploy an agent or "outpost" inside each network. Both approaches can retrofit
authentication onto applications that cannot speak OIDC, but they turn the identity service
into a traffic dependency and create a new trust boundary.

## Decision

AuthKit does not ship an auth proxy, forward-auth middleware, or outposts in v1.
Applications integrate with OIDC directly. A reverse proxy may terminate TLS or provide a
WAF in front of AuthKit, but it must not inject authenticated identity for upstream
applications.

An application that cannot validate a JWT may call userinfo or introspection server-side;
that is an application integration choice, not a proxy feature.

## Alternatives considered

- **Forward-auth proxy.** Rejected: it routes every request through AuthKit, breaks on
  WebSockets and non-HTTP protocols, and encourages unsafe header trust.
- **Per-network outpost.** Rejected: it adds deployment, upgrade, and trust complexity that
  a small identity service should not carry.
- **Per-application connector.** Rejected: it is an integration project per application and
  duplicates what OIDC already standardizes.

## Consequences

- Applications must be able to integrate OIDC or use a small sidecar/BFF of their own.
- AuthKit is an identity dependency, not a data-plane dependency; a login outage does not
  take down every request.
- Host-only cookies and per-origin sessions remain coherent.
- A future proxy feature would be a separate product with its own threat model, not a
  configuration flag.

## Security considerations

Header-based identity is safe only when the application is unreachable except through the
proxy and the network path is airtight. That is difficult to guarantee and easy to
misconfigure. Direct token validation with JWKS keeps the trust decision in the application
and avoids a class of spoofing bugs.
