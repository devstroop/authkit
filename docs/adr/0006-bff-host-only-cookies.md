# ADR-0006: BFF default and host-only cookies

- Status: Accepted
- Deciders: maintainers
- Related: [Architecture](../architecture.md#6-bff-choice), [Security model](../security-model.md#6-cookies)

## Context

Browser applications can hold OIDC tokens directly (SPA with PKCE) or delegate the code
exchange and token storage to a backend-for-frontend (BFF). Direct token storage exposes
refresh tokens to XSS and makes rotation, revocation, and cross-tab logout harder. It also
encourages parent-domain cookies so that several subdomains can share a session, which
widens the blast radius of any one application.

## Decision

The default browser architecture is a BFF:

- The browser holds a host-only, HttpOnly, Secure session cookie for the application's own
  origin.
- The application backend is a confidential OAuth client. It performs the code exchange,
  stores tokens server-side, and refreshes them.
- AuthKit's own UI is server-rendered and uses its own host-only session cookie.
- Each origin sets its own cookie. No cookie is shared across the apex or across unrelated
  subdomains.
- Native and CLI clients use public-client flows with PKCE instead of a BFF.

## Alternatives considered

- **SPA with tokens in memory.** Better than local storage, but refresh tokens still need a
  browser-reachable store or a refresh endpoint that behaves like a BFF.
- **Parent-domain cookie for SSO across subdomains.** Convenient, but any subdomain can
  read or overwrite the cookie; a compromise anywhere becomes a compromise everywhere.
- **No browser sessions; token per request.** Poor UX and a larger token exposure surface.

## Consequences

- Every browser-facing integration needs a small server component.
- Logout is coordinated: the application clears its session and redirects to AuthKit's
  logout endpoint; AuthKit clears its own session.
- Documentation must show the BFF pattern clearly, because it is more work than a SPA
  quickstart.
- A future first-party SSO feature would require an explicit design, not a cookie-scope
  change.

## Security considerations

Host-only cookies prevent sibling-subdomain cookie injection and reduce the impact of a
compromised application origin. The BFF keeps refresh tokens off the browser, which is the
single largest reduction in token-theft impact. CSRF defense is simpler with same-origin
forms and `SameSite` cookies, but a CSRF token is still required for state-changing
requests.
