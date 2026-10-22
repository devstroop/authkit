# ADR-0005: Server-rendered Askama/HTMX UI

- Status: Accepted
- Deciders: maintainers
- Related: [UI stack](../ui-stack.md)

## Context

The administration and account surfaces are security-sensitive and must be usable by
operators with different browsers, assistive technology, and network conditions. A React
single-page application would add a second build system, a client-side auth/session layer,
JSON API contracts, and a large dependency surface. It would also make the no-JavaScript
baseline much harder to preserve.

## Decision

AuthKit renders HTML on the server with Askama templates and enhances selected regions with
HTMX v4. Tailwind CSS provides styling, and the component primitives are shadcn-inspired
ports designed for HTML, not React components.

- Core flows work as normal HTML forms and links with JavaScript disabled.
- HTMX is used for regions and partial updates, not to replace navigation or form
  semantics.
- Create/edit operations use native `<dialog>` forms rather than forms buried at the bottom
  of pages.
- The UI calls application use cases in-process; it does not make private HTTP calls to
  itself.
- Templates receive view models, never domain entities or database rows.

## Alternatives considered

- **React SPA with a JSON API.** More familiar to some frontend developers, but a second
  runtime, a larger attack surface, and a worse no-JS story.
- **React islands inside Askama.** Useful for a few highly interactive screens, but not
  needed for the planned admin/account flows.
- **Plain HTML with no HTMX.** Viable, but HTMX provides useful partial updates with a
  small footprint and no client-side state model.

## Consequences

- One deployable artifact serves pages, fragments, and OAuth endpoints.
- UI tests must cover both full-page and fragment responses, and must include a
  JavaScript-disabled pass.
- The design system is expressed as HTML macros, CSS tokens, and small scripts, not as a
  React component library.
- If an exact React-only component becomes mandatory, an isolated island or a separate
  admin app is a new decision, not a silent exception.

## Security considerations

Server rendering reduces token exposure in the browser: the browser holds a host-only
session cookie, not OIDC access or refresh tokens. Every mutating form uses a CSRF token
and same-origin checks. Output escaping is the default; raw HTML is never rendered from
user input.
