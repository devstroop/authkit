# AuthKit UI stack

AuthKit's UI is server-rendered with Askama, enhanced with HTMX, and styled with Tailwind.
The visual language is shadcn-inspired: restrained surfaces, semantic color tokens, clear
focus states, and composable primitives. It is **not** a React application and does not
embed React shadcn components.

This document defines the rendering architecture, component conventions, accessibility
requirements, form and CSRF patterns, and the options if exact shadcn parity becomes a hard
product requirement.

Related documents:

- [Architecture](architecture.md)
- [Domain model](domain-model.md)
- [Runtime targets](runtime-targets.md)
- [Standards](standards.md)

## 1. Goals and constraints

Goals:

- Fast first paint and usable pages without JavaScript.
- A single Rust deployable with no Node runtime in production.
- Server-owned state and authorization; the browser is not an authorization authority.
- Accessible forms, dialogs, tables, and navigation by default.
- Host-only cookies and strict CSRF defenses.
- A small, auditable JavaScript surface.
- Visual consistency with modern shadcn-inspired admin interfaces without adopting React.

Constraints:

- Askama templates are compiled into the binary. There is no client-side component
  runtime, no hydration, and no virtual DOM.
- HTMX swaps HTML fragments returned by the server. It is not a state manager.
- Tailwind classes must be statically discoverable at build time. Dynamically constructed
  class names are not allowed.
- The AuthKit UI runs on both native and Workers targets. Avoid browser APIs or asset
  pipelines that only one runtime can serve.
- The UI shares an origin with the OAuth endpoints on `auth.<apex>`. No parent-domain
  cookies are used.

## 2. Stack

| Layer | Choice | Role |
| --- | --- | --- |
| Templates | Askama | Compile-time HTML templates, auto-escaping, layout inheritance, macros. |
| Hypermedia | HTMX | Partial page updates, form submission, history, events. |
| Styling | Tailwind CSS | Utility classes compiled to a static stylesheet. |
| Design primitives | AuthKit component macros | shadcn-inspired markup and variants implemented with native HTML. |
| Behavior | Small vanilla ES modules | Dialog opening, menus, focus management, toasts, copy buttons. |
| Icons | Inline SVG sprite | No icon-font or runtime dependency. |
| Assets | Static files served by the app or platform | Pinned HTMX, compiled CSS, compiled JS. No CDN requirement. |

No React, Vue, Svelte, Alpine, jQuery, or client-side router is part of the baseline. A
small dependency is acceptable when it removes custom fragile code, but it must be
vendored, pinned, and covered by the CSP.

## 3. Rendering architecture

### 3.1 Layouts, pages, fragments, macros

Suggested template tree:

```text
templates/
  layouts/
    app.html          # authenticated shell, nav, flash region
    auth.html         # centered login/consent shell
    error.html
  pages/
    organizations/list.html
    organizations/detail.html
    applications/detail.html
    clients/form.html
    audit/list.html
    account/security.html
  fragments/
    organizations/table.html
    applications/table.html
    clients/form.html
    audit/rows.html
    shared/pagination.html
  macros/
    ui.html           # button, input, field, badge, dialog, table, alert
    icons.html
```

- A **page** template extends a layout and renders a complete document.
- A **fragment** template renders only the region that HTMX will swap. It may use the same
  macros as the page.
- A **macro** is the single source of truth for a primitive's markup. Pages and fragments
  call the macro; they do not duplicate button or field markup.
- View models are plain Rust structs prepared by the handler. Templates do not query the
  database, call services, or perform authorization checks.

Askama does not provide a general "render one block of a page" API. Do not try to reuse a
full-page template as a fragment by stripping HTML in the handler. Instead:

1. Extract the region into a fragment template or a macro.
2. Call the macro from both the page and the fragment.
3. Render the fragment template for HTMX requests.

This keeps one markup definition and avoids brittle string slicing.

### 3.2 Full page versus fragment

Handlers decide based on the request, not on a query parameter supplied by the client:

```rust
fn wants_fragment(headers: &HeaderMap) -> bool {
    headers.get("HX-Request").is_some()
}
```

Response rules:

| Request | Response |
| --- | --- |
| Normal navigation | Full page with layout, status 200. |
| HTMX GET/POST success | Fragment for the target, status 200, plus `HX-Trigger` events if needed. |
| HTMX form validation failure | Form fragment with errors, status 200, target remains open. |
| Non-HTMX form success | `303 See Other` to the canonical GET URL (POST-redirect-GET). |
| Non-HTMX validation failure | Full page with errors, status 200 or 422 according to the route's contract. |
| Authentication expired during HTMX request | `HX-Redirect: /login?next=...`, status 200 or 401 with the header. |
| Authorization denied | Full 403 page for navigation; fragment with an alert and `HX-Reswap: none` for HTMX. |

HTMX does not swap 4xx responses by default. Validation errors therefore return 200 with
the form fragment, or use `HX-Retarget`/`HX-Reswap` only when there is a deliberate reason.
Do not return a bare 422 and expect the user to see the errors.

### 3.3 Handler shape

A typical handler:

1. Authenticate the session.
2. Resolve the tenant from the route and verify membership.
3. Authorize the action against the permission catalog.
4. Parse and validate the form.
5. Call one application use case.
6. Build a view model from the result.
7. Render a page or fragment.

Handlers do not contain business rules. They map HTTP concerns to use-case inputs and map
domain errors to UI states. The same use case is callable from the JSON API and the CLI.

### 3.4 URL and history behavior

- Filters, sorting, and pagination live in query parameters. HTMX requests use
  `hx-push-url="true"` for navigational changes so the back button works.
- Form submissions that create or update a resource use POST-redirect-GET without HTMX. With
  HTMX, return the updated region and use `HX-Push-Url` only when the URL should change.
- Do not push a URL for transient validation errors or toast-only updates.
- Logout is a POST, never a GET. It redirects to the signed-out page.

## 4. HTMX conventions

### 4.1 Use HTMX for regions, not for everything

Appropriate:

- Filtering and paginating a table.
- Opening and submitting a create/edit form in a dialog.
- Inline validation after a field changes, when it does not upstage submit validation.
- Refreshing a status badge after an action.
- Loading a "load more" page of audit events.

Inappropriate:

- Full-page navigation where a normal link works.
- Client-side state machines that belong on the server.
- Drag-and-drop reordering without a server-side canonical order.
- Optimistic updates that can diverge from server state.
- Infinite scroll as the only way to reach content.

### 4.2 Targets and swaps

- Give each region a stable ID (`#members-table`, `#client-form`).
- Prefer `outerHTML` for a component that replaces itself, `innerHTML` for rows inside a
  container.
- Use `hx-swap="morph"` only if the chosen HTMX extension is vendored and tested; the default
  is a plain swap with explicit focus management.
- Use out-of-band swaps sparingly. A toast or a dialog close is better expressed as an
  event.

### 4.3 Events

Server-to-client signals:

- `HX-Trigger` with a JSON object for `toast:show`, `dialog:close`, or `table:refresh`.
- `HX-Redirect` for a full navigation after session expiry or a successful non-fragment
  flow.
- `HX-Push-Url` / `HX-Replace-Url` for history.
- `HX-Location` only for deliberate client-side navigation.

Client-to-server signals are normal requests with form data or query parameters. Avoid
inventing a JSON protocol over HTMX; the server should return HTML.

### 4.4 Concurrency and feedback

- Use `hx-sync="this:drop"` or `this:abort` on repeated submissions so a double click
  cannot create two resources.
- Use `hx-disabled-elt="find button[type=submit]"` to prevent duplicate submits.
- Use `hx-indicator` with visible text or an accessible spinner; do not rely on color alone.
- Set `aria-busy="true"` on the region during requests via the `htmx:beforeRequest` and
  `htmx:afterRequest` events.
- Avoid polling unless a job genuinely runs asynchronously. If polling is needed, use a
  bounded interval and stop when the region is hidden.

### 4.5 Errors

- Global `htmx:responseError` handler shows a generic toast and logs a request ID.
- A 401/redirect response clears stale UI and navigates to login.
- A network failure shows a retry action; it does not silently leave a spinner.
- Server errors include a request ID that support can correlate with logs. Never include a
  stack trace or SQL error in HTML.

## 5. Tailwind and shadcn-inspired primitives

### 5.1 Design tokens

Define semantic tokens as CSS custom properties and map them into Tailwind:

```css
:root {
  --background: ...;
  --foreground: ...;
  --card: ...;
  --card-foreground: ...;
  --primary: ...;
  --primary-foreground: ...;
  --muted: ...;
  --muted-foreground: ...;
  --border: ...;
  --ring: ...;
  --destructive: ...;
  --destructive-foreground: ...;
}
```

Use semantic names in templates (`bg-background`, `text-muted-foreground`, `ring-ring`),
not raw palette names scattered through markup. Dark mode uses a `data-theme="dark"` root
attribute or `prefers-color-scheme`, with the same tokens. Contrast is verified for both
themes.

### 5.2 Variants

Primitive variants are explicit maps in Rust or fixed class strings in Askama macros:

```askama
{% macro button(variant="default", size="default", kind="button") %}
<button
  type="{{ kind }}"
  class="inline-flex items-center justify-center gap-2 rounded-md text-sm font-medium
         transition-colors focus-visible:outline-none focus-visible:ring-2
         focus-visible:ring-ring disabled:pointer-events-none disabled:opacity-50
         {% if variant == "default" %}bg-primary text-primary-foreground hover:bg-primary/90{% endif %}
         {% if variant == "outline" %}border border-border bg-background hover:bg-muted{% endif %}
         {% if variant == "ghost" %}hover:bg-muted{% endif %}
         {% if variant == "destructive" %}bg-destructive text-destructive-foreground{% endif %}
         {% if size == "sm" %}h-8 px-3{% else %}h-10 px-4{% endif %}">
  {{ caller() }}
</button>
{% endmacro %}
```

Rules:

- Never build class names by concatenating user input. Tailwind cannot see them, and it is an
  injection risk in attribute context.
- Attribute values are escaped by Askama. Use `|safe` only for server-generated, already
  sanitized SVG or trusted static markup, never for user content.
- Primitives use native elements: `<button>`, `<input>`, `<select>`, `<textarea>`, `<table>`,
  `<dialog>`. Do not recreate them with divs.
- Icons are decorative unless they carry meaning. Decorative icons get `aria-hidden="true"`;
  icon-only buttons get an accessible name via visible text or `aria-label`.

### 5.3 Primitive inventory

| Primitive | Implementation | Notes |
| --- | --- | --- |
| Button | `<button>` or `<a>` with variants | `<a>` is for navigation, not actions. |
| Input / textarea / select | Native control + label + description + error | Use `aria-describedby` and `aria-invalid`. |
| Field | Label, control slot, hint, error | One error ID per field, stable across swaps. |
| Checkbox / radio / switch | Native input; switch uses `role="switch"` only if implemented accessibly | Prefer a checkbox when in doubt. |
| Badge | `<span>` with tone variants | Text, not color alone. |
| Card | Section with heading | Not a clickable div. |
| Table | `<table>` with `<caption>`, `<th scope>` | Responsive overflow wrapper, not card-per-row only. |
| Dialog | Native `<dialog>` + `showModal()` | Focus trap and Escape handled by the platform. |
| Alert | `role="alert"` for errors, `role="status"` for success | Avoid duplicate announcements. |
| Toast | Live region + dismiss button | Timeout is generous; errors persist until dismissed. |
| Tabs | Links or native radio pattern | Prefer navigable links for page-level tabs. |
| Dropdown menu | `<details>` or button + popover + keyboard JS | Do not ship an inaccessible custom menu. |
| Pagination | Links with `rel="prev"`/`next` | Works without JS; HTMX enhances. |
| Empty state | Heading, explanation, primary action | Not just "No data". |

## 6. Native dialog forms

Native `<dialog>` is the default modal primitive. It provides modal focus behavior,
Escape-to-close, backdrop rendering, and top-layer stacking without a React dialog library.

### 6.1 Progressive enhancement

The trigger is a real link to a dedicated page. JavaScript upgrades it to a dialog:

```html
<a href="/orgs/acme/apps/new"
   data-dialog-open="create-app"
   hx-get="/orgs/acme/apps/new"
   hx-target="#create-app-body"
   hx-swap="innerHTML">
  New application
</a>

<dialog id="create-app" aria-labelledby="create-app-title">
  <div id="create-app-body"></div>
</dialog>
```

Without JavaScript, the link navigates to a full form page. With JavaScript, a delegated
click handler prevents navigation, fetches the form into the dialog, and calls
`showModal()`. The form itself is ordinary HTML and posts normally if HTMX is unavailable.

### 6.2 Form behavior

- Do not use `method="dialog"` for data submission. It closes the dialog and discards the
  request semantics. Use a normal form with `hx-post` or a standard POST.
- Cancel is a `type="button"` control handled by a small script. Escape also closes.
- On validation failure, the server returns the form fragment with errors and the dialog
  stays open. Focus moves to the error summary.
- On success, the server returns the updated region and an `HX-Trigger` event such as
  `dialog:close` and `toast:show`. The client closes the dialog and moves focus to a
  sensible place, usually the updated row or the page heading.
- If the trigger element was removed by the swap, focus the region heading rather than a
  detached node.
- Destructive actions use a separate confirmation dialog with explicit wording and, for
  high-impact actions, a typed resource name. The server enforces authorization
  independently; the dialog is not a security control.

### 6.3 Dialog accessibility

- `aria-labelledby` points to the dialog title; `aria-describedby` points to a short
  description when helpful.
- The first meaningful field gets `autofocus`; do not autofocus a destructive button.
- The close button has an accessible name.
- Background content is inert while a modal dialog is open (native `showModal()` behavior).
- Do not nest dialogs. If a flow needs a second step, replace the dialog content.
- Return focus to the opener when it still exists; otherwise focus the page's main heading.
- Do not close on backdrop click by default for forms with unsaved input. **Decision
  pending:** whether to allow backdrop dismissal with a dirty-form confirmation.

## 7. Progressive enhancement

The baseline contract:

1. Every navigation is a link.
2. Every mutation is a form POST with a CSRF token.
3. Every successful mutation ends in a redirect or a full page render.
4. HTMX replaces full-page updates with fragment updates when available.
5. JavaScript-only behavior (modal dialogs, menus, toasts) has a non-JavaScript fallback:
   a separate page, native `<details>`, or a plain flash message after redirect.

Rules:

- Do not require JavaScript to log in, consent, reset a password, manage members, or perform
  any authorization action.
- Run a no-JavaScript test suite for critical paths: login, logout, create application,
  invite member, revoke session.
- `hx-boost` may be used on simple navigational links, but not on logout, OAuth redirects, or
  anything that must produce a full document.
- Server-rendered flash messages survive redirects via a short-lived signed cookie or a
  one-time session field. Do not put them in the URL.
- The page remains usable at 200% zoom and at a 320 CSS-pixel viewport.

## 8. Accessibility

Target WCAG 2.2 AA for the admin and account UI. Accessibility is part of the definition of
done, not a later audit.

- Use one `<h1>` per page and a logical heading order.
- Provide a skip link to main content.
- Use landmarks: `<header>`, `<nav aria-label>`, `<main>`, `<aside>`, `<footer>`.
- Every form control has a visible `<label>`. Placeholders are not labels.
- Errors are announced and associated: `aria-invalid="true"`, `aria-describedby` pointing to
  the error text, and an error summary with links to fields.
- Success and error toasts use a live region. Do not announce the entire swapped table.
- After a fragment swap, manage focus deliberately:
  - validation error: focus the error summary;
  - successful create: focus the new row or a status message;
  - filter/pagination: keep focus in the filter or on the results heading, and announce the
    result count politely;
  - dialog close: return focus to the opener.
- Keyboard: all actions reachable by Tab, menus close on Escape, dialogs trap focus
  natively, no keyboard traps, visible focus ring using the `ring` token.
- Do not use color alone for status. Pair badges with text and icons.
- Respect `prefers-reduced-motion`; avoid gratuitous animation.
- Tables have captions or associated headings, column scopes, and responsive overflow that
  does not hide columns without an accessible alternative.
- Charts and audit visualizations (if any) have text summaries and data tables.
- Test with a screen reader and keyboard only for core flows. Automated axe checks are a
  floor, not a substitute.

## 9. CSRF and form security

### 9.1 Cookies

- Session cookie: `__Host-authkit_session`, `Secure`, `HttpOnly`, `SameSite=Lax`, `Path=/`,
  no `Domain`.
- CSRF cookie, if used: `__Host-authkit_csrf`, same attributes. It is readable by JavaScript
  only if the chosen pattern requires it; the synchronizer pattern does not.
- No parent-domain cookies. `app.example.com` cannot read `auth.example.com` cookies.
- Session token rotation on login, privilege change, and organization switch. Old session
  rows are revoked, not reused.

### 9.2 CSRF patterns

Use two complementary mechanisms:

1. **Synchronizer token for authenticated forms.** A per-session CSRF secret is stored
   server-side (hashed in the session row). Each form includes a hidden `_csrf` value derived
   from it. HTMX requests also send `X-CSRF-Token` via a global `htmx:configRequest`
   listener. The server compares in constant time.
2. **Signed double-submit for pre-authentication forms.** Login and password-reset request
   forms exist before a session. Set a short-lived host-only CSRF cookie and include a hidden
   token whose HMAC the server verifies against a server secret and the cookie. Rotate after
   login.

Additional defenses:

- Reject state-changing requests whose `Origin` is not the deployment's own origin.
  Optionally require `Sec-Fetch-Site: same-origin`.
- `SameSite=Lax` is required, not optional. Do not set `SameSite=None`.
- No state-changing GET requests. Logout, consent, revoke, and delete are POST.
- Do not accept CSRF tokens in URLs or log them.
- Rotate the CSRF secret on login and privilege changes. Do not make tokens single-use;
  multi-tab forms must remain valid.
- Custom headers alone are not sufficient CSRF defense; they complement tokens and origin
  checks.

### 9.3 Forms

- Use POST for all mutations, with a hidden `_csrf` and an optional `_idempotency_key` for
  admin mutations.
- Validate on the server. Client-side validation is a convenience only.
- Preserve non-sensitive field values on validation failure. Never re-render a password
  value.
- Name fields consistently (`email`, `display_name`, `role_key`) and map errors to field
  names, not positions.
- Use `autocomplete` attributes: `username`, `current-password`, `new-password`, `email`,
  `one-time-code`.
- Disable the submit button during submission and show a progress state. Server-side
  idempotency still applies.
- Destructive forms require explicit confirmation and show the target resource name.
- File uploads (for example, a logo) use multipart, enforce size and content-type limits on
  the server, and never trust the client-provided filename.

### 9.4 Headers and CSP

Recommended response headers for UI routes:

```text
Content-Security-Policy:
  default-src 'self';
  script-src 'self' 'nonce-<random>';
  style-src 'self';
  img-src 'self' data:;
  font-src 'self';
  connect-src 'self';
  frame-ancestors 'none';
  form-action 'self';
  base-uri 'none';
  object-src 'none'
Referrer-Policy: strict-origin-when-cross-origin
X-Content-Type-Options: nosniff
Permissions-Policy: camera=(), microphone=(), geolocation=()
```

- HTMX is vendored locally. Do not load it from a third-party CDN.
- Disable HTMX eval features (`htmx.config.allowEval = false`) and avoid `hx-on` attributes.
  Use external event listeners instead. This keeps `unsafe-eval` out of the CSP.
- Avoid inline scripts and styles. If a nonce is required, generate it per response and do
  not cache the HTML.
- OAuth authorization and consent pages must not be frameable (`frame-ancestors 'none'`) to
  prevent clickjacking. **Decision pending:** whether any embedding use case requires a
  controlled frame-ancestors allowlist.

## 10. Why React shadcn components are not directly usable

shadcn/ui is not a runtime component library. It is a set of source files that you copy into
a React project. Those files:

- are JSX/TSX and require a React runtime, a bundler, and a hydration or client-render
  pipeline;
- import React hooks (`useState`, `useEffect`, `useId`, context) and Radix UI primitives for
  behavior;
- rely on React context for dialog, dropdown, tooltip, and form composition;
- assume client-side state and event handlers, not server-rendered HTML fragments;
- are distributed through a CLI that expects a React/TypeScript project structure;
- use `class-variance-authority`, `clsx`, and `tailwind-merge` to compose classes at
  runtime.

Askama emits HTML strings at compile time. It has no component lifecycle, no hooks, no
context, and no client-side state. A React component cannot be called from an Askama
template. Rendering React on the server and hydrating it in the browser would add a Node
toolchain and a JavaScript runtime to a Rust product, complicate CSP, and create two UI
ownership models.

What is reusable:

- The visual design language: spacing, radii, borders, muted surfaces, focus rings.
- CSS custom-property tokens and Tailwind theme mappings.
- Variant names and class recipes, rewritten as Askama macros.
- Accessibility patterns and interaction intent, reimplemented with native elements.
- MIT-licensed source as a reference for markup and behavior. Porting code requires a
  rewrite, not a copy-paste.

What is not reusable without React:

- The component implementations themselves.
- Radix behavior primitives.
- React context composition and hooks.
- The shadcn CLI workflow.

## 11. Options if exact shadcn is mandatory

### Option A: Port the primitives (recommended)

Implement the needed primitives as Askama macros plus small vanilla modules, using native
`<dialog>`, `<details>`, popover, and form controls. Match shadcn's visual tokens closely.

- Pros: one Rust deployable, no hydration, strict CSP, accessible native foundations,
  consistent with Workers.
- Cons: behavior must be reimplemented and tested; visual parity is close but not
  pixel-identical; some complex components (combobox, data table) need custom work.
- Cost: moderate, contained, and paid once.

### Option B: Separate React admin SPA

Build the admin console as a React + shadcn application on its own origin, backed by a BFF
that holds the session and calls AuthKit.

- Pros: exact shadcn component availability; familiar React tooling for admin features.
- Cons: two UI stacks, two build systems, a Node toolchain, a second session/BFF surface,
  duplicated design tokens, more CSP and CSRF surface, and a heavier self-hosted footprint.
  The login and consent pages should remain server-rendered and first-party to avoid
  fragmenting the authentication origin.
- When: exact shadcn parity is a hard requirement and the team accepts the operational
  cost.

### Option C: React islands inside Askama pages

Mount React only for complex widgets (for example, a role-permission matrix) while keeping
the rest server-rendered.

- Pros: exact shadcn for the widget; less React than a full SPA.
- Cons: hydration boundaries, bundle splitting, CSP nonces, focus and state synchronization
  across the boundary, and two rendering models on one page. Usually more complex than
  either A or B.
- When: a few genuinely stateful widgets justify it.

### Option D: Web components or another headless library

Wrap behavior in web components or use a non-React headless library.

- Pros: framework-agnostic behavior if a mature library exists.
- Cons: it is still not shadcn; shadow DOM complicates Tailwind and forms; another
  dependency and accessibility surface.
- When: there is a proven, maintained library that fits the exact need.

### Decision

**Decision pending:** whether exact shadcn parity is a product requirement. The default is
Option A. The architecture keeps the UI layer replaceable: pages and fragments are
server-rendered and the API is separate, so a future React admin can be added without
changing the domain or OAuth endpoints. It must use its own host-only BFF session and must
not share parent-domain cookies.

## 12. Testing and quality gates

- Askama compilation is a build gate; template errors fail the build.
- Snapshot tests for pages and fragments using deterministic view models.
- HTMX integration tests: target IDs, swap behavior, validation errors, `HX-Trigger`
  headers, history updates, and 401 redirects.
- No-JavaScript browser tests for login, consent, member invitation, and client creation.
- Accessibility: axe checks on every page template plus manual keyboard and screen-reader
  passes for dialogs, menus, tables, and forms.
- Visual regression tests for light/dark themes and responsive breakpoints.
- CSP tests: fail if inline scripts, remote scripts, or `unsafe-eval` appear.
- CSRF tests: missing token, wrong token, cross-origin Origin header, GET mutation, and
  token rotation after login.
- Performance budget: CSS and JS are small, no render-blocking third-party assets, and
  pages remain usable on a slow connection.
- Workers compatibility: static assets, multiple Set-Cookie headers, and Askama rendering
  are included in the runtime spike checklist in [Runtime targets](runtime-targets.md).

## 13. Open UI decisions

- Exact shadcn parity versus shadcn-inspired primitives.
- Whether the admin console ever becomes a separate React application.
- Passkey and MFA enrollment UI scope.
- Dark mode default and theme persistence (cookie versus `prefers-color-scheme`).
- Internationalization and right-to-left layout. **Decision pending:** whether v1 is
  English-only.
- Rich text or Markdown rendering in audit metadata and descriptions; the default is plain
  text only.
- Backdrop dismissal for dirty dialog forms.
- Whether to vendor a tiny behavior library or keep all behavior in first-party modules.

See [Architecture](architecture.md) for the BFF and cookie decisions, and
[Standards](standards.md) for the login, consent, and logout protocol behavior these pages
implement.
