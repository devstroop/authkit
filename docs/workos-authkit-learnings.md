# Learnings from WorkOS/AuthKit

Source: https://github.com/workos/authkit and https://workos.com/docs/authkit

## Product model

- Two delivery modes: **hosted UI** (fastest, fully themeable, custom domain) and **custom UI** (headless User Management APIs, self-hosted).
- Auth methods: Email + Password, OAuth (Google/Microsoft/GitHub), **Magic Auth** (passwordless 6-digit code), SSO (SAML), Passkeys.
- Magic Link is deprecated in favor of Magic Auth because corporate email scanners programmatically click links and invalidate them.
- Multi-tenant B2B model: Organizations with memberships; users can belong to many orgs.
- Domain verification + domain policies: verified domains can enforce SSO for all matching users and auto-provision members.
- Admin Portal: hosted UI for customers to configure their own SSO connections.
- Organization selection: users with multiple memberships pick an org at sign-in.
- Impersonation: admins/support assume a user's identity for debugging.
- Testing: an open-source in-memory emulator of the WorkOS API for local/CI testing.

## Learnings applicable to AuthKit

1. **Magic Auth over Magic Link.** If we add passwordless, use short-lived numeric codes, not clickable links, to survive email security scanners. (We already have one-time tokens; a 6-digit code variant fits.)
2. **Organization-aware authentication.** Sign-in should resolve the user's organization context; support org selection when a user belongs to several. Our model has memberships but no org picker at login.
3. **Domain policies.** Verified domains can force SSO and auto-provision members. We have organizations and invitations but no domain verification or policy enforcement.
4. **Impersonation.** Useful for support; requires audit logging (we have audit hash chain) and a distinct session marker.
5. **Admin Portal pattern.** Let customers self-serve SSO configuration instead of manual admin work.
6. **Hosted vs. headless.** Keep both paths open: server-rendered pages (current) plus a clean HTTP API for custom frontends (we have OAuth/OIDC endpoints).
7. **In-memory test emulator.** A lightweight fake of our own API would speed up frontend/integration tests.
8. **Passkeys.** Domain support exists; ensure enrollment and login flows are exposed in the UI.
9. **Session/cookie hygiene.** WorkOS emphasizes automatic token refresh and session validation middleware (we have refresh families and CSRF).
10. **Accessibility.** Hosted UI is Radix-based; our templates should keep ARIA, focus management, and keyboard support (in progress).

## Suggested next features (priority order)

1. Magic Auth (passwordless email code) — reuses one-time token infrastructure.
2. Organization selection at sign-in for multi-org users.
3. Domain verification + domain policies for B2B SSO enforcement.
4. Impersonation with audit logging.
5. Passkey enrollment/login UI.
6. In-memory test emulator for the HTTP API.
