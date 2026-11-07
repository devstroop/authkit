# UI/UX Audit and Roadmap

## Current state

All server-rendered pages now use Askama templates extending a shared base layout with
design tokens, HTMX, skip links, focus styles, and ARIA landmarks. Remaining gaps are
listed below.

## Page inventory (status)

| Area | Page | Template | Status |
|------|------|----------|--------|
| Auth | login | pages/login.html | migrated, macros applied |
| Auth | register | pages/register.html | migrated, macros applied |
| Auth | MFA challenge | pages/mfa_challenge.html | migrated |
| Auth | reset request/confirm | pages/request_reset.html, confirm_reset.html | migrated |
| Auth | verify email | pages/request_verify.html, verify_email.html | migrated |
| Account | sessions/password/MFA/recovery | pages/account.html, mfa_enroll.html, recovery_codes*.html | migrated, partial macros |
| Account | connected apps | pages/connected_apps.html | migrated |
| Account | profile | pages/profile.html | migrated |
| Organizations | list/members/invitations/roles/applications/oauth clients | pages/*.html | migrated, HTMX fragments added |
| Admin | login/dashboard/MFA | pages/admin*.html | migrated, macros applied |
| Admin | audit review, signing keys, bootstrap, backups | (handlers) | partial raw HTML in handlers |
| OAuth | consent/error | pages/authorize_consent.html, authorize_error.html | migrated |

## Identified gaps

### 1. Admin area (huge)
- Audit review page: raw HTML in handler, no pagination/filter UI.
- Signing key list: no rotation history, no copy-to-clipboard.
- Bootstrap flow: CLI only; no web bootstrap wizard.
- Backup/restore: CLI only; no web UI.
- MFA enrollment for admins: works but no recovery-code display styling.
- No admin navigation/sidebar; each page is standalone.
- No breadcrumbs, no search, no bulk actions.
- No role-based admin views (all admins see everything).

### 2. UI/UX consistency
- Inconsistent use of macros across pages (some still raw inputs).
- No empty states, loading skeletons, or error boundaries.
- No toast/notification system for HTMX actions.
- No responsive navigation; mobile untested.
- Forms lack inline validation feedback.
- No dark-mode toggle (only prefers-color-scheme).
- No i18n/localization hooks.

### 3. Missing features vs. WorkOS/Authentik
- Magic Auth (passwordless email code).
- Organization selection at sign-in for multi-org users.
- Domain verification + domain policies.
- Impersonation (admin assumes user).
- Passkey enrollment/login UI (domain support exists).
- SSO/SAML (out of scope for now).
- In-memory test emulator for HTTP API.

### 4. Accessibility
- Focus management on HTMX swaps (done).
- Need: aria-live regions, form error association, keyboard shortcuts, screen-reader testing.
- Color contrast audit for dark mode.

## Phased plan

### Phase A — Finish UI consistency (1-2 sprints)
- Apply macros to remaining pages (members, invitations, roles, applications, oauth clients, account).
- Add empty states and loading indicators.
- Add toast notifications for HTMX actions.
- Add admin sidebar navigation and breadcrumbs.

### Phase B — Admin completeness
- Web UI for audit review with filters/pagination.
- Web UI for backup/restore.
- Web bootstrap wizard.
- Admin role-based views.

### Phase C — New features
- Magic Auth (passwordless).
- Organization selection at sign-in.
- Passkey UI.
- Impersonation.

### Phase D — Polish
- Dark-mode toggle.
- i18n.
- Responsive/mobile.
- Accessibility audit + screen-reader testing.

## Immediate next actions
1. Apply macros to remaining organization pages.
2. Add admin sidebar + breadcrumbs.
3. Implement Magic Auth as first new feature.
