# Gap analysis: AuthKit vs Authentik and WorkOS AuthKit

Date: 2026-11-08
Scope: compare our AuthKit (`devstroop/authkit`) against `goauthentik/authentik` and `workos/authkit`, identify gaps, and recommend scope decisions. Written against our own product definition (`docs/product.md`) and roadmap (`docs/roadmap.md`), not as a feature-parity demand.

## 1. Positioning (read this first)

- **Our AuthKit**: small, self-hostable, narrow OIDC/OAuth 2.0 authorization server + tenant model, native Rust binary, SQLite/Postgres, server-rendered UI. Explicitly "not a drop-in replacement for Authentik, Keycloak, or Zitadel" and deliberately implements less.
- **Authentik**: full self-hosted IdP platform — flow/stage engine, SAML/LDAP/RADIUS/SCIM/proxy/RAC, policy engine, blueprints, outposts, enterprise governance. Python/Django core + Rust/Go outposts + Lit UI over Postgres.
- **WorkOS AuthKit**: hosted/headless identity platform consumed via SDK; Next.js example app demonstrating self-hosted UI on top of WorkOS User Management APIs.

Therefore many Authentik "gaps" are intentional non-goals (SAML, SCIM, LDAP, outposts, visual flow builder, enterprise lifecycle). The useful comparison is: (a) gaps against our own stated v1/after-v1 scope, (b) high-value features Authentik/WorkOS have that we could adopt without violating our principles, (c) developer-experience gaps vs WorkOS.

## 2. Where our AuthKit is strong (already implemented)

Authentication methods:
- Password (Argon2id), email verification, password reset, change password domain
- Magic link / passwordless email code (`/magic-auth`)
- Passkeys / WebAuthn (`/passkeys` routes, `CredentialKind::Passkey`)
- TOTP MFA + recovery codes + login challenge
- Admin MFA (enroll/verify/required)
- OIDC/OAuth 2.0: discovery, authorization code + PKCE, consent, token, userinfo, revocation, RP-initiated logout, JWKS, client credentials, refresh rotation/reuse detection

Tenancy / authorization:
- Organizations as tenants, applications as surfaces, memberships, invitations, domains, org selection, role bindings, OAuth clients, scopes, redirect URIs
- RBAC: Owner/Admin/Member + custom roles, application-scoped roles, granular permissions, last-owner protection

Admin / ops:
- First-run setup wizard, system administrators (super_admin/auditor), dashboard, users, impersonate/exit, audit browser, backup download, restore, signing key rotation
- Audit event hash chain + CLI export/prune/verify
- Metrics, health/readiness, security headers, request IDs
- Signing keys encrypted keyring + rotation + JWKS
- Backup/restore CLI (SQLite), migrate, doctor, bootstrap

Cross-cutting:
- Sessions (account/admin audiences, CSRF, host-only cookies, idle/absolute expiry, revoke)
- Rate limiting table
- Connected apps / consents revocation
- i18n (en + partial es) with middleware (Accept-Language, cookie, query)
- Email: dev logger + SMTP
- Server-rendered UI (Askama + HTMX), native `<dialog>` forms
- Property tests, load tests

## 3. Gaps against our own stated scope (product.md v1 / after v1)

These are the most important because they are commitments, not optional parity.

| # | Stated scope item | Status | Evidence |
|---|---|---|---|
| G1 | "Change an email address with re-verification and notification to the old address" (Identity and session use case) | **Not wired** | `User::change_email` exists in domain (`crates/authkit-core/src/domain/user.rs:155`), but no HTTP route/UI. Only `/account/verify-email` request flow. |
| G2 | "Upstream OIDC federation for deployments that need an external identity source" (after v1) | **Not implemented** | No social/OIDC source login, no `/login` federation. Authentik has OIDC/SAML/LDAP sources; WorkOS has GitHub/Google/Microsoft OAuth. We have none. This is "after v1" so acceptable, but it's the largest competitive gap for adoption. |
| G3 | "Passkeys/WebAuthn and TOTP MFA, if not included in v1" (after v1) | **Already implemented** (passkeys + TOTP) — ahead of plan. Good. |
| G4 | "An outbound webhook/event stream" (after v1) | **Not implemented** | No webhook/event stream. |
| G5 | "Optional introspection and opaque access tokens" (after v1) | **Not implemented** | JWT + JWKS only; introspection not present. |
| G6 | "A supported Cloudflare Workers profile" (after v1) | **Stub only** | `authkit-worker` is a stub with feature-gate notes. |
| G7 | "A migration/import toolkit" (after v1) | **Not implemented** | No import path for users/password hashes. |
| G8 | "Conformance evidence published" (M2 exit) | **Unknown/unverified** | No published conformance run artifact visible. |
| G9 | "Accessibility checklist (keyboard, focus, labels, error announcements)" (M3 exit) | **Partially** | UI work ongoing; not verified. |
| G10 | "Rate limits and lockouts behave correctly across restarts and multiple replicas" (M4) | **Partially** | DB-backed rate_limit_bucket exists; lockout semantics unverified. |
| G11 | "Email delivery: bounce handling, security notifications" (M4) | **Partial** | SMTP sender exists; no bounce handling or security-notification emails. |
| G12 | "Audit integrity, export, retention, redaction checks" (M4) | **Partial** | Hash chain + export/prune/verify CLI; retention/redaction not evident. |
| G13 | "Fuzzing/property tests for parsers, tokens, redirects, form handling" (M4) | **Partial** | proptest present; fuzzing not evident. |
| G14 | "Load tests for login, token exchange, refresh, JWKS" (M4) | **Present** | `load-tests/` exists. |

## 4. Gaps vs Authentik (intentional vs worth adopting)

Authentik is a much larger product; most of its surface is explicitly out of scope for us. The table separates intentional non-goals from features that would materially help our target users without violating "narrower than an enterprise IdP".

### 4.1 Intentional non-goals (do NOT adopt; documented in product.md "Not planned")

- SAML, SCIM, LDAP, enterprise directory suite
- Outposts / connectors / forward-auth proxy / per-app gateway
- Visual authentication-flow builder
- React SPA as default UI
- Parent-domain cookies / cross-subdomain sessions / implicit flow
- Billing / hosted SaaS control plane
- Enterprise governance: lifecycle/offboarding, access reviews, required actions, device trust (GDTC), mTLS stage, account lockdown

### 4.2 Worth evaluating (high value, low scope creep)

| Feature in Authentik | Why it matters for us | Effort / risk | Recommendation |
|---|---|---|---|
| **Policy engine (password strength, expiry, geoip, reputation, expression)** | We have Argon2 + verifier validation but no password-strength policy, expiry, or lockout policy config. Operators want configurable password rules. | Medium. Add a small policy table + evaluation hook in registration/password-change flows. | Adopt a *minimal* subset: password complexity policy + expiry. Skip expression/geoip/reputation (too enterprise). |
| **Branding per domain (title, logo, favicon, custom CSS, default flows)** | We have multi-tenant orgs but no per-org branding. Authentik's Brand model is a clean, well-scoped feature. | Medium. Add `brand` table keyed by domain/org + template variables. | Adopt. Fits "organizations as tenants". High UX value. |
| **Flow/stage orchestration** | Our flows are hard-coded routes. Authentik's flow engine is powerful but is explicitly a non-goal ("no visual flow builder"). | High. Would conflict with "boring beats clever". | Do not adopt the engine. Keep hard-coded flows. Maybe adopt the *concept* of configurable default flows per brand (login/recovery/unenrollment) as simple config, not a builder. |
| **Email stage for flows + authenticator email (MFA via email)** | We have magic link (email code) but no email-based MFA factor or email stage. | Low-medium. | Adopt email as an MFA factor (authenticator email) — useful for low-friction MFA. |
| **Notifications (in-app + email) with rules** | We have audit events but no user-facing notifications (e.g., "new sign-in", "password changed"). | Medium. | Adopt security notifications (new session, password change, email change) at minimum. Full notification rule engine is overkill. |
| **Blueprints (YAML declarative config)** | Nice for GitOps operators; but adds a config-management subsystem. | Medium-high. | Defer. Our CLI + TOML config covers most needs; blueprints risk scope creep. Revisit after v1. |
| **Social/OIDC source login (Google, GitHub, etc.)** | This is G2 (upstream federation). Authentik supports OIDC/SAML sources. | Medium. | Adopt as "upstream OIDC federation" (already planned after v1). Start with OIDC (not SAML). |
| **Device code grant** | Useful for CLI/TV auth. OAuth 2.0 device authorization. | Low-medium. | Adopt if demand; not in current scope. |
| **Token exchange grant** | Useful for service-to-service delegation. | Medium. | Defer; client credentials covers most. |
| **Dynamic client registration** | Useful for multi-tenant SaaS where tenants register their own clients. | Medium. | Defer; admin UI registration covers v1. |
| **Back/front-channel logout** | We have RP-initiated logout; back-channel logout is better for SPAs. | Medium. | Adopt back-channel logout (OIDC spec) — improves correctness. |
| **ML-DSA / post-quantum JWT algs** | Authentik added ML-DSA. Niche. | Low value now. | Skip. |
| **Impersonation / user switching sessions** | We have impersonate/exit. Authentik has dedicated switching sessions + audit. | Low. | Verify our impersonation audit events are complete; align naming. |
| **Property mappings** | Authentik lets admins map claims per provider. We have fixed scopes. | Medium. | Adopt configurable claim mapping for OIDC clients (after v1). |
| **Application entitlements** | Per-app access gating. | Medium. | Our role bindings already cover; document. |
| **File manager / crypto cert UI** | Authentik manages TLS certs in UI. We use env/encrypted DB keys. | Low value. | Skip; CLI key rotation is enough. |
| **Reports / analytics** | Authentik has reporting. | Medium. | Defer. |
| **Access requests / approvals** | Enterprise feature. | High. | Skip (out of scope). |
| **Endpoints / device trust** | Enterprise. | High. | Skip. |
| **Multi-brand (domain-based branding)** | See branding row. | Medium. | Adopt (as above). |

### 4.3 Authentik features we should NOT chase (reinforce non-goals)

Outposts, LDAP/RADIUS/RAC, SCIM, SAML, WS-Federation, SSF, blueprints-as-code engine, visual flow builder, expression policies, geoip/reputation, enterprise lifecycle, access reviews, device trust, mTLS. These conflict with "narrower than an enterprise IdP" and "boring beats clever".

## 5. Gaps vs WorkOS AuthKit (developer experience)

WorkOS is a hosted/headless platform; our comparison is about DX and feature expectations developers bring.

| WorkOS feature | Our status | Gap? |
|---|---|---|
| Email + password sign-up/sign-in | ✅ | No |
| Magic Auth (passwordless email code) | ✅ (`/magic-auth`) | No |
| OAuth social providers (GitHub/Google/Microsoft) | ❌ None | **Yes — largest DX gap.** Developers expect "Sign in with Google". Adopt as upstream OIDC federation (G2). Even a single provider (Google) would unblock many. |
| SSO (organization-scoped) | ❌ None | Partially covered by org model; no SAML/OIDC SSO brokering. Adopt OIDC SSO (after v1). |
| MFA (TOTP) | ✅ | No |
| Passkeys | ✅ (we have; WorkOS example doesn't) | We're ahead |
| Email verification | ✅ | No |
| Password reset | ✅ | No |
| User management (list/update/delete, pagination) | ✅ (admin users) | No |
| Session management (cookie/JWT patterns) | ✅ | No |
| Hosted UI theming via dashboard | N/A (we self-host UI) | Different model; our branding-per-domain (4.2) is the equivalent |
| i18n | ❌ None in WorkOS example; we have en+partial es | We're ahead (but incomplete) |
| Organization switching UI | ❌ (WorkOS has none in example either) | We have `/select-organization` — ahead |

Conclusion: the one big DX gap vs WorkOS is **social login**. Everything else we match or exceed.

## 6. Internal / quality gaps (not feature gaps)

| # | Issue | Severity | Notes |
|---|---|---|---|
| Q1 | i18n Spanish catalog is 165/335 keys (49%) — incomplete | Medium | Either finish es or drop the claim. Missing keys fall back to English silently. |
| Q2 | `set_locale` is a no-op (`crates/authkit-server/src/i18n.rs`) | Low | Task-local scope is used instead; dead-ish function. Clean up. |
| Q3 | Locale query param `lang` doesn't persist a cookie | Medium | Middleware reads cookie but nothing sets it from `lang`. Users can't persist language choice via URL. (From prior review.) |
| Q4 | Auth pages lost the language switcher UI | Medium | `auth.html` override emptied; base header switcher removed. No way to change language on auth pages. (From prior review.) |
| Q5 | `confirm_password` validation bypassable when field omitted | Medium | `if !confirm_password.is_empty() && ...` skips check. Should require presence. (From prior review.) |
| Q6 | Mismatch error message not localized | Low | Returns literal "Passwords do not match." |
| Q7 | `change_email` not wired to HTTP/UI | Medium | Domain ready; route + UI + email-to-old-address notification missing. |
| Q8 | Global layout changes (`base.html` flex/min-height) affect admin/app pages | Medium | Verify admin/app still look correct; scope if needed. (From prior review.) |
| Q9 | Button width change (removed `.btn-primary { width: auto }`) affects all forms | Low-Medium | Verify intended; admin uses inline style. (From prior review.) |
| Q10 | Email adapter has no bounce handling / security notifications | Medium | Listed in M4 scope. |
| Q11 | Audit retention/redaction not evident | Medium | Listed in M4 scope. |
| Q12 | No fuzzing harness | Low-Medium | Listed in M4 scope. |
| Q13 | Workers profile is a stub | Low (after v1) | R1/R2 decisions pending. |
| Q14 | Naming/trademark review (P1) open | Governance | Blocks public launch. |
| Q15 | MFA-in-v1 decision (P3) still RFC | Governance | Passkeys+TOTP already shipped, so effectively resolved in favor of "both" — update register. |
| Q16 | No published OIDC conformance evidence | Medium | M2 exit criterion. |
| Q17 | No second maintainer / security reviewer named | Governance | 1.0 gate. |

## 7. Recommended scope decisions (prioritized)

### Do now (before 1.0, fits v1)
1. Wire `change_email` end-to-end (G1) — domain already there; add route, UI, verification email, notify old address, revoke other sessions. Closes a stated v1 use case.
2. Fix i18n quality: finish Spanish or trim claim; persist `lang` cookie; restore language switcher on auth pages; localize "Passwords do not match." (Q1–Q6).
3. Make `confirm_password` required + non-empty (Q5).
4. Add back-channel logout + configurable claim mapping groundwork (4.2).
5. Adopt minimal password policy (complexity + expiry) (4.2).
6. Add security notifications: new session, password change, email change (4.2).
7. Adopt email as an MFA factor (authenticator email) (4.2).
8. Add per-domain/org branding (title, logo, favicon, custom CSS) (4.2) — high UX value, fits tenant model.
9. Verify global layout changes don't break admin/app (Q8/Q9); scope if needed.
10. Publish OIDC conformance evidence (Q16); complete accessibility checklist (Q9? G9).

### Do after v1 (already planned; sequence)
11. Upstream OIDC federation (social login: Google first) (G2) — biggest DX gap.
12. Outbound webhook/event stream (G4).
13. Introspection + opaque tokens (G5).
14. Migration/import toolkit (G7).
15. Workers profile completion (G6).
16. Device code grant, dynamic client registration, property mappings (4.2, on demand).

### Explicitly skip (reinforce non-goals)
SAML, SCIM, LDAP, RADIUS, outposts, proxy/forward-auth, visual flow builder, SPA default UI, expression/geoip/reputation policies, enterprise lifecycle/access reviews/device trust/mTLS, blueprints engine, post-quantum JWT algs, hosted control plane, billing.

## 8. One-line summary

Our AuthKit is on track for its stated narrow scope and already exceeds both references on passkeys, i18n scaffolding, org/role model, audit hash chain, and operability (single binary + SQLite). The two highest-impact gaps to close before 1.0 are (1) the unwired `change_email` flow and (2) i18n completeness/UX; the biggest competitive gap to plan for after v1 is social/OIDC federation (Google sign-in). Everything Authentik does beyond that is, by our own product definition, out of scope.
