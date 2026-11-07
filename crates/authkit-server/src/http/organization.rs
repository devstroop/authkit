//! Organization administration pages.

use authkit_core::domain::{
    Application, ApplicationKind, ClientId, ClientType, DisplayName, DomainError, Email, GrantType, Id, Membership, OAuthClient, OAuthClientSpec, Permission,
    PermissionSet, RedirectUri, Role, RoleBinding, Scope, ScopeSet, Slug, TenantContext, TokenEndpointAuthMethod, WriteOutcome,
};
use authkit_core::domain::id::{InvitationEntity, OrganizationEntity, RoleBindingEntity, RoleEntity, UserEntity};
use base64::Engine;
use authkit_core::domain::invitation::Invitation;
use authkit_core::ports::{ApplicationRepository, IdGenerator, InvitationRepository, MembershipRepository, OAuthClientRepository, OrganizationRepository, RoleBindingRepository, RoleRepository, UserRepository};
use authkit_core::application::CreateOrganization;
use axum::extract::{Extension, Path, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};

use crate::http::routes::AppState;
use crate::http::session::SessionContext;
use crate::session::{SecureIdGenerator, SystemClock};

pub(crate) async fn organizations_page(
    State(state): State<AppState>,
    session: Option<Extension<SessionContext>>,
) -> Response {
    let Some(Extension(session)) = session else {
        return redirect("/login");
    };
    let Some(sessions) = state.sessions.as_ref() else {
        return unavailable();
    };
    let user_id = session.session().user_id().clone();
    let store = sessions.store().clone();
    let csrf = sessions.csrf_token(session.session());
    let memberships = tokio::task::spawn_blocking({
        let store = store.clone();
        let user_id = user_id.clone();
        move || MembershipRepository::list_for_user(store.as_ref(), &user_id)
    })
    .await
    .ok()
    .and_then(|r| r.ok())
    .unwrap_or_default();

    let mut rows = String::new();
    for m in memberships {
        if !m.is_active() {
            continue;
        }
        let org = tokio::task::spawn_blocking({
            let store = store.clone();
            let org_id = m.organization_id().clone();
            move || OrganizationRepository::find_by_id(store.as_ref(), &org_id)
        })
        .await
        .ok()
        .and_then(|r| r.ok().flatten());
        if let Some(org) = org {
            rows.push_str(&format!(
                "<li>{} ({}) <a href=\"/organizations/{}/members\">Manage</a></li>",
                escape(org.name().as_str()),
                escape(org.slug().as_str()),
                org.id().as_str()
            ));
        }
    }

    let body = format!(
        r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Organizations</title></head><body style="font-family: system-ui, sans-serif; max-width: 40rem; margin: 4rem auto; padding: 0 1rem;">
<h1>Organizations</h1>
<ul>{rows}</ul>
<h2>Create organization</h2>
<form method="post" action="/organizations">
<input type="hidden" name="_csrf" value="{csrf}">
<label>Slug <input name="slug" required></label><br>
<label>Name <input name="name" required></label><br>
<button type="submit">Create</button>
</form>
</body></html>"#,
        rows = rows,
        csrf = escape(&csrf)
    );
    html_ok(&body)
}

pub(crate) async fn create_organization(
    State(state): State<AppState>,
    session: Option<Extension<SessionContext>>,
    body: axum::body::Bytes,
) -> Response {
    let Some(Extension(session)) = session else {
        return redirect("/login");
    };
    let Some(sessions) = state.sessions.as_ref() else {
        return unavailable();
    };
    let mut params = parse_form(&body);
    let slug = params.remove("slug").unwrap_or_default();
    let name = params.remove("name").unwrap_or_default();
    let slug = match Slug::parse(&slug) {
        Ok(v) => v,
        Err(_) => return bad_request(),
    };
    let name = match DisplayName::parse(&name) {
        Ok(v) => v,
        Err(_) => return bad_request(),
    };
    let store = sessions.store().clone();
    let user_id = session.session().user_id().clone();
    let result = tokio::task::spawn_blocking(move || {
        let uc = CreateOrganization {
            slug,
            name,
            owner_id: user_id,
        };
        uc.execute(store.as_ref(), &SystemClock, &SecureIdGenerator)
    })
    .await;
    if result.ok().and_then(|r| r.ok()).is_some() {
        redirect("/organizations")
    } else {
        unavailable()
    }
}

pub(crate) async fn members_page(
    State(state): State<AppState>,
    session: Option<Extension<SessionContext>>,
    Path(org_id): Path<String>,
) -> Response {
    let Some(Extension(session)) = session else {
        return redirect("/login");
    };
    let Some(sessions) = state.sessions.as_ref() else {
        return unavailable();
    };
    let org_id = match Id::<OrganizationEntity>::parse(&org_id) {
        Ok(v) => v,
        Err(_) => return bad_request(),
    };
    let user_id = session.session().user_id().clone();
    let store = sessions.store().clone();
    let csrf = sessions.csrf_token(session.session());
    if !can_manage_members(&store, &user_id, &org_id) && !can_read_members(&store, &user_id, &org_id) {
        return forbidden();
    }
    let tenant = TenantContext::new(org_id.clone());
    let memberships = tokio::task::spawn_blocking({
        let store = store.clone();
        let tenant = tenant.clone();
        move || MembershipRepository::list(store.as_ref(), &tenant)
    })
    .await
    .ok()
    .and_then(|r| r.ok())
    .unwrap_or_default();

    let mut rows = String::new();
    for m in memberships {
        let email = tokio::task::spawn_blocking({
            let store = store.clone();
            let uid = m.user_id().clone();
            move || UserRepository::find_by_id(store.as_ref(), &uid).ok().flatten().map(|u| u.email().as_str().to_owned()).unwrap_or_default()
        })
        .await
        .unwrap_or_default();
        rows.push_str(&format!(
            "<li>{} {} ({})</li>",
            escape(&email),
            m.status_label(),
            m.id().as_str()
        ));
    }

    let can_manage = can_manage_members(&store, &user_id, &org_id);
    let manage_form = if can_manage {
        format!(
            r#"<h2>Add member</h2><form method="post" action="/organizations/{}/members"><input type="hidden" name="_csrf" value="{}"><label>User email <input name="email" type="email" required></label><button type="submit">Add</button></form>"#,
            org_id.as_str(),
            escape(&csrf)
        )
    } else {
        String::new()
    };

    let body = format!(
        r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Members</title></head><body style="font-family: system-ui, sans-serif; max-width: 40rem; margin: 4rem auto; padding: 0 1rem;">
<h1>Members</h1>
<ul>{rows}</ul>
{manage_form}
<p><a href="/organizations/{org_id}/invitations">Invitations</a> | <a href="/organizations/{org_id2}/roles">Roles</a></p>
</body></html>"#,
        rows = rows,
        manage_form = manage_form,
        org_id = org_id.as_str(),
        org_id2 = org_id.as_str()
    );
    html_ok(&body)
}

pub(crate) async fn add_member(
    State(state): State<AppState>,
    session: Option<Extension<SessionContext>>,
    Path(org_id): Path<String>,
    body: axum::body::Bytes,
) -> Response {
    let Some(Extension(session)) = session else {
        return redirect("/login");
    };
    let Some(sessions) = state.sessions.as_ref() else {
        return unavailable();
    };
    let org_id = match Id::<OrganizationEntity>::parse(&org_id) {
        Ok(v) => v,
        Err(_) => return bad_request(),
    };
    let user_id = session.session().user_id().clone();
    let store = sessions.store().clone();
    if !can_manage_members(&store, &user_id, &org_id) {
        return forbidden();
    }
    let mut params = parse_form(&body);
    let email_str = params.remove("email").unwrap_or_default();
    let email = match Email::parse(&email_str) {
        Ok(v) => v,
        Err(_) => return bad_request(),
    };
    let target_user = match tokio::task::spawn_blocking({
        let store = store.clone();
        let email = email.clone();
        move || UserRepository::find_by_email(store.as_ref(), &email)
    })
    .await
    .ok()
    .and_then(|r| r.ok().flatten())
    {
        Some(u) => u,
        None => return bad_request(),
    };
    let tenant = TenantContext::new(org_id.clone());
    let result = tokio::task::spawn_blocking({
        let store = store.clone();
        let tenant = tenant.clone();
        let target_id = target_user.id().clone();
        move || {
            let uc = authkit_core::application::AddMembership {
                tenant,
                user_id: target_id,
            };
            uc.execute(store.as_ref(), &SystemClock, &SecureIdGenerator)
        }
    })
    .await;
    if result.ok().and_then(|r| r.ok()).is_some() {
        redirect(&format!("/organizations/{}/members", org_id.as_str()))
    } else {
        unavailable()
    }
}

pub(crate) async fn invitations_page(
    State(state): State<AppState>,
    session: Option<Extension<SessionContext>>,
    Path(org_id): Path<String>,
) -> Response {
    let Some(Extension(session)) = session else {
        return redirect("/login");
    };
    let Some(sessions) = state.sessions.as_ref() else {
        return unavailable();
    };
    let org_id = match Id::<OrganizationEntity>::parse(&org_id) {
        Ok(v) => v,
        Err(_) => return bad_request(),
    };
    let user_id = session.session().user_id().clone();
    let store = sessions.store().clone();
    let csrf = sessions.csrf_token(session.session());
    if !can_read_members(&store, &user_id, &org_id) {
        return forbidden();
    }
    let tenant = TenantContext::new(org_id.clone());
    let invitations = tokio::task::spawn_blocking({
        let store = store.clone();
        let tenant = tenant.clone();
        move || InvitationRepository::list(store.as_ref(), &tenant)
    })
    .await
    .ok()
    .and_then(|r| r.ok())
    .unwrap_or_default();
    let roles = tokio::task::spawn_blocking({
        let store = store.clone();
        let tenant = tenant.clone();
        move || RoleRepository::list(store.as_ref(), &tenant)
    })
    .await
    .ok()
    .and_then(|r| r.ok())
    .unwrap_or_default();

    let mut rows = String::new();
    for inv in invitations {
        rows.push_str(&format!(
            "<li>{} {} <form method=\"post\" action=\"/organizations/{}/invitations/{}/revoke\" style=\"display:inline\"><input type=\"hidden\" name=\"_csrf\" value=\"{}\"><button type=\"submit\">Revoke</button></form></li>",
            escape(inv.email().as_str()),
            inv.status_label(),
            org_id.as_str(),
            inv.id().as_str(),
            escape(&csrf)
        ));
    }
    let mut role_options = String::new();
    for r in roles {
        role_options.push_str(&format!(
            "<option value=\"{}\">{}</option>",
            r.id().as_str(),
            escape(r.name().as_str())
        ));
    }
    let can_manage = can_manage_members(&store, &user_id, &org_id);
    let create_form = if can_manage {
        format!(
            r#"<h2>Invite member</h2><form method="post" action="/organizations/{}/invitations"><input type="hidden" name="_csrf" value="{}"><label>Email <input name="email" type="email" required></label><br><label>Role <select name="role_id">{}</select></label><br><button type="submit">Invite</button></form>"#,
            org_id.as_str(),
            escape(&csrf),
            role_options
        )
    } else {
        String::new()
    };

    let body = format!(
        r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Invitations</title></head><body style="font-family: system-ui, sans-serif; max-width: 40rem; margin: 4rem auto; padding: 0 1rem;">
<h1>Invitations</h1>
<ul>{rows}</ul>
{create_form}
<p><a href="/organizations/{org_id}/members">Members</a></p>
</body></html>"#,
        rows = rows,
        create_form = create_form,
        org_id = org_id.as_str()
    );
    html_ok(&body)
}

pub(crate) async fn create_invitation(
    State(state): State<AppState>,
    session: Option<Extension<SessionContext>>,
    Path(org_id): Path<String>,
    body: axum::body::Bytes,
) -> Response {
    let Some(Extension(session)) = session else {
        return redirect("/login");
    };
    let Some(sessions) = state.sessions.as_ref() else {
        return unavailable();
    };
    let org_id = match Id::<OrganizationEntity>::parse(&org_id) {
        Ok(v) => v,
        Err(_) => return bad_request(),
    };
    let user_id = session.session().user_id().clone();
    let store = sessions.store().clone();
    if !can_manage_members(&store, &user_id, &org_id) {
        return forbidden();
    }
    let mut params = parse_form(&body);
    let email_str = params.remove("email").unwrap_or_default();
    let role_id_str = params.remove("role_id").unwrap_or_default();
    let email = match Email::parse(&email_str) {
        Ok(v) => v,
        Err(_) => return bad_request(),
    };
    let role_id = match Id::<RoleEntity>::parse(&role_id_str) {
        Ok(v) => v,
        Err(_) => return bad_request(),
    };
    let tenant = TenantContext::new(org_id.clone());
    let now = sessions.clock().now();
    let pepper = sessions.pepper().to_vec();
    let token_plain = random_token();
    let token_hash = hash_token(&token_plain, &pepper);
    let expires = authkit_core::domain::time::Timestamp::from_millis(
        now.as_millis().saturating_add(7 * 24 * 60 * 60 * 1000),
    );
    let org_id_for_task = org_id.clone();
    let result = tokio::task::spawn_blocking({
        let store = store.clone();
        let tenant = tenant.clone();
        let email = email.clone();
        let token_hash = token_hash.clone();
        let role_id = role_id.clone();
        let user_id = user_id.clone();
        let now = now;
        let expires = expires;
        let org_id = org_id_for_task.clone();
        move || {
            let invitation = Invitation::new(
                SecureIdGenerator.generate::<InvitationEntity>().expect("id"),
                org_id.clone(),
                email,
                token_hash,
                vec![role_id],
                user_id,
                now,
                expires,
            )
            .map_err(|_| DomainError::invalid("invitation"))?;
            InvitationRepository::insert(store.as_ref(), &tenant, &invitation)
                .map(|_| (invitation, token_plain))
        }
    })
    .await;

    match result {
        Ok(Ok((_invitation, token))) => {
            // Dev-only token logging.
            #[cfg(debug_assertions)]
            tracing::debug!(invitation_token = %token, "dev-only invitation token");
            redirect(&format!("/organizations/{}/invitations", org_id.as_str()))
        }
        _ => unavailable(),
    }
}

pub(crate) async fn revoke_invitation(
    State(state): State<AppState>,
    session: Option<Extension<SessionContext>>,
    Path((org_id, invitation_id)): Path<(String, String)>,
    _body: axum::body::Bytes,
) -> Response {
    let Some(Extension(session)) = session else {
        return redirect("/login");
    };
    let Some(sessions) = state.sessions.as_ref() else {
        return unavailable();
    };
    let org_id = match Id::<OrganizationEntity>::parse(&org_id) {
        Ok(v) => v,
        Err(_) => return bad_request(),
    };
    let invitation_id = match Id::<InvitationEntity>::parse(&invitation_id) {
        Ok(v) => v,
        Err(_) => return bad_request(),
    };
    let user_id = session.session().user_id().clone();
    let store = sessions.store().clone();
    if !can_manage_members(&store, &user_id, &org_id) {
        return forbidden();
    }
    let tenant = TenantContext::new(org_id.clone());
    let now = sessions.clock().now();
    let outcome = tokio::task::spawn_blocking({
        let store = store.clone();
        let tenant = tenant.clone();
        let invitation_id = invitation_id.clone();
        let now = now;
        move || {
            if let Some(mut inv) = InvitationRepository::find_by_id(store.as_ref(), &tenant, &invitation_id)? {
                let expected = inv.version();
                inv.revoke(now)?;
                InvitationRepository::update(store.as_ref(), &tenant, &inv, expected)
            } else {
                Ok(WriteOutcome::NotFound)
            }
        }
    })
    .await;
    if outcome.ok().and_then(|r| r.ok()).map(|o| o.is_applied()).unwrap_or(false) {
        redirect(&format!("/organizations/{}/invitations", org_id.as_str()))
    } else {
        unavailable()
    }
}

pub(crate) async fn roles_page(
    State(state): State<AppState>,
    session: Option<Extension<SessionContext>>,
    Path(org_id): Path<String>,
) -> Response {
    let Some(Extension(session)) = session else {
        return redirect("/login");
    };
    let Some(sessions) = state.sessions.as_ref() else {
        return unavailable();
    };
    let org_id = match Id::<OrganizationEntity>::parse(&org_id) {
        Ok(v) => v,
        Err(_) => return bad_request(),
    };
    let user_id = session.session().user_id().clone();
    let store = sessions.store().clone();
    let csrf = sessions.csrf_token(session.session());
    if !can_read_members(&store, &user_id, &org_id) {
        return forbidden();
    }
    let tenant = TenantContext::new(org_id.clone());
    let roles = tokio::task::spawn_blocking({
        let store = store.clone();
        let tenant = tenant.clone();
        move || RoleRepository::list(store.as_ref(), &tenant)
    })
    .await
    .ok()
    .and_then(|r| r.ok())
    .unwrap_or_default();
    let mut rows = String::new();
    for r in roles {
        rows.push_str(&format!(
            "<li>{} ({}) - {}</li>",
            escape(r.name().as_str()),
            escape(r.slug().as_str()),
            escape(&r.permissions().as_slice().iter().map(|p| p.as_str()).collect::<Vec<_>>().join(", "))
        ));
    }
    let can_manage = can_manage_members(&store, &user_id, &org_id);
    let create_form = if can_manage {
        format!(
            r#"<h2>Create role</h2><form method="post" action="/organizations/{}/roles"><input type="hidden" name="_csrf" value="{}"><label>Slug <input name="slug" required></label><br><label>Name <input name="name" required></label><br><label>Permissions (space-separated) <input name="permissions"></label><br><button type="submit">Create</button></form>"#,
            org_id.as_str(),
            escape(&csrf)
        )
    } else {
        String::new()
    };
    let body = format!(
        r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Roles</title></head><body style="font-family: system-ui, sans-serif; max-width: 40rem; margin: 4rem auto; padding: 0 1rem;">
<h1>Roles</h1>
<ul>{rows}</ul>
{create_form}
<p><a href="/organizations/{org_id}/members">Members</a></p>
</body></html>"#,
        rows = rows,
        create_form = create_form,
        org_id = org_id.as_str()
    );
    html_ok(&body)
}

pub(crate) async fn create_role(
    State(state): State<AppState>,
    session: Option<Extension<SessionContext>>,
    Path(org_id): Path<String>,
    body: axum::body::Bytes,
) -> Response {
    let Some(Extension(session)) = session else {
        return redirect("/login");
    };
    let Some(sessions) = state.sessions.as_ref() else {
        return unavailable();
    };
    let org_id = match Id::<OrganizationEntity>::parse(&org_id) {
        Ok(v) => v,
        Err(_) => return bad_request(),
    };
    let user_id = session.session().user_id().clone();
    let store = sessions.store().clone();
    if !can_manage_members(&store, &user_id, &org_id) {
        return forbidden();
    }
    let mut params = parse_form(&body);
    let slug_str = params.remove("slug").unwrap_or_default();
    let name_str = params.remove("name").unwrap_or_default();
    let perms_str = params.remove("permissions").unwrap_or_default();
    let slug = match Slug::parse(&slug_str) {
        Ok(v) => v,
        Err(_) => return bad_request(),
    };
    let name = match DisplayName::parse(&name_str) {
        Ok(v) => v,
        Err(_) => return bad_request(),
    };
    let permissions: Vec<Permission> = perms_str
        .split_whitespace()
        .filter_map(|p| Permission::parse(p).ok())
        .collect();
    let permission_set = PermissionSet::new(permissions);
    let tenant = TenantContext::new(org_id.clone());
    let now = sessions.clock().now();
    let org_id_for_task = org_id.clone();
    let result = tokio::task::spawn_blocking({
        let store = store.clone();
        let tenant = tenant.clone();
        let slug = slug.clone();
        let name = name.clone();
        let permission_set = permission_set.clone();
        let now = now;
        let org_id = org_id_for_task.clone();
        move || {
            let role = Role::custom(
                SecureIdGenerator.generate::<RoleEntity>().expect("id"),
                org_id.clone(),
                None,
                slug,
                name,
                None,
                permission_set,
                now,
            )
            .map_err(|_| DomainError::invalid("role"))?;
            RoleRepository::insert(store.as_ref(), &tenant, &role)
        }
    })
    .await;
    if result.ok().and_then(|r| r.ok()).map(|o| o.is_applied()).unwrap_or(false) {
        redirect(&format!("/organizations/{}/roles", org_id.as_str()))
    } else {
        unavailable()
    }
}

pub(crate) async fn bind_role(
    State(state): State<AppState>,
    session: Option<Extension<SessionContext>>,
    Path(org_id): Path<String>,
    body: axum::body::Bytes,
) -> Response {
    let Some(Extension(session)) = session else {
        return redirect("/login");
    };
    let Some(sessions) = state.sessions.as_ref() else {
        return unavailable();
    };
    let org_id = match Id::<OrganizationEntity>::parse(&org_id) {
        Ok(v) => v,
        Err(_) => return bad_request(),
    };
    let user_id = session.session().user_id().clone();
    let store = sessions.store().clone();
    if !can_manage_members(&store, &user_id, &org_id) {
        return forbidden();
    }
    let mut params = parse_form(&body);
    let email_str = params.remove("email").unwrap_or_default();
    let role_id_str = params.remove("role_id").unwrap_or_default();
    let email = match Email::parse(&email_str) {
        Ok(v) => v,
        Err(_) => return bad_request(),
    };
    let role_id = match Id::<RoleEntity>::parse(&role_id_str) {
        Ok(v) => v,
        Err(_) => return bad_request(),
    };
    let target_user = match tokio::task::spawn_blocking({
        let store = store.clone();
        let email = email.clone();
        move || UserRepository::find_by_email(store.as_ref(), &email)
    })
    .await
    .ok()
    .and_then(|r| r.ok().flatten())
    {
        Some(u) => u,
        None => return bad_request(),
    };
    let tenant = TenantContext::new(org_id.clone());
    let now = sessions.clock().now();
    let org_id_for_task = org_id.clone();
    let outcome = tokio::task::spawn_blocking({
        let store = store.clone();
        let tenant = tenant.clone();
        let role_id = role_id.clone();
        let target_id = target_user.id().clone();
        let now = now;
        let org_id = org_id_for_task.clone();
        move || {
            let binding = RoleBinding::organization(
                SecureIdGenerator.generate::<RoleBindingEntity>().expect("id"),
                org_id.clone(),
                role_id,
                target_id,
                now,
            );
            RoleBindingRepository::insert(store.as_ref(), &tenant, &binding)
        }
    })
    .await;
    if outcome.ok().and_then(|r| r.ok()).map(|o| o.is_applied()).unwrap_or(false) {
        redirect(&format!("/organizations/{}/roles", org_id.as_str()))
    } else {
        unavailable()
    }
}


pub(crate) async fn applications_page(
    State(state): State<AppState>,
    session: Option<Extension<SessionContext>>,
    Path(org_id): Path<String>,
) -> Response {
    let Some(Extension(session)) = session else { return redirect("/login"); };
    let Some(sessions) = state.sessions.as_ref() else { return unavailable(); };
    let org_id = match Id::<OrganizationEntity>::parse(&org_id) { Ok(v)=>v, Err(_)=>return bad_request() };
    let user_id = session.session().user_id().clone();
    let store = sessions.store().clone();
    let csrf = sessions.csrf_token(session.session());
    if !can_read_members(&store, &user_id, &org_id) { return forbidden(); }
    let tenant = TenantContext::new(org_id.clone());
    let apps = tokio::task::spawn_blocking({
        let store=store.clone(); let tenant=tenant.clone();
        move || ApplicationRepository::list(store.as_ref(), &tenant)
    }).await.ok().and_then(|r|r.ok()).unwrap_or_default();
    let mut rows = String::new();
    for a in apps {
        rows.push_str(&format!("<li>{} ({}) {} {}</li>", escape(a.name().as_str()), escape(a.slug().as_str()), format!("{:?}", a.kind()), if a.is_active() { "active" } else { "disabled" }));
    }
    let can_manage = can_manage_members(&store, &user_id, &org_id);
    let form = if can_manage {
        format!(r#"<h2>Create application</h2><form method="post" action="/organizations/{}/applications"><input type="hidden" name="_csrf" value="{}"><label>Slug <input name="slug" required></label><br><label>Name <input name="name" required></label><br><label>Kind <select name="kind"><option value="web">web</option><option value="admin">admin</option><option value="native">native</option><option value="service">service</option><option value="cli">cli</option></select></label><br><label><input type="checkbox" name="first_party" value="true"> First-party</label><br><button type="submit">Create</button></form>"#, org_id.as_str(), escape(&csrf))
    } else { String::new() };
    let body = format!(r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Applications</title></head><body style="font-family: system-ui, sans-serif; max-width: 40rem; margin: 4rem auto; padding: 0 1rem;"><h1>Applications</h1><ul>{}</ul>{}<p><a href="/organizations/{}/members">Members</a></p></body></html>"#, rows, form, org_id.as_str());
    html_ok(&body)
}

pub(crate) async fn create_application(
    State(state): State<AppState>,
    session: Option<Extension<SessionContext>>,
    Path(org_id): Path<String>,
    body: axum::body::Bytes,
) -> Response {
    let Some(Extension(session)) = session else { return redirect("/login"); };
    let Some(sessions) = state.sessions.as_ref() else { return unavailable(); };
    let org_id = match Id::<OrganizationEntity>::parse(&org_id) { Ok(v)=>v, Err(_)=>return bad_request() };
    let user_id = session.session().user_id().clone();
    let store = sessions.store().clone();
    if !can_manage_members(&store, &user_id, &org_id) { return forbidden(); }
    let mut params = parse_form(&body);
    let slug_str = params.remove("slug").unwrap_or_default();
    let name_str = params.remove("name").unwrap_or_default();
    let kind_str = params.remove("kind").unwrap_or_default();
    let first_party = params.remove("first_party").unwrap_or_default() == "true";
    let slug = match Slug::parse(&slug_str) { Ok(v)=>v, Err(_)=>return bad_request() };
    let name = match DisplayName::parse(&name_str) { Ok(v)=>v, Err(_)=>return bad_request() };
    let kind = match kind_str.as_str() {
        "web" => ApplicationKind::Web,
        "admin" => ApplicationKind::Admin,
        "native" => ApplicationKind::Native,
        "service" => ApplicationKind::Service,
        "cli" => ApplicationKind::Cli,
        _ => return bad_request(),
    };
    let tenant = TenantContext::new(org_id.clone());
    let result = tokio::task::spawn_blocking({
        let store=store.clone(); let tenant=tenant.clone(); let slug=slug.clone(); let name=name.clone();
        move || {
            let uc = authkit_core::application::CreateApplication { tenant, slug, name, kind, first_party };
            uc.execute(store.as_ref(), &SystemClock, &SecureIdGenerator)
        }
    }).await;
    if result.ok().and_then(|r|r.ok()).is_some() {
        redirect(&format!("/organizations/{}/applications", org_id.as_str()))
    } else {
        unavailable()
    }
}


pub(crate) async fn oauth_clients_page(
    State(state): State<AppState>,
    session: Option<Extension<SessionContext>>,
    Path(org_id): Path<String>,
) -> Response {
    let Some(Extension(session)) = session else { return redirect("/login"); };
    let Some(sessions) = state.sessions.as_ref() else { return unavailable(); };
    let org_id = match Id::<OrganizationEntity>::parse(&org_id) { Ok(v)=>v, Err(_)=>return bad_request() };
    let user_id = session.session().user_id().clone();
    let store = sessions.store().clone();
    let csrf = sessions.csrf_token(session.session());
    if !can_read_members(&store, &user_id, &org_id) { return forbidden(); }
    let tenant = TenantContext::new(org_id.clone());
    let clients = tokio::task::spawn_blocking({
        let store=store.clone(); let tenant=tenant.clone();
        move || OAuthClientRepository::list(store.as_ref(), &tenant)
    }).await.ok().and_then(|r|r.ok()).unwrap_or_default();
    let apps = tokio::task::spawn_blocking({
        let store=store.clone(); let tenant=tenant.clone();
        move || ApplicationRepository::list(store.as_ref(), &tenant)
    }).await.ok().and_then(|r|r.ok()).unwrap_or_default();
    let mut rows = String::new();
    for c in clients {
        rows.push_str(&format!("<li>{} ({}) - {} <a href=\"/organizations/{}/oauth-clients/{}\">Manage</a></li>", escape(c.name().as_str()), escape(c.client_id().as_str()), if c.status() == authkit_core::domain::oauth_client::ClientStatus::Active { "active" } else { "disabled" }, org_id.as_str(), c.id().as_str()));
    }
    let mut app_options = String::new();
    for a in apps {
        app_options.push_str(&format!("<option value=\"{}\">{}</option>", a.id().as_str(), escape(a.name().as_str())));
    }
    let can_manage = can_manage_members(&store, &user_id, &org_id);
    let form = if can_manage {
        format!(r#"<h2>Create OAuth client</h2><form method="post" action="/organizations/{}/oauth-clients"><input type="hidden" name="_csrf" value="{}"><label>Application <select name="application_id">{}</select></label><br><label>Name <input name="name" required></label><br><label>Client type <select name="client_type"><option value="public">public</option><option value="confidential">confidential</option></select></label><br><label>Redirect URI <input name="redirect_uri" required></label><br><label>Scopes <input name="scopes" value="openid profile email"></label><br><button type="submit">Create</button></form>"#, org_id.as_str(), escape(&csrf), app_options)
    } else { String::new() };
    let body = format!(r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><title>OAuth clients</title></head><body style="font-family: system-ui, sans-serif; max-width: 40rem; margin: 4rem auto; padding: 0 1rem;"><h1>OAuth clients</h1><ul>{}</ul>{}<p><a href="/organizations/{}/applications">Applications</a></p></body></html>"#, rows, form, org_id.as_str());
    html_ok(&body)
}

pub(crate) async fn create_oauth_client(
    State(state): State<AppState>,
    session: Option<Extension<SessionContext>>,
    Path(org_id): Path<String>,
    body: axum::body::Bytes,
) -> Response {
    let Some(Extension(session)) = session else { return redirect("/login"); };
    let Some(sessions) = state.sessions.as_ref() else { return unavailable(); };
    let org_id = match Id::<OrganizationEntity>::parse(&org_id) { Ok(v)=>v, Err(_)=>return bad_request() };
    let user_id = session.session().user_id().clone();
    let store = sessions.store().clone();
    if !can_manage_members(&store, &user_id, &org_id) { return forbidden(); }
    let mut params = parse_form(&body);
    let application_id_str = params.remove("application_id").unwrap_or_default();
    let name_str = params.remove("name").unwrap_or_default();
    let client_type_str = params.remove("client_type").unwrap_or_default();
    let redirect_uri_str = params.remove("redirect_uri").unwrap_or_default();
    let scopes_str = params.remove("scopes").unwrap_or_default();
    let application_id = match Id::<authkit_core::domain::id::ApplicationEntity>::parse(&application_id_str) { Ok(v)=>v, Err(_)=>return bad_request() };
    let name = match DisplayName::parse(&name_str) { Ok(v)=>v, Err(_)=>return bad_request() };
    let redirect_uri = match RedirectUri::parse(&redirect_uri_str) { Ok(v)=>v, Err(_)=>return bad_request() };
    let scopes: Vec<Scope> = scopes_str.split_whitespace().filter_map(|s| Scope::parse(s).ok()).collect();
    let allowed_scopes = ScopeSet::new(scopes);
    let client_type = if client_type_str == "confidential" { ClientType::Confidential } else { ClientType::Public };
    let pepper = sessions.pepper().to_vec();
    let (secret_plain, secret_hash) = if client_type == ClientType::Confidential {
        use rand_core::{OsRng, RngCore};
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        let secret = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
        let hash = match crate::tokens::hash_client_secret(&pepper, &secret) {
            Ok(v) => v,
            Err(_) => return bad_request(),
        };
        (Some(secret), Some(hash))
    } else {
        (None, None)
    };
    // generate client_id
    use rand_core::{OsRng, RngCore};
    let mut bytes = [0u8; 24];
    OsRng.fill_bytes(&mut bytes);
    let client_id_str: String = bytes.iter().map(|b| format!("{:02x}", b)).collect();
    let client_id = match ClientId::parse(client_id_str) { Ok(v)=>v, Err(_)=>return bad_request() };
    let tenant = TenantContext::new(org_id.clone());
    let now = sessions.clock().now();
    let spec = OAuthClientSpec {
        application_id,
        client_id: client_id.clone(),
        name,
        client_type,
        token_endpoint_auth_method: if client_type == ClientType::Confidential { TokenEndpointAuthMethod::ClientSecretPost } else { TokenEndpointAuthMethod::None },
        secret_hash,
        require_pkce: true,
        redirect_uris: vec![redirect_uri.clone()],
        post_logout_redirect_uris: Vec::new(),
        allowed_scopes,
        allowed_grant_types: vec![GrantType::AuthorizationCode, GrantType::RefreshToken],
    };
    let client = match OAuthClient::new(
        SecureIdGenerator.generate::<authkit_core::domain::id::OAuthClientEntity>().expect("id"),
        spec,
        now,
    ) {
        Ok(v) => v,
        Err(_) => return bad_request(),
    };
    let outcome = tokio::task::spawn_blocking({
        let store=store.clone(); let tenant=tenant.clone(); let client=client.clone();
        move || OAuthClientRepository::insert(store.as_ref(), &tenant, &client)
    }).await;
    if outcome.ok().and_then(|r|r.ok()) != Some(WriteOutcome::Applied) {
        return unavailable();
    }
    let secret_text = secret_plain.unwrap_or_else(|| "(public client)".to_owned());
    let body = format!(r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><title>OAuth client created</title></head><body style="font-family: system-ui, sans-serif; max-width: 40rem; margin: 4rem auto; padding: 0 1rem;"><h1>OAuth client created</h1><p>Client ID: <code>{}</code></p><p>Client secret: <code>{}</code></p><p><a href="/organizations/{}/oauth-clients">Back</a></p></body></html>"#, escape(client.client_id().as_str()), escape(&secret_text), org_id.as_str());
    html_ok(&body)
}


pub(crate) async fn oauth_client_detail(
    State(state): State<AppState>,
    session: Option<Extension<SessionContext>>,
    Path((org_id, client_id)): Path<(String, String)>,
) -> Response {
    let Some(Extension(session)) = session else { return redirect("/login"); };
    let Some(sessions) = state.sessions.as_ref() else { return unavailable(); };
    let org_id = match Id::<OrganizationEntity>::parse(&org_id) { Ok(v)=>v, Err(_)=>return bad_request() };
    let client_id = match Id::<authkit_core::domain::id::OAuthClientEntity>::parse(&client_id) { Ok(v)=>v, Err(_)=>return bad_request() };
    let user_id = session.session().user_id().clone();
    let store = sessions.store().clone();
    let csrf = sessions.csrf_token(session.session());
    if !can_manage_members(&store, &user_id, &org_id) { return forbidden(); }
    let tenant = TenantContext::new(org_id.clone());
    let client = tokio::task::spawn_blocking({
        let store=store.clone(); let tenant=tenant.clone(); let client_id=client_id.clone();
        move || OAuthClientRepository::find_by_id(store.as_ref(), &tenant, &client_id)
    }).await.ok().and_then(|r|r.ok().flatten());
    let Some(client) = client else { return bad_request(); };
    let redirect_rows = client.redirect_uris().iter().map(|u| format!("<li>{} <form method=\"post\" action=\"/organizations/{}/oauth-clients/{}/redirect-uris/remove\" style=\"display:inline\"><input type=\"hidden\" name=\"_csrf\" value=\"{}\"><input type=\"hidden\" name=\"uri\" value=\"{}\"><button type=\"submit\">Remove</button></form></li>", escape(u.as_str()), org_id.as_str(), client.id().as_str(), escape(&csrf), escape(u.as_str()))).collect::<Vec<_>>().join("");
    let body = format!(r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><title>OAuth client</title></head><body style="font-family: system-ui, sans-serif; max-width: 40rem; margin: 4rem auto; padding: 0 1rem;"><h1>{}</h1><p>Client ID: <code>{}</code></p><h2>Redirect URIs</h2><ul>{}</ul><form method="post" action="/organizations/{}/oauth-clients/{}/redirect-uris"><input type="hidden" name="_csrf" value="{}"><label>Redirect URI <input name="uri" required></label><button type="submit">Add</button></form><h2>Scopes</h2><p>{}</p><form method="post" action="/organizations/{}/oauth-clients/{}/scopes"><input type="hidden" name="_csrf" value="{}"><label>Scopes <input name="scopes" value="{}"></label><button type="submit">Replace</button></form></body></html>"#,
        escape(client.name().as_str()),
        escape(client.client_id().as_str()),
        redirect_rows,
        org_id.as_str(),
        client.id().as_str(),
        escape(&csrf),
        escape(&client.allowed_scopes().as_slice().iter().map(|s| s.as_str()).collect::<Vec<_>>().join(" ")),
        org_id.as_str(),
        client.id().as_str(),
        escape(&csrf),
        escape(&client.allowed_scopes().as_slice().iter().map(|s| s.as_str()).collect::<Vec<_>>().join(" "))
    );
    html_ok(&body)
}

pub(crate) async fn add_redirect_uri(
    State(state): State<AppState>,
    session: Option<Extension<SessionContext>>,
    Path((org_id, client_id)): Path<(String, String)>,
    body: axum::body::Bytes,
) -> Response {
    let Some(Extension(session)) = session else { return redirect("/login"); };
    let Some(sessions) = state.sessions.as_ref() else { return unavailable(); };
    let org_id = match Id::<OrganizationEntity>::parse(&org_id) { Ok(v)=>v, Err(_)=>return bad_request() };
    let client_id = match Id::<authkit_core::domain::id::OAuthClientEntity>::parse(&client_id) { Ok(v)=>v, Err(_)=>return bad_request() };
    let user_id = session.session().user_id().clone();
    let store = sessions.store().clone();
    if !can_manage_members(&store, &user_id, &org_id) { return forbidden(); }
    let mut params = parse_form(&body);
    let uri_str = params.remove("uri").unwrap_or_default();
    let uri = match RedirectUri::parse(&uri_str) { Ok(v)=>v, Err(_)=>return bad_request() };
    let tenant = TenantContext::new(org_id.clone());
    let now = sessions.clock().now();
    let outcome = tokio::task::spawn_blocking({
        let store=store.clone(); let tenant=tenant.clone(); let client_id=client_id.clone(); let uri=uri.clone(); let now=now;
        move || {
            let client = OAuthClientRepository::find_by_id(store.as_ref(), &tenant, &client_id)?;
            let Some(mut client) = client else { return Ok(WriteOutcome::NotFound); };
            let expected = client.version();
            client.add_redirect_uri(uri, now)?;
            OAuthClientRepository::update(store.as_ref(), &tenant, &client, expected)
        }
    }).await;
    if outcome.ok().and_then(|r|r.ok()).map(|o|o.is_applied()).unwrap_or(false) {
        redirect(&format!("/organizations/{}/oauth-clients/{}", org_id.as_str(), client_id.as_str()))
    } else {
        unavailable()
    }
}

pub(crate) async fn remove_redirect_uri(
    State(state): State<AppState>,
    session: Option<Extension<SessionContext>>,
    Path((org_id, client_id)): Path<(String, String)>,
    body: axum::body::Bytes,
) -> Response {
    let Some(Extension(session)) = session else { return redirect("/login"); };
    let Some(sessions) = state.sessions.as_ref() else { return unavailable(); };
    let org_id = match Id::<OrganizationEntity>::parse(&org_id) { Ok(v)=>v, Err(_)=>return bad_request() };
    let client_id = match Id::<authkit_core::domain::id::OAuthClientEntity>::parse(&client_id) { Ok(v)=>v, Err(_)=>return bad_request() };
    let user_id = session.session().user_id().clone();
    let store = sessions.store().clone();
    if !can_manage_members(&store, &user_id, &org_id) { return forbidden(); }
    let mut params = parse_form(&body);
    let uri_str = params.remove("uri").unwrap_or_default();
    let uri = match RedirectUri::parse(&uri_str) { Ok(v)=>v, Err(_)=>return bad_request() };
    let tenant = TenantContext::new(org_id.clone());
    let now = sessions.clock().now();
    let outcome = tokio::task::spawn_blocking({
        let store=store.clone(); let tenant=tenant.clone(); let client_id=client_id.clone(); let uri=uri.clone(); let now=now;
        move || {
            let client = OAuthClientRepository::find_by_id(store.as_ref(), &tenant, &client_id)?;
            let Some(mut client) = client else { return Ok(WriteOutcome::NotFound); };
            let expected = client.version();
            client.remove_redirect_uri(&uri, now)?;
            OAuthClientRepository::update(store.as_ref(), &tenant, &client, expected)
        }
    }).await;
    if outcome.ok().and_then(|r|r.ok()).map(|o|o.is_applied()).unwrap_or(false) {
        redirect(&format!("/organizations/{}/oauth-clients/{}", org_id.as_str(), client_id.as_str()))
    } else {
        unavailable()
    }
}

pub(crate) async fn replace_scopes(
    State(state): State<AppState>,
    session: Option<Extension<SessionContext>>,
    Path((org_id, client_id)): Path<(String, String)>,
    body: axum::body::Bytes,
) -> Response {
    let Some(Extension(session)) = session else { return redirect("/login"); };
    let Some(sessions) = state.sessions.as_ref() else { return unavailable(); };
    let org_id = match Id::<OrganizationEntity>::parse(&org_id) { Ok(v)=>v, Err(_)=>return bad_request() };
    let client_id = match Id::<authkit_core::domain::id::OAuthClientEntity>::parse(&client_id) { Ok(v)=>v, Err(_)=>return bad_request() };
    let user_id = session.session().user_id().clone();
    let store = sessions.store().clone();
    if !can_manage_members(&store, &user_id, &org_id) { return forbidden(); }
    let mut params = parse_form(&body);
    let scopes_str = params.remove("scopes").unwrap_or_default();
    let scopes: Vec<Scope> = scopes_str.split_whitespace().filter_map(|s| Scope::parse(s).ok()).collect();
    let scope_set = ScopeSet::new(scopes);
    let tenant = TenantContext::new(org_id.clone());
    let now = sessions.clock().now();
    let outcome = tokio::task::spawn_blocking({
        let store=store.clone(); let tenant=tenant.clone(); let client_id=client_id.clone(); let scope_set=scope_set.clone(); let now=now;
        move || {
            let client = OAuthClientRepository::find_by_id(store.as_ref(), &tenant, &client_id)?;
            let Some(mut client) = client else { return Ok(WriteOutcome::NotFound); };
            let expected = client.version();
            client.replace_scopes(scope_set, now);
            OAuthClientRepository::update(store.as_ref(), &tenant, &client, expected)
        }
    }).await;
    if outcome.ok().and_then(|r|r.ok()).map(|o|o.is_applied()).unwrap_or(false) {
        redirect(&format!("/organizations/{}/oauth-clients/{}", org_id.as_str(), client_id.as_str()))
    } else {
        unavailable()
    }
}

pub(crate) async fn accept_invitation_page(
    axum::extract::RawQuery(query): axum::extract::RawQuery,
) -> Response {
    let token = query
        .as_deref()
        .and_then(|q| form_value(q, "token"))
        .unwrap_or_default();
    let body = format!(
        r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Accept invitation</title></head><body style="font-family: system-ui, sans-serif; max-width: 32rem; margin: 4rem auto; padding: 0 1rem;">
<h1>Accept invitation</h1>
<form method="post" action="/invitations/accept"><input type="hidden" name="token" value="{}"><button type="submit">Accept</button></form>
</body></html>"#,
        escape(&token)
    );
    html_ok(&body)
}

pub(crate) async fn accept_invitation(
    State(state): State<AppState>,
    session: Option<Extension<SessionContext>>,
    body: axum::body::Bytes,
) -> Response {
    let Some(Extension(session)) = session else {
        return redirect("/login");
    };
    let Some(sessions) = state.sessions.as_ref() else {
        return unavailable();
    };
    let mut params = parse_form(&body);
    let token_plain = params.remove("token").unwrap_or_default();
    if token_plain.is_empty() {
        return bad_request();
    }
    let pepper = sessions.pepper().to_vec();
    let hash = hash_token(&token_plain, &pepper);
    let store = sessions.store().clone();
    let now = sessions.clock().now();
    let user_id = session.session().user_id().clone();

    let invitation = match tokio::task::spawn_blocking({
        let store = store.clone();
        let hash = hash.clone();
        move || InvitationRepository::find_by_token_hash(store.as_ref(), &hash)
    })
    .await
    {
        Ok(Ok(Some(inv))) => inv,
        _ => return bad_request(),
    };

    // Email binding.
    let user = match tokio::task::spawn_blocking({
        let store = store.clone();
        let uid = user_id.clone();
        move || UserRepository::find_by_id(store.as_ref(), &uid)
    })
    .await
    .ok()
    .and_then(|r| r.ok().flatten())
    {
        Some(u) => u,
        None => return unavailable(),
    };
    if user.email().as_str() != invitation.email().as_str() {
        return forbidden();
    }
    if !invitation.is_usable(now) {
        return bad_request();
    }

    let org_id = invitation.organization_id().clone();
    let tenant = TenantContext::new(org_id.clone());
    let role_ids = invitation.role_ids().to_vec();
    let original_version = invitation.version();

    // Create membership if needed.
    let membership_result = tokio::task::spawn_blocking({
        let store = store.clone();
        let tenant = tenant.clone();
        let user_id = user_id.clone();
        move || {
            if MembershipRepository::find_by_user(store.as_ref(), &tenant, &user_id)?.is_some() {
                return Ok::<_, authkit_core::domain::DomainError>(());
            }
            let uc = authkit_core::application::AddMembership {
                tenant: tenant.clone(),
                user_id: user_id.clone(),
            };
            uc.execute(store.as_ref(), &SystemClock, &SecureIdGenerator).map(|_| ())
        }
    })
    .await;
    if membership_result.ok().and_then(|r| r.ok()).is_none() {
        return unavailable();
    }

    // Bind roles.
    for role_id in role_ids {
        let _ = tokio::task::spawn_blocking({
            let store = store.clone();
            let tenant = tenant.clone();
            let role_id = role_id.clone();
            let user_id = user_id.clone();
            let now = now;
            let org_id = org_id.clone();
            move || {
                let binding = RoleBinding::organization(
                    SecureIdGenerator.generate::<RoleBindingEntity>().expect("id"),
                    org_id,
                    role_id,
                    user_id,
                    now,
                );
                RoleBindingRepository::insert(store.as_ref(), &tenant, &binding)
            }
        })
        .await;
    }

    // Mark invitation accepted.
    let mut updated_invitation = invitation;
    if updated_invitation.accept(now).is_err() {
        return bad_request();
    }
    let update_result = tokio::task::spawn_blocking({
        let store = store.clone();
        let tenant = tenant.clone();
        let updated_invitation = updated_invitation.clone();
        let original_version = original_version;
        move || InvitationRepository::update(store.as_ref(), &tenant, &updated_invitation, original_version)
    })
    .await;
    if update_result.ok().and_then(|r| r.ok()).map(|o| o.is_applied()).unwrap_or(false) {
        redirect("/account")
    } else {
        unavailable()
    }
}

// helpers
fn can_read_members(store: &std::sync::Arc<authkit_store::SqlStore>, user_id: &authkit_core::domain::Id<UserEntity>, org_id: &authkit_core::domain::Id<OrganizationEntity>) -> bool {
    let tenant = TenantContext::new(org_id.clone());
    let membership = MembershipRepository::find_by_user(store.as_ref(), &tenant, user_id).ok().flatten();
    if !membership.map(|m| m.is_active()).unwrap_or(false) {
        return false;
    }
    let bindings = RoleBindingRepository::list_for_user(store.as_ref(), &tenant, user_id).ok().unwrap_or_default();
    for b in bindings {
        if let Ok(Some(role)) = RoleRepository::find_by_id(store.as_ref(), &tenant, b.role_id()) {
            if role.grants(&Permission::parse("org.member.read").expect("perm"))
                || role.grants(&Permission::parse("org.member.manage").expect("perm")) {
                return true;
            }
        }
    }
    false
}

fn can_manage_members(store: &std::sync::Arc<authkit_store::SqlStore>, user_id: &authkit_core::domain::Id<UserEntity>, org_id: &authkit_core::domain::Id<OrganizationEntity>) -> bool {
    let tenant = TenantContext::new(org_id.clone());
    let membership = MembershipRepository::find_by_user(store.as_ref(), &tenant, user_id).ok().flatten();
    if !membership.map(|m| m.is_active()).unwrap_or(false) {
        return false;
    }
    let bindings = RoleBindingRepository::list_for_user(store.as_ref(), &tenant, user_id).ok().unwrap_or_default();
    for b in bindings {
        if let Ok(Some(role)) = RoleRepository::find_by_id(store.as_ref(), &tenant, b.role_id()) {
            if role.grants(&Permission::parse("org.member.manage").expect("perm")) {
                return true;
            }
        }
    }
    false
}

fn parse_form(body: &axum::body::Bytes) -> std::collections::HashMap<String, String> {
    let mut params = std::collections::HashMap::new();
    for (k, v) in url::form_urlencoded::parse(body) {
        params.insert(k.into_owned(), v.into_owned());
    }
    params
}

fn form_value(query: &str, key: &str) -> Option<String> {
    url::form_urlencoded::parse(query.as_bytes())
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.into_owned())
}

fn redirect(location: &str) -> Response {
    match axum::http::HeaderValue::from_str(location) {
        Ok(location) => (
            StatusCode::SEE_OTHER,
            [(header::LOCATION, location), (header::CACHE_CONTROL, HeaderValue::from_static("no-store"))],
        )
            .into_response(),
        Err(_) => unavailable(),
    }
}

fn unavailable() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        [(header::CACHE_CONTROL, "no-store")],
        axum::Json(serde_json::json!({"error": "unavailable"})),
    )
        .into_response()
}

fn bad_request() -> Response {
    (
        StatusCode::BAD_REQUEST,
        [(header::CACHE_CONTROL, "no-store")],
        axum::Json(serde_json::json!({"error": "invalid_request"})),
    )
        .into_response()
}

fn forbidden() -> Response {
    (
        StatusCode::FORBIDDEN,
        [(header::CACHE_CONTROL, "no-store")],
        axum::Json(serde_json::json!({"error": "forbidden"})),
    )
        .into_response()
}

fn html_ok(body: &str) -> Response {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8"), (header::CACHE_CONTROL, "no-store")],
        body.to_owned(),
    )
        .into_response()
}

fn escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

trait MembershipStatusExt {
    fn status_label(&self) -> &'static str;
}
impl MembershipStatusExt for Membership {
    fn status_label(&self) -> &'static str {
        match self.status() {
            authkit_core::domain::MembershipStatus::Invited => "invited",
            authkit_core::domain::MembershipStatus::Active => "active",
            authkit_core::domain::MembershipStatus::Suspended => "suspended",
            authkit_core::domain::MembershipStatus::Removed => "removed",
        }
    }
}

trait InvitationStatusExt {
    fn status_label(&self) -> &'static str;
}
impl InvitationStatusExt for Invitation {
    fn status_label(&self) -> &'static str {
        match self.status() {
            authkit_core::domain::InvitationStatus::Pending => "pending",
            authkit_core::domain::InvitationStatus::Accepted => "accepted",
            authkit_core::domain::InvitationStatus::Revoked => "revoked",
        }
    }
}

fn random_token() -> String {
    use rand_core::{OsRng, RngCore};
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn hash_token(value: &str, pepper: &[u8]) -> authkit_core::domain::SecretHash {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let mut mac = Hmac::<Sha256>::new_from_slice(pepper).expect("hmac");
    mac.update(b"authkit.reset.v1\0");
    mac.update(value.as_bytes());
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(mac.finalize().into_bytes());
    authkit_core::domain::SecretHash::parse(format!("hmac-sha256:{encoded}")).expect("hash")
}
