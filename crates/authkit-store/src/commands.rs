use authkit_core::domain::DomainError;
use authkit_core::domain::application::Application;
use authkit_core::domain::audit::AuditEvent;
use authkit_core::domain::credential::{Credential, CredentialData};
use authkit_core::domain::grant::{AuthorizationCode, Consent, RefreshFamily, RefreshToken};
use authkit_core::domain::id::{ApplicationEntity, Id, OrganizationEntity, RoleEntity};
use authkit_core::domain::invitation::Invitation;
use authkit_core::domain::membership::Membership;
use authkit_core::domain::oauth_client::OAuthClient;
use authkit_core::domain::organization::Organization;
use authkit_core::domain::role::{Role, RoleBinding};
use authkit_core::domain::session::Session;
use authkit_core::domain::tenant::TenantContext;
use authkit_core::domain::user::User;
use authkit_core::domain::write::WriteOutcome;
use authkit_core::ports::write::{UnitOfWork, WriteBatch, WriteCommand};
use sqlx::any::AnyArguments;
use sqlx::{Any, Transaction};

use crate::mapping::{
    application_kind_str, application_status_str, audit_actor_parts, client_status_str,
    client_type_str, credential_kind_str, credential_status_str, db_flag, db_timestamp, db_version,
    encode_pairs, encode_strings, grant_type_str, invitation_status_str, membership_status_str,
    organization_status_str, role_kind_str, session_audience_str, session_status_str,
    token_endpoint_auth_method_str, totp_algorithm_str, transport_strings, user_status_str,
};
use crate::{Dialect, SqlStore, map_db_error};

impl UnitOfWork for SqlStore {
    fn commit(&self, batch: &WriteBatch) -> Result<WriteOutcome, DomainError> {
        self.block_on(async {
            let mut tx = self.pool.begin().await.map_err(map_db_error)?;
            for command in batch.commands() {
                match apply_command(self.dialect, &mut tx, command).await? {
                    WriteOutcome::Applied => {}
                    outcome => {
                        tx.rollback().await.map_err(map_db_error)?;
                        return Ok(outcome);
                    }
                }
            }
            tx.commit().await.map_err(map_db_error)?;
            Ok(WriteOutcome::Applied)
        })
    }
}

async fn apply_command(
    dialect: Dialect,
    tx: &mut Transaction<'_, Any>,
    command: &WriteCommand,
) -> Result<WriteOutcome, DomainError> {
    match command {
        WriteCommand::InsertUser(user) => insert_user(dialect, tx, user).await,
        WriteCommand::UpdateUser {
            user,
            expected_version,
        } => update_user(dialect, tx, user, *expected_version).await,
        WriteCommand::InsertOrganization(organization) => {
            insert_organization(dialect, tx, organization).await
        }
        WriteCommand::UpdateOrganization {
            organization,
            expected_version,
        } => update_organization(dialect, tx, organization, *expected_version).await,
        WriteCommand::InsertMembership { tenant, membership } => {
            insert_membership(dialect, tx, tenant, membership).await
        }
        WriteCommand::UpdateMembership {
            tenant,
            membership,
            expected_version,
        } => update_membership(dialect, tx, tenant, membership, *expected_version).await,
        WriteCommand::InsertInvitation { tenant, invitation } => {
            insert_invitation(dialect, tx, tenant, invitation).await
        }
        WriteCommand::UpdateInvitation {
            tenant,
            invitation,
            expected_version,
        } => update_invitation(dialect, tx, tenant, invitation, *expected_version).await,
        WriteCommand::InsertApplication {
            tenant,
            application,
        } => insert_application(dialect, tx, tenant, application).await,
        WriteCommand::UpdateApplication {
            tenant,
            application,
            expected_version,
        } => update_application(dialect, tx, tenant, application, *expected_version).await,
        WriteCommand::InsertOAuthClient { tenant, client } => {
            insert_oauth_client(dialect, tx, tenant, client).await
        }
        WriteCommand::UpdateOAuthClient {
            tenant,
            client,
            expected_version,
        } => update_oauth_client(dialect, tx, tenant, client, *expected_version).await,
        WriteCommand::InsertCredential(credential) => {
            insert_credential(dialect, tx, credential).await
        }
        WriteCommand::UpdateCredential {
            credential,
            expected_version,
        } => update_credential(dialect, tx, credential, *expected_version).await,
        WriteCommand::InsertSession(session) => insert_session(dialect, tx, session).await,
        WriteCommand::UpdateSession {
            session,
            expected_version,
        } => update_session(dialect, tx, session, *expected_version).await,
        WriteCommand::InsertRole { tenant, role } => insert_role(dialect, tx, tenant, role).await,
        WriteCommand::UpdateRole {
            tenant,
            role,
            expected_version,
        } => update_role(dialect, tx, tenant, role, *expected_version).await,
        WriteCommand::InsertRoleBinding { tenant, binding } => {
            insert_role_binding(dialect, tx, tenant, binding).await
        }
        WriteCommand::DeleteRoleBinding { tenant, binding_id } => {
            delete_role_binding(dialect, tx, tenant, binding_id).await
        }
        WriteCommand::InsertAuthorizationCode { tenant, code } => {
            insert_authorization_code(dialect, tx, tenant, code).await
        }
        WriteCommand::UpdateAuthorizationCode {
            tenant,
            code,
            expected_version,
        } => update_authorization_code(dialect, tx, tenant, code, *expected_version).await,
        WriteCommand::InsertConsent { tenant, consent } => {
            insert_consent(dialect, tx, tenant, consent).await
        }
        WriteCommand::UpdateConsent {
            tenant,
            consent,
            expected_version,
        } => update_consent(dialect, tx, tenant, consent, *expected_version).await,
        WriteCommand::InsertRefreshFamily { tenant, family } => {
            insert_refresh_family(dialect, tx, tenant, family).await
        }
        WriteCommand::UpdateRefreshFamily {
            tenant,
            family,
            expected_version,
        } => update_refresh_family(dialect, tx, tenant, family, *expected_version).await,
        WriteCommand::InsertRefreshToken { tenant, token } => {
            insert_refresh_token(dialect, tx, tenant, token).await
        }
        WriteCommand::UpdateRefreshToken {
            tenant,
            token,
            expected_version,
        } => update_refresh_token(dialect, tx, tenant, token, *expected_version).await,
        WriteCommand::AppendAudit { tenant, event } => {
            insert_audit(dialect, tx, tenant, event).await
        }
    }
}

fn ensure_tenant(
    tenant: &TenantContext,
    organization_id: &Id<OrganizationEntity>,
) -> Result<(), DomainError> {
    if tenant.organization_id() != organization_id {
        return Err(DomainError::forbidden(
            "the aggregate does not belong to the requested tenant",
        ));
    }
    Ok(())
}

fn scope_key(application_id: Option<&Id<ApplicationEntity>>) -> String {
    application_id.map_or_else(
        || "org".to_owned(),
        |application_id| format!("app_{}", application_id.as_str()),
    )
}

async fn insert_user(
    dialect: Dialect,
    tx: &mut Transaction<'_, Any>,
    user: &User,
) -> Result<WriteOutcome, DomainError> {
    let sql = dialect.placeholders(
        "INSERT INTO user_account (id, email, email_verified_at, display_name, status, created_at, updated_at, version) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    );
    match sqlx::query(&sql)
        .bind(user.id().as_str())
        .bind(user.email().as_str())
        .bind(user.email_verified_at().map(db_timestamp).transpose()?)
        .bind(user.display_name().as_str())
        .bind(user_status_str(user.status()))
        .bind(db_timestamp(user.created_at())?)
        .bind(db_timestamp(user.updated_at())?)
        .bind(db_version(user.version())?)
        .execute(&mut **tx)
        .await
    {
        Ok(_) => Ok(WriteOutcome::Applied),
        Err(error) => insert_outcome(error),
    }
}

async fn update_user(
    dialect: Dialect,
    tx: &mut Transaction<'_, Any>,
    user: &User,
    expected_version: u64,
) -> Result<WriteOutcome, DomainError> {
    let sql = dialect.placeholders(
        "UPDATE user_account SET email = ?, email_verified_at = ?, display_name = ?, status = ?, updated_at = ?, version = ? WHERE id = ? AND version = ?",
    );
    let result = sqlx::query(&sql)
        .bind(user.email().as_str())
        .bind(user.email_verified_at().map(db_timestamp).transpose()?)
        .bind(user.display_name().as_str())
        .bind(user_status_str(user.status()))
        .bind(db_timestamp(user.updated_at())?)
        .bind(db_version(user.version())?)
        .bind(user.id().as_str())
        .bind(db_version(expected_version)?)
        .execute(&mut **tx)
        .await
        .map_err(map_db_error)?;
    classify_update(
        dialect,
        tx,
        "user_account",
        "id",
        user.id().as_str(),
        None,
        result.rows_affected(),
    )
    .await
}

async fn insert_organization(
    dialect: Dialect,
    tx: &mut Transaction<'_, Any>,
    organization: &Organization,
) -> Result<WriteOutcome, DomainError> {
    let sql = dialect.placeholders(
        "INSERT INTO organization (id, slug, name, status, created_at, updated_at, version) VALUES (?, ?, ?, ?, ?, ?, ?)",
    );
    match sqlx::query(&sql)
        .bind(organization.id().as_str())
        .bind(organization.slug().as_str())
        .bind(organization.name().as_str())
        .bind(organization_status_str(organization.status()))
        .bind(db_timestamp(organization.created_at())?)
        .bind(db_timestamp(organization.updated_at())?)
        .bind(db_version(organization.version())?)
        .execute(&mut **tx)
        .await
    {
        Ok(_) => Ok(WriteOutcome::Applied),
        Err(error) => insert_outcome(error),
    }
}

async fn update_organization(
    dialect: Dialect,
    tx: &mut Transaction<'_, Any>,
    organization: &Organization,
    expected_version: u64,
) -> Result<WriteOutcome, DomainError> {
    let sql = dialect.placeholders(
        "UPDATE organization SET slug = ?, name = ?, status = ?, updated_at = ?, version = ? WHERE id = ? AND version = ?",
    );
    let result = sqlx::query(&sql)
        .bind(organization.slug().as_str())
        .bind(organization.name().as_str())
        .bind(organization_status_str(organization.status()))
        .bind(db_timestamp(organization.updated_at())?)
        .bind(db_version(organization.version())?)
        .bind(organization.id().as_str())
        .bind(db_version(expected_version)?)
        .execute(&mut **tx)
        .await
        .map_err(map_db_error)?;
    classify_update(
        dialect,
        tx,
        "organization",
        "id",
        organization.id().as_str(),
        None,
        result.rows_affected(),
    )
    .await
}

async fn insert_membership(
    dialect: Dialect,
    tx: &mut Transaction<'_, Any>,
    tenant: &TenantContext,
    membership: &Membership,
) -> Result<WriteOutcome, DomainError> {
    ensure_tenant(tenant, membership.organization_id())?;
    let sql = dialect.placeholders(
        "INSERT INTO membership (id, org_id, user_id, status, invited_by, joined_at, created_at, updated_at, version) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
    );
    match sqlx::query(&sql)
        .bind(membership.id().as_str())
        .bind(membership.organization_id().as_str())
        .bind(membership.user_id().as_str())
        .bind(membership_status_str(membership.status()))
        .bind(membership.invited_by().map(|id| id.as_str()))
        .bind(membership.joined_at().map(db_timestamp).transpose()?)
        .bind(db_timestamp(membership.created_at())?)
        .bind(db_timestamp(membership.updated_at())?)
        .bind(db_version(membership.version())?)
        .execute(&mut **tx)
        .await
    {
        Ok(_) => Ok(WriteOutcome::Applied),
        Err(error) => insert_outcome(error),
    }
}

async fn update_membership(
    dialect: Dialect,
    tx: &mut Transaction<'_, Any>,
    tenant: &TenantContext,
    membership: &Membership,
    expected_version: u64,
) -> Result<WriteOutcome, DomainError> {
    ensure_tenant(tenant, membership.organization_id())?;
    let sql = dialect.placeholders(
        "UPDATE membership SET user_id = ?, status = ?, invited_by = ?, joined_at = ?, updated_at = ?, version = ? WHERE id = ? AND org_id = ? AND version = ?",
    );
    let result = sqlx::query(&sql)
        .bind(membership.user_id().as_str())
        .bind(membership_status_str(membership.status()))
        .bind(membership.invited_by().map(|id| id.as_str()))
        .bind(membership.joined_at().map(db_timestamp).transpose()?)
        .bind(db_timestamp(membership.updated_at())?)
        .bind(db_version(membership.version())?)
        .bind(membership.id().as_str())
        .bind(membership.organization_id().as_str())
        .bind(db_version(expected_version)?)
        .execute(&mut **tx)
        .await
        .map_err(map_db_error)?;
    classify_update(
        dialect,
        tx,
        "membership",
        "id",
        membership.id().as_str(),
        Some(membership.organization_id().as_str()),
        result.rows_affected(),
    )
    .await
}

async fn insert_invitation(
    dialect: Dialect,
    tx: &mut Transaction<'_, Any>,
    tenant: &TenantContext,
    invitation: &Invitation,
) -> Result<WriteOutcome, DomainError> {
    ensure_tenant(tenant, invitation.organization_id())?;
    for role_id in invitation.role_ids() {
        ensure_role_tenant(dialect, tx, tenant, role_id).await?;
    }
    let sql = dialect.placeholders(
        "INSERT INTO invitation (id, org_id, email, token_hash, invited_by, status, expires_at, accepted_at, created_at, updated_at, version) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    );
    match sqlx::query(&sql)
        .bind(invitation.id().as_str())
        .bind(invitation.organization_id().as_str())
        .bind(invitation.email().as_str())
        .bind(invitation.token_hash().as_str())
        .bind(invitation.invited_by().as_str())
        .bind(invitation_status_str(invitation.status()))
        .bind(db_timestamp(invitation.expires_at())?)
        .bind(invitation.accepted_at().map(db_timestamp).transpose()?)
        .bind(db_timestamp(invitation.created_at())?)
        .bind(db_timestamp(invitation.updated_at())?)
        .bind(db_version(invitation.version())?)
        .execute(&mut **tx)
        .await
    {
        Ok(_) => insert_invitation_roles(dialect, tx, invitation).await,
        Err(error) => insert_outcome(error),
    }
}

async fn update_invitation(
    dialect: Dialect,
    tx: &mut Transaction<'_, Any>,
    tenant: &TenantContext,
    invitation: &Invitation,
    expected_version: u64,
) -> Result<WriteOutcome, DomainError> {
    ensure_tenant(tenant, invitation.organization_id())?;
    for role_id in invitation.role_ids() {
        ensure_role_tenant(dialect, tx, tenant, role_id).await?;
    }
    let sql = dialect.placeholders(
        "UPDATE invitation SET email = ?, token_hash = ?, invited_by = ?, status = ?, expires_at = ?, accepted_at = ?, updated_at = ?, version = ? WHERE id = ? AND org_id = ? AND version = ?",
    );
    let result = sqlx::query(&sql)
        .bind(invitation.email().as_str())
        .bind(invitation.token_hash().as_str())
        .bind(invitation.invited_by().as_str())
        .bind(invitation_status_str(invitation.status()))
        .bind(db_timestamp(invitation.expires_at())?)
        .bind(invitation.accepted_at().map(db_timestamp).transpose()?)
        .bind(db_timestamp(invitation.updated_at())?)
        .bind(db_version(invitation.version())?)
        .bind(invitation.id().as_str())
        .bind(invitation.organization_id().as_str())
        .bind(db_version(expected_version)?)
        .execute(&mut **tx)
        .await
        .map_err(map_db_error)?;
    let outcome = classify_update(
        dialect,
        tx,
        "invitation",
        "id",
        invitation.id().as_str(),
        Some(invitation.organization_id().as_str()),
        result.rows_affected(),
    )
    .await?;
    if outcome.is_applied() {
        delete_children(
            dialect,
            tx,
            "invitation_role",
            "invitation_id",
            invitation.id().as_str(),
        )
        .await?;
        let child = insert_invitation_roles(dialect, tx, invitation).await?;
        if !child.is_applied() {
            return Ok(child);
        }
    }
    Ok(outcome)
}

async fn insert_invitation_roles(
    dialect: Dialect,
    tx: &mut Transaction<'_, Any>,
    invitation: &Invitation,
) -> Result<WriteOutcome, DomainError> {
    let sql = dialect.placeholders(
        "INSERT INTO invitation_role (invitation_id, role_id, position) VALUES (?, ?, ?)",
    );
    for (position, role_id) in invitation.role_ids().iter().enumerate() {
        match sqlx::query(&sql)
            .bind(invitation.id().as_str())
            .bind(role_id.as_str())
            .bind(position as i64)
            .execute(&mut **tx)
            .await
        {
            Ok(_) => {}
            Err(error) => return child_outcome(error),
        }
    }
    Ok(WriteOutcome::Applied)
}

async fn insert_application(
    dialect: Dialect,
    tx: &mut Transaction<'_, Any>,
    tenant: &TenantContext,
    application: &Application,
) -> Result<WriteOutcome, DomainError> {
    ensure_tenant(tenant, application.organization_id())?;
    let sql = dialect.placeholders(
        "INSERT INTO application (id, org_id, slug, name, kind, first_party, status, created_at, updated_at, version) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    );
    match sqlx::query(&sql)
        .bind(application.id().as_str())
        .bind(application.organization_id().as_str())
        .bind(application.slug().as_str())
        .bind(application.name().as_str())
        .bind(application_kind_str(application.kind()))
        .bind(db_flag(application.is_first_party()))
        .bind(application_status_str(application.status()))
        .bind(db_timestamp(application.created_at())?)
        .bind(db_timestamp(application.updated_at())?)
        .bind(db_version(application.version())?)
        .execute(&mut **tx)
        .await
    {
        Ok(_) => Ok(WriteOutcome::Applied),
        Err(error) => insert_outcome(error),
    }
}

async fn update_application(
    dialect: Dialect,
    tx: &mut Transaction<'_, Any>,
    tenant: &TenantContext,
    application: &Application,
    expected_version: u64,
) -> Result<WriteOutcome, DomainError> {
    ensure_tenant(tenant, application.organization_id())?;
    let sql = dialect.placeholders(
        "UPDATE application SET slug = ?, name = ?, kind = ?, first_party = ?, status = ?, updated_at = ?, version = ? WHERE id = ? AND org_id = ? AND version = ?",
    );
    let result = sqlx::query(&sql)
        .bind(application.slug().as_str())
        .bind(application.name().as_str())
        .bind(application_kind_str(application.kind()))
        .bind(db_flag(application.is_first_party()))
        .bind(application_status_str(application.status()))
        .bind(db_timestamp(application.updated_at())?)
        .bind(db_version(application.version())?)
        .bind(application.id().as_str())
        .bind(application.organization_id().as_str())
        .bind(db_version(expected_version)?)
        .execute(&mut **tx)
        .await
        .map_err(map_db_error)?;
    classify_update(
        dialect,
        tx,
        "application",
        "id",
        application.id().as_str(),
        Some(application.organization_id().as_str()),
        result.rows_affected(),
    )
    .await
}

async fn insert_oauth_client(
    dialect: Dialect,
    tx: &mut Transaction<'_, Any>,
    tenant: &TenantContext,
    client: &OAuthClient,
) -> Result<WriteOutcome, DomainError> {
    ensure_application_tenant(dialect, tx, tenant, client.application_id()).await?;
    let sql = dialect.placeholders(
        "INSERT INTO oauth_client (id, application_id, client_id, name, client_type, token_endpoint_auth_method, secret_hash, require_pkce, status, created_at, updated_at, version) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    );
    match sqlx::query(&sql)
        .bind(client.id().as_str())
        .bind(client.application_id().as_str())
        .bind(client.client_id().as_str())
        .bind(client.name().as_str())
        .bind(client_type_str(client.client_type()))
        .bind(token_endpoint_auth_method_str(
            client.token_endpoint_auth_method(),
        ))
        .bind(client.secret_hash().map(|hash| hash.as_str()))
        .bind(db_flag(client.require_pkce()))
        .bind(client_status_str(client.status()))
        .bind(db_timestamp(client.created_at())?)
        .bind(db_timestamp(client.updated_at())?)
        .bind(db_version(client.version())?)
        .execute(&mut **tx)
        .await
    {
        Ok(_) => insert_oauth_client_children(dialect, tx, client).await,
        Err(error) => insert_outcome(error),
    }
}

async fn update_oauth_client(
    dialect: Dialect,
    tx: &mut Transaction<'_, Any>,
    tenant: &TenantContext,
    client: &OAuthClient,
    expected_version: u64,
) -> Result<WriteOutcome, DomainError> {
    ensure_application_tenant(dialect, tx, tenant, client.application_id()).await?;
    let sql = dialect.placeholders(
        "UPDATE oauth_client SET application_id = ?, client_id = ?, name = ?, client_type = ?, token_endpoint_auth_method = ?, secret_hash = ?, require_pkce = ?, status = ?, updated_at = ?, version = ? WHERE id = ? AND application_id IN (SELECT id FROM application WHERE org_id = ?) AND version = ?",
    );
    let result = sqlx::query(&sql)
        .bind(client.application_id().as_str())
        .bind(client.client_id().as_str())
        .bind(client.name().as_str())
        .bind(client_type_str(client.client_type()))
        .bind(token_endpoint_auth_method_str(
            client.token_endpoint_auth_method(),
        ))
        .bind(client.secret_hash().map(|hash| hash.as_str()))
        .bind(db_flag(client.require_pkce()))
        .bind(client_status_str(client.status()))
        .bind(db_timestamp(client.updated_at())?)
        .bind(db_version(client.version())?)
        .bind(client.id().as_str())
        .bind(tenant.organization_id().as_str())
        .bind(db_version(expected_version)?)
        .execute(&mut **tx)
        .await
        .map_err(map_db_error)?;
    let outcome = classify_oauth_client_update(
        dialect,
        tx,
        client.id().as_str(),
        tenant.organization_id().as_str(),
        result.rows_affected(),
    )
    .await?;
    if outcome.is_applied() {
        for table in [
            "oauth_client_redirect_uri",
            "oauth_client_post_logout_redirect_uri",
            "oauth_client_scope",
            "oauth_client_grant_type",
        ] {
            delete_children(dialect, tx, table, "client_row_id", client.id().as_str()).await?;
        }
        let child = insert_oauth_client_children(dialect, tx, client).await?;
        if !child.is_applied() {
            return Ok(child);
        }
    }
    Ok(outcome)
}

async fn insert_oauth_client_children(
    dialect: Dialect,
    tx: &mut Transaction<'_, Any>,
    client: &OAuthClient,
) -> Result<WriteOutcome, DomainError> {
    let redirect_sql = dialect.placeholders(
        "INSERT INTO oauth_client_redirect_uri (client_row_id, uri, position) VALUES (?, ?, ?)",
    );
    for (position, uri) in client.redirect_uris().iter().enumerate() {
        match sqlx::query(&redirect_sql)
            .bind(client.id().as_str())
            .bind(uri.as_str())
            .bind(position as i64)
            .execute(&mut **tx)
            .await
        {
            Ok(_) => {}
            Err(error) => return child_outcome(error),
        }
    }

    let post_logout_sql = dialect.placeholders(
        "INSERT INTO oauth_client_post_logout_redirect_uri (client_row_id, uri, position) VALUES (?, ?, ?)",
    );
    for (position, uri) in client.post_logout_redirect_uris().iter().enumerate() {
        match sqlx::query(&post_logout_sql)
            .bind(client.id().as_str())
            .bind(uri.as_str())
            .bind(position as i64)
            .execute(&mut **tx)
            .await
        {
            Ok(_) => {}
            Err(error) => return child_outcome(error),
        }
    }

    let scope_sql = dialect.placeholders(
        "INSERT INTO oauth_client_scope (client_row_id, scope, position) VALUES (?, ?, ?)",
    );
    for (position, scope) in client.allowed_scopes().as_slice().iter().enumerate() {
        match sqlx::query(&scope_sql)
            .bind(client.id().as_str())
            .bind(scope.as_str())
            .bind(position as i64)
            .execute(&mut **tx)
            .await
        {
            Ok(_) => {}
            Err(error) => return child_outcome(error),
        }
    }

    let grant_sql = dialect.placeholders(
        "INSERT INTO oauth_client_grant_type (client_row_id, grant_type, position) VALUES (?, ?, ?)",
    );
    for (position, grant) in client.allowed_grant_types().iter().enumerate() {
        match sqlx::query(&grant_sql)
            .bind(client.id().as_str())
            .bind(grant_type_str(*grant))
            .bind(position as i64)
            .execute(&mut **tx)
            .await
        {
            Ok(_) => {}
            Err(error) => return child_outcome(error),
        }
    }
    Ok(WriteOutcome::Applied)
}

async fn insert_credential(
    dialect: Dialect,
    tx: &mut Transaction<'_, Any>,
    credential: &Credential,
) -> Result<WriteOutcome, DomainError> {
    let columns = CredentialColumns::from(credential)?;
    let sql = dialect.placeholders(
        "INSERT INTO credential (id, user_id, kind, password_verifier, webauthn_credential_id, webauthn_public_key, webauthn_aaguid, webauthn_sign_count, webauthn_transports, webauthn_discoverable, webauthn_backup_eligible, webauthn_backup_state, totp_ciphertext, totp_key_id, totp_nonce, totp_algorithm, totp_digits, totp_period, totp_last_accepted_step, status, created_at, updated_at, last_used_at, version) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    );
    match columns
        .bind_insert(sqlx::query(&sql), credential)?
        .execute(&mut **tx)
        .await
    {
        Ok(_) => Ok(WriteOutcome::Applied),
        Err(error) => insert_outcome(error),
    }
}

async fn update_credential(
    dialect: Dialect,
    tx: &mut Transaction<'_, Any>,
    credential: &Credential,
    expected_version: u64,
) -> Result<WriteOutcome, DomainError> {
    let columns = CredentialColumns::from(credential)?;
    let sql = dialect.placeholders(
        "UPDATE credential SET kind = ?, password_verifier = ?, webauthn_credential_id = ?, webauthn_public_key = ?, webauthn_aaguid = ?, webauthn_sign_count = ?, webauthn_transports = ?, webauthn_discoverable = ?, webauthn_backup_eligible = ?, webauthn_backup_state = ?, totp_ciphertext = ?, totp_key_id = ?, totp_nonce = ?, totp_algorithm = ?, totp_digits = ?, totp_period = ?, totp_last_accepted_step = ?, status = ?, updated_at = ?, last_used_at = ?, version = ? WHERE id = ? AND version = ?",
    );
    let query = columns.bind_update(sqlx::query(&sql), credential)?;
    let result = query
        .bind(credential.id().as_str())
        .bind(db_version(expected_version)?)
        .execute(&mut **tx)
        .await
        .map_err(map_db_error)?;
    classify_update(
        dialect,
        tx,
        "credential",
        "id",
        credential.id().as_str(),
        None,
        result.rows_affected(),
    )
    .await
}

struct CredentialColumns {
    kind: &'static str,
    password_verifier: Option<String>,
    webauthn_credential_id: Option<Vec<u8>>,
    webauthn_public_key: Option<Vec<u8>>,
    webauthn_aaguid: Option<Vec<u8>>,
    webauthn_sign_count: Option<i64>,
    webauthn_transports: Option<String>,
    webauthn_discoverable: Option<i64>,
    webauthn_backup_eligible: Option<i64>,
    webauthn_backup_state: Option<i64>,
    totp_ciphertext: Option<Vec<u8>>,
    totp_key_id: Option<String>,
    totp_nonce: Option<Vec<u8>>,
    totp_algorithm: Option<&'static str>,
    totp_digits: Option<i64>,
    totp_period: Option<i64>,
    totp_last_accepted_step: Option<i64>,
}

impl CredentialColumns {
    fn from(credential: &Credential) -> Result<Self, DomainError> {
        let mut columns = Self {
            kind: credential_kind_str(credential.kind()),
            password_verifier: None,
            webauthn_credential_id: None,
            webauthn_public_key: None,
            webauthn_aaguid: None,
            webauthn_sign_count: None,
            webauthn_transports: None,
            webauthn_discoverable: None,
            webauthn_backup_eligible: None,
            webauthn_backup_state: None,
            totp_ciphertext: None,
            totp_key_id: None,
            totp_nonce: None,
            totp_algorithm: None,
            totp_digits: None,
            totp_period: None,
            totp_last_accepted_step: None,
        };
        match credential.data() {
            CredentialData::Password(verifier) => {
                columns.password_verifier = Some(verifier.as_str().to_owned());
            }
            CredentialData::Passkey(passkey) => {
                let registration = passkey.registration();
                columns.webauthn_credential_id = Some(registration.credential_id().to_vec());
                columns.webauthn_public_key = Some(registration.public_key().to_vec());
                columns.webauthn_aaguid = Some(registration.aaguid().to_vec());
                columns.webauthn_sign_count = Some(i64::from(passkey.sign_count()));
                columns.webauthn_transports = Some(encode_strings(&transport_strings(
                    registration.transports(),
                ))?);
                columns.webauthn_discoverable = Some(db_flag(registration.discoverable()));
                columns.webauthn_backup_eligible = Some(db_flag(registration.backup_eligible()));
                columns.webauthn_backup_state = Some(db_flag(registration.backup_state()));
            }
            CredentialData::Totp(totp) => {
                columns.totp_ciphertext = Some(totp.secret().ciphertext().to_vec());
                columns.totp_key_id = Some(totp.secret().key_id().to_owned());
                columns.totp_nonce = Some(totp.secret().nonce().to_vec());
                columns.totp_algorithm = Some(totp_algorithm_str(totp.config().algorithm()));
                columns.totp_digits = Some(i64::from(totp.config().digits()));
                columns.totp_period =
                    Some(i64::try_from(totp.config().period_seconds()).map_err(|_| {
                        DomainError::invalid("TOTP period is outside the supported range")
                    })?);
                columns.totp_last_accepted_step = totp
                    .last_accepted_step()
                    .map(|step| {
                        i64::try_from(step).map_err(|_| {
                            DomainError::invalid("TOTP step is outside the supported range")
                        })
                    })
                    .transpose()?;
            }
        }
        Ok(columns)
    }

    fn bind_insert<'q>(
        self,
        query: sqlx::query::Query<'q, Any, AnyArguments<'q>>,
        credential: &'q Credential,
    ) -> Result<sqlx::query::Query<'q, Any, AnyArguments<'q>>, DomainError> {
        Ok(query
            .bind(credential.id().as_str())
            .bind(credential.user_id().as_str())
            .bind(self.kind)
            .bind(self.password_verifier)
            .bind(self.webauthn_credential_id)
            .bind(self.webauthn_public_key)
            .bind(self.webauthn_aaguid)
            .bind(self.webauthn_sign_count)
            .bind(self.webauthn_transports)
            .bind(self.webauthn_discoverable)
            .bind(self.webauthn_backup_eligible)
            .bind(self.webauthn_backup_state)
            .bind(self.totp_ciphertext)
            .bind(self.totp_key_id)
            .bind(self.totp_nonce)
            .bind(self.totp_algorithm)
            .bind(self.totp_digits)
            .bind(self.totp_period)
            .bind(self.totp_last_accepted_step)
            .bind(credential_status_str(credential.status()))
            .bind(db_timestamp(credential.created_at())?)
            .bind(db_timestamp(credential.updated_at())?)
            .bind(credential.last_used_at().map(db_timestamp).transpose()?)
            .bind(db_version(credential.version())?))
    }

    fn bind_update<'q>(
        self,
        query: sqlx::query::Query<'q, Any, AnyArguments<'q>>,
        credential: &'q Credential,
    ) -> Result<sqlx::query::Query<'q, Any, AnyArguments<'q>>, DomainError> {
        Ok(query
            .bind(self.kind)
            .bind(self.password_verifier)
            .bind(self.webauthn_credential_id)
            .bind(self.webauthn_public_key)
            .bind(self.webauthn_aaguid)
            .bind(self.webauthn_sign_count)
            .bind(self.webauthn_transports)
            .bind(self.webauthn_discoverable)
            .bind(self.webauthn_backup_eligible)
            .bind(self.webauthn_backup_state)
            .bind(self.totp_ciphertext)
            .bind(self.totp_key_id)
            .bind(self.totp_nonce)
            .bind(self.totp_algorithm)
            .bind(self.totp_digits)
            .bind(self.totp_period)
            .bind(self.totp_last_accepted_step)
            .bind(credential_status_str(credential.status()))
            .bind(db_timestamp(credential.updated_at())?)
            .bind(credential.last_used_at().map(db_timestamp).transpose()?)
            .bind(db_version(credential.version())?))
    }
}

async fn insert_session(
    dialect: Dialect,
    tx: &mut Transaction<'_, Any>,
    session: &Session,
) -> Result<WriteOutcome, DomainError> {
    let sql = dialect.placeholders(
        "INSERT INTO session (id, user_id, organization_id, audience, token_hash, status, created_at, last_seen_at, idle_expires_at, absolute_expires_at, revoked_at, rotated_from, version) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    );
    match sqlx::query(&sql)
        .bind(session.id().as_str())
        .bind(session.user_id().as_str())
        .bind(session.organization_id().map(|id| id.as_str()))
        .bind(session_audience_str(session.audience()))
        .bind(session.token_hash().as_str())
        .bind(session_status_str(session.status()))
        .bind(db_timestamp(session.created_at())?)
        .bind(db_timestamp(session.last_seen_at())?)
        .bind(db_timestamp(session.idle_expires_at())?)
        .bind(db_timestamp(session.absolute_expires_at())?)
        .bind(session.revoked_at().map(db_timestamp).transpose()?)
        .bind(session.rotated_from().map(|id| id.as_str()))
        .bind(db_version(session.version())?)
        .execute(&mut **tx)
        .await
    {
        Ok(_) => Ok(WriteOutcome::Applied),
        Err(error) => insert_outcome(error),
    }
}

async fn update_session(
    dialect: Dialect,
    tx: &mut Transaction<'_, Any>,
    session: &Session,
    expected_version: u64,
) -> Result<WriteOutcome, DomainError> {
    let sql = dialect.placeholders(
        "UPDATE session SET user_id = ?, organization_id = ?, audience = ?, token_hash = ?, status = ?, last_seen_at = ?, idle_expires_at = ?, absolute_expires_at = ?, revoked_at = ?, rotated_from = ?, version = ? WHERE id = ? AND version = ?",
    );
    let result = sqlx::query(&sql)
        .bind(session.user_id().as_str())
        .bind(session.organization_id().map(|id| id.as_str()))
        .bind(session_audience_str(session.audience()))
        .bind(session.token_hash().as_str())
        .bind(session_status_str(session.status()))
        .bind(db_timestamp(session.last_seen_at())?)
        .bind(db_timestamp(session.idle_expires_at())?)
        .bind(db_timestamp(session.absolute_expires_at())?)
        .bind(session.revoked_at().map(db_timestamp).transpose()?)
        .bind(session.rotated_from().map(|id| id.as_str()))
        .bind(db_version(session.version())?)
        .bind(session.id().as_str())
        .bind(db_version(expected_version)?)
        .execute(&mut **tx)
        .await
        .map_err(map_db_error)?;
    classify_update(
        dialect,
        tx,
        "session",
        "id",
        session.id().as_str(),
        None,
        result.rows_affected(),
    )
    .await
}

async fn insert_role(
    dialect: Dialect,
    tx: &mut Transaction<'_, Any>,
    tenant: &TenantContext,
    role: &Role,
) -> Result<WriteOutcome, DomainError> {
    ensure_tenant(tenant, role.organization_id())?;
    if let Some(application_id) = role.application_id() {
        ensure_application_tenant(dialect, tx, tenant, application_id).await?;
    }
    let sql = dialect.placeholders(
        "INSERT INTO role (id, org_id, application_id, scope_key, slug, name, description, kind, created_at, updated_at, version) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    );
    match sqlx::query(&sql)
        .bind(role.id().as_str())
        .bind(role.organization_id().as_str())
        .bind(role.application_id().map(|id| id.as_str()))
        .bind(scope_key(role.application_id()))
        .bind(role.slug().as_str())
        .bind(role.name().as_str())
        .bind(role.description())
        .bind(role_kind_str(role.kind()))
        .bind(db_timestamp(role.created_at())?)
        .bind(db_timestamp(role.updated_at())?)
        .bind(db_version(role.version())?)
        .execute(&mut **tx)
        .await
    {
        Ok(_) => insert_role_permissions(dialect, tx, role).await,
        Err(error) => insert_outcome(error),
    }
}

async fn update_role(
    dialect: Dialect,
    tx: &mut Transaction<'_, Any>,
    tenant: &TenantContext,
    role: &Role,
    expected_version: u64,
) -> Result<WriteOutcome, DomainError> {
    ensure_tenant(tenant, role.organization_id())?;
    if let Some(application_id) = role.application_id() {
        ensure_application_tenant(dialect, tx, tenant, application_id).await?;
    }
    let sql = dialect.placeholders(
        "UPDATE role SET application_id = ?, scope_key = ?, slug = ?, name = ?, description = ?, kind = ?, updated_at = ?, version = ? WHERE id = ? AND org_id = ? AND version = ?",
    );
    let result = sqlx::query(&sql)
        .bind(role.application_id().map(|id| id.as_str()))
        .bind(scope_key(role.application_id()))
        .bind(role.slug().as_str())
        .bind(role.name().as_str())
        .bind(role.description())
        .bind(role_kind_str(role.kind()))
        .bind(db_timestamp(role.updated_at())?)
        .bind(db_version(role.version())?)
        .bind(role.id().as_str())
        .bind(role.organization_id().as_str())
        .bind(db_version(expected_version)?)
        .execute(&mut **tx)
        .await
        .map_err(map_db_error)?;
    let outcome = classify_update(
        dialect,
        tx,
        "role",
        "id",
        role.id().as_str(),
        Some(role.organization_id().as_str()),
        result.rows_affected(),
    )
    .await?;
    if outcome.is_applied() {
        delete_children(
            dialect,
            tx,
            "role_permission",
            "role_id",
            role.id().as_str(),
        )
        .await?;
        let child = insert_role_permissions(dialect, tx, role).await?;
        if !child.is_applied() {
            return Ok(child);
        }
    }
    Ok(outcome)
}

async fn insert_role_permissions(
    dialect: Dialect,
    tx: &mut Transaction<'_, Any>,
    role: &Role,
) -> Result<WriteOutcome, DomainError> {
    let sql = dialect.placeholders(
        "INSERT INTO role_permission (role_id, permission, position) VALUES (?, ?, ?)",
    );
    for (position, permission) in role.permissions().as_slice().iter().enumerate() {
        match sqlx::query(&sql)
            .bind(role.id().as_str())
            .bind(permission.as_str())
            .bind(position as i64)
            .execute(&mut **tx)
            .await
        {
            Ok(_) => {}
            Err(error) => return child_outcome(error),
        }
    }
    Ok(WriteOutcome::Applied)
}

async fn insert_role_binding(
    dialect: Dialect,
    tx: &mut Transaction<'_, Any>,
    tenant: &TenantContext,
    binding: &RoleBinding,
) -> Result<WriteOutcome, DomainError> {
    ensure_tenant(tenant, binding.organization_id())?;
    ensure_role_tenant(dialect, tx, tenant, binding.role_id()).await?;
    if let Some(application_id) = binding.application_id() {
        ensure_application_tenant(dialect, tx, tenant, application_id).await?;
    }
    let sql = dialect.placeholders(
        "INSERT INTO role_binding (id, org_id, application_id, scope_key, role_id, user_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
    );
    match sqlx::query(&sql)
        .bind(binding.id().as_str())
        .bind(binding.organization_id().as_str())
        .bind(binding.application_id().map(|id| id.as_str()))
        .bind(scope_key(binding.application_id()))
        .bind(binding.role_id().as_str())
        .bind(binding.user_id().as_str())
        .bind(db_timestamp(binding.created_at())?)
        .execute(&mut **tx)
        .await
    {
        Ok(_) => Ok(WriteOutcome::Applied),
        Err(error) => insert_outcome(error),
    }
}

async fn delete_role_binding(
    dialect: Dialect,
    tx: &mut Transaction<'_, Any>,
    tenant: &TenantContext,
    binding_id: &Id<authkit_core::domain::id::RoleBindingEntity>,
) -> Result<WriteOutcome, DomainError> {
    let sql = dialect.placeholders("DELETE FROM role_binding WHERE id = ? AND org_id = ?");
    let result = sqlx::query(&sql)
        .bind(binding_id.as_str())
        .bind(tenant.organization_id().as_str())
        .execute(&mut **tx)
        .await
        .map_err(map_db_error)?;
    Ok(if result.rows_affected() == 1 {
        WriteOutcome::Applied
    } else {
        WriteOutcome::NotFound
    })
}

async fn insert_authorization_code(
    dialect: Dialect,
    tx: &mut Transaction<'_, Any>,
    tenant: &TenantContext,
    code: &AuthorizationCode,
) -> Result<WriteOutcome, DomainError> {
    ensure_tenant(tenant, code.organization_id())?;
    ensure_application_tenant(dialect, tx, tenant, code.application_id()).await?;
    ensure_client_tenant(dialect, tx, tenant, code.client_id()).await?;
    let sql = dialect.placeholders(
        "INSERT INTO authorization_code (id, org_id, application_id, client_id, user_id, code_hash, redirect_uri, pkce_challenge, nonce, auth_time, session_id, created_at, expires_at, consumed_at, version) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    );
    match sqlx::query(&sql)
        .bind(code.id().as_str())
        .bind(code.organization_id().as_str())
        .bind(code.application_id().as_str())
        .bind(code.client_id().as_str())
        .bind(code.user_id().as_str())
        .bind(code.code_hash().as_str())
        .bind(code.redirect_uri().as_str())
        .bind(code.pkce_challenge().as_str())
        .bind(code.nonce().map(|nonce| nonce.as_str()))
        .bind(db_timestamp(code.auth_time())?)
        .bind(code.session_id().map(|id| id.as_str()))
        .bind(db_timestamp(code.created_at())?)
        .bind(db_timestamp(code.expires_at())?)
        .bind(code.consumed_at().map(db_timestamp).transpose()?)
        .bind(db_version(code.version())?)
        .execute(&mut **tx)
        .await
    {
        Ok(_) => insert_code_scopes(dialect, tx, code).await,
        Err(error) => insert_outcome(error),
    }
}

async fn update_authorization_code(
    dialect: Dialect,
    tx: &mut Transaction<'_, Any>,
    tenant: &TenantContext,
    code: &AuthorizationCode,
    expected_version: u64,
) -> Result<WriteOutcome, DomainError> {
    ensure_tenant(tenant, code.organization_id())?;
    ensure_application_tenant(dialect, tx, tenant, code.application_id()).await?;
    ensure_client_tenant(dialect, tx, tenant, code.client_id()).await?;
    let sql = dialect.placeholders(
        "UPDATE authorization_code SET application_id = ?, client_id = ?, user_id = ?, code_hash = ?, redirect_uri = ?, pkce_challenge = ?, nonce = ?, auth_time = ?, session_id = ?, expires_at = ?, consumed_at = ?, version = ? WHERE id = ? AND org_id = ? AND version = ?",
    );
    let result = sqlx::query(&sql)
        .bind(code.application_id().as_str())
        .bind(code.client_id().as_str())
        .bind(code.user_id().as_str())
        .bind(code.code_hash().as_str())
        .bind(code.redirect_uri().as_str())
        .bind(code.pkce_challenge().as_str())
        .bind(code.nonce().map(|nonce| nonce.as_str()))
        .bind(db_timestamp(code.auth_time())?)
        .bind(code.session_id().map(|id| id.as_str()))
        .bind(db_timestamp(code.expires_at())?)
        .bind(code.consumed_at().map(db_timestamp).transpose()?)
        .bind(db_version(code.version())?)
        .bind(code.id().as_str())
        .bind(code.organization_id().as_str())
        .bind(db_version(expected_version)?)
        .execute(&mut **tx)
        .await
        .map_err(map_db_error)?;
    let outcome = classify_update(
        dialect,
        tx,
        "authorization_code",
        "id",
        code.id().as_str(),
        Some(code.organization_id().as_str()),
        result.rows_affected(),
    )
    .await?;
    if outcome.is_applied() {
        delete_children(
            dialect,
            tx,
            "authorization_code_scope",
            "code_id",
            code.id().as_str(),
        )
        .await?;
        let child = insert_code_scopes(dialect, tx, code).await?;
        if !child.is_applied() {
            return Ok(child);
        }
    }
    Ok(outcome)
}

async fn insert_code_scopes(
    dialect: Dialect,
    tx: &mut Transaction<'_, Any>,
    code: &AuthorizationCode,
) -> Result<WriteOutcome, DomainError> {
    let sql = dialect.placeholders(
        "INSERT INTO authorization_code_scope (code_id, scope, position) VALUES (?, ?, ?)",
    );
    for (position, scope) in code.scopes().as_slice().iter().enumerate() {
        match sqlx::query(&sql)
            .bind(code.id().as_str())
            .bind(scope.as_str())
            .bind(position as i64)
            .execute(&mut **tx)
            .await
        {
            Ok(_) => {}
            Err(error) => return child_outcome(error),
        }
    }
    Ok(WriteOutcome::Applied)
}

async fn insert_consent(
    dialect: Dialect,
    tx: &mut Transaction<'_, Any>,
    tenant: &TenantContext,
    consent: &Consent,
) -> Result<WriteOutcome, DomainError> {
    ensure_tenant(tenant, consent.organization_id())?;
    ensure_client_tenant(dialect, tx, tenant, consent.client_id()).await?;
    let sql = dialect.placeholders(
        "INSERT INTO consent (id, org_id, user_id, client_id, created_at, updated_at, revoked_at, version) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    );
    match sqlx::query(&sql)
        .bind(consent.id().as_str())
        .bind(consent.organization_id().as_str())
        .bind(consent.user_id().as_str())
        .bind(consent.client_id().as_str())
        .bind(db_timestamp(consent.created_at())?)
        .bind(db_timestamp(consent.updated_at())?)
        .bind(consent.revoked_at().map(db_timestamp).transpose()?)
        .bind(db_version(consent.version())?)
        .execute(&mut **tx)
        .await
    {
        Ok(_) => insert_consent_scopes(dialect, tx, consent).await,
        Err(error) => insert_outcome(error),
    }
}

async fn update_consent(
    dialect: Dialect,
    tx: &mut Transaction<'_, Any>,
    tenant: &TenantContext,
    consent: &Consent,
    expected_version: u64,
) -> Result<WriteOutcome, DomainError> {
    ensure_tenant(tenant, consent.organization_id())?;
    ensure_client_tenant(dialect, tx, tenant, consent.client_id()).await?;
    let sql = dialect.placeholders(
        "UPDATE consent SET user_id = ?, client_id = ?, updated_at = ?, revoked_at = ?, version = ? WHERE id = ? AND org_id = ? AND version = ?",
    );
    let result = sqlx::query(&sql)
        .bind(consent.user_id().as_str())
        .bind(consent.client_id().as_str())
        .bind(db_timestamp(consent.updated_at())?)
        .bind(consent.revoked_at().map(db_timestamp).transpose()?)
        .bind(db_version(consent.version())?)
        .bind(consent.id().as_str())
        .bind(consent.organization_id().as_str())
        .bind(db_version(expected_version)?)
        .execute(&mut **tx)
        .await
        .map_err(map_db_error)?;
    let outcome = classify_update(
        dialect,
        tx,
        "consent",
        "id",
        consent.id().as_str(),
        Some(consent.organization_id().as_str()),
        result.rows_affected(),
    )
    .await?;
    if outcome.is_applied() {
        delete_children(
            dialect,
            tx,
            "consent_scope",
            "consent_id",
            consent.id().as_str(),
        )
        .await?;
        let child = insert_consent_scopes(dialect, tx, consent).await?;
        if !child.is_applied() {
            return Ok(child);
        }
    }
    Ok(outcome)
}

async fn insert_consent_scopes(
    dialect: Dialect,
    tx: &mut Transaction<'_, Any>,
    consent: &Consent,
) -> Result<WriteOutcome, DomainError> {
    let sql = dialect
        .placeholders("INSERT INTO consent_scope (consent_id, scope, position) VALUES (?, ?, ?)");
    for (position, scope) in consent.scopes().as_slice().iter().enumerate() {
        match sqlx::query(&sql)
            .bind(consent.id().as_str())
            .bind(scope.as_str())
            .bind(position as i64)
            .execute(&mut **tx)
            .await
        {
            Ok(_) => {}
            Err(error) => return child_outcome(error),
        }
    }
    Ok(WriteOutcome::Applied)
}

async fn insert_refresh_family(
    dialect: Dialect,
    tx: &mut Transaction<'_, Any>,
    tenant: &TenantContext,
    family: &RefreshFamily,
) -> Result<WriteOutcome, DomainError> {
    ensure_tenant(tenant, family.organization_id())?;
    ensure_client_tenant(dialect, tx, tenant, family.client_id()).await?;
    let sql = dialect.placeholders(
        "INSERT INTO refresh_family (id, org_id, client_id, user_id, created_at, absolute_expires_at, revoked_at, version) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    );
    match sqlx::query(&sql)
        .bind(family.id().as_str())
        .bind(family.organization_id().as_str())
        .bind(family.client_id().as_str())
        .bind(family.user_id().as_str())
        .bind(db_timestamp(family.created_at())?)
        .bind(db_timestamp(family.absolute_expires_at())?)
        .bind(family.revoked_at().map(db_timestamp).transpose()?)
        .bind(db_version(family.version())?)
        .execute(&mut **tx)
        .await
    {
        Ok(_) => Ok(WriteOutcome::Applied),
        Err(error) => insert_outcome(error),
    }
}

async fn update_refresh_family(
    dialect: Dialect,
    tx: &mut Transaction<'_, Any>,
    tenant: &TenantContext,
    family: &RefreshFamily,
    expected_version: u64,
) -> Result<WriteOutcome, DomainError> {
    ensure_tenant(tenant, family.organization_id())?;
    ensure_client_tenant(dialect, tx, tenant, family.client_id()).await?;
    let sql = dialect.placeholders(
        "UPDATE refresh_family SET client_id = ?, user_id = ?, absolute_expires_at = ?, revoked_at = ?, version = ? WHERE id = ? AND org_id = ? AND version = ?",
    );
    let result = sqlx::query(&sql)
        .bind(family.client_id().as_str())
        .bind(family.user_id().as_str())
        .bind(db_timestamp(family.absolute_expires_at())?)
        .bind(family.revoked_at().map(db_timestamp).transpose()?)
        .bind(db_version(family.version())?)
        .bind(family.id().as_str())
        .bind(family.organization_id().as_str())
        .bind(db_version(expected_version)?)
        .execute(&mut **tx)
        .await
        .map_err(map_db_error)?;
    classify_update(
        dialect,
        tx,
        "refresh_family",
        "id",
        family.id().as_str(),
        Some(family.organization_id().as_str()),
        result.rows_affected(),
    )
    .await
}

async fn insert_refresh_token(
    dialect: Dialect,
    tx: &mut Transaction<'_, Any>,
    tenant: &TenantContext,
    token: &RefreshToken,
) -> Result<WriteOutcome, DomainError> {
    ensure_refresh_family_tenant(dialect, tx, tenant, token.family_id()).await?;
    let sql = dialect.placeholders(
        "INSERT INTO refresh_token (id, family_id, token_hash, created_at, expires_at, consumed_at, version) VALUES (?, ?, ?, ?, ?, ?, ?)",
    );
    match sqlx::query(&sql)
        .bind(token.id().as_str())
        .bind(token.family_id().as_str())
        .bind(token.token_hash().as_str())
        .bind(db_timestamp(token.created_at())?)
        .bind(db_timestamp(token.expires_at())?)
        .bind(token.consumed_at().map(db_timestamp).transpose()?)
        .bind(db_version(token.version())?)
        .execute(&mut **tx)
        .await
    {
        Ok(_) => Ok(WriteOutcome::Applied),
        Err(error) => insert_outcome(error),
    }
}

async fn update_refresh_token(
    dialect: Dialect,
    tx: &mut Transaction<'_, Any>,
    tenant: &TenantContext,
    token: &RefreshToken,
    expected_version: u64,
) -> Result<WriteOutcome, DomainError> {
    ensure_refresh_family_tenant(dialect, tx, tenant, token.family_id()).await?;
    let sql = dialect.placeholders(
        "UPDATE refresh_token SET family_id = ?, token_hash = ?, expires_at = ?, consumed_at = ?, version = ? WHERE id = ? AND family_id IN (SELECT id FROM refresh_family WHERE org_id = ?) AND version = ?",
    );
    let result = sqlx::query(&sql)
        .bind(token.family_id().as_str())
        .bind(token.token_hash().as_str())
        .bind(db_timestamp(token.expires_at())?)
        .bind(token.consumed_at().map(db_timestamp).transpose()?)
        .bind(db_version(token.version())?)
        .bind(token.id().as_str())
        .bind(tenant.organization_id().as_str())
        .bind(db_version(expected_version)?)
        .execute(&mut **tx)
        .await
        .map_err(map_db_error)?;
    classify_refresh_token_update(
        dialect,
        tx,
        token.id().as_str(),
        tenant.organization_id().as_str(),
        result.rows_affected(),
    )
    .await
}

async fn insert_audit(
    dialect: Dialect,
    tx: &mut Transaction<'_, Any>,
    tenant: &TenantContext,
    event: &AuditEvent,
) -> Result<WriteOutcome, DomainError> {
    let event_org = event
        .organization_id()
        .ok_or_else(|| DomainError::forbidden("tenant audit events require an organization"))?;
    ensure_tenant(tenant, event_org)?;
    insert_audit_row(dialect, tx, event).await
}

pub(crate) fn append_unscoped_audit(
    store: &SqlStore,
    event: &AuditEvent,
) -> Result<WriteOutcome, DomainError> {
    store.block_on(async {
        let mut tx = store.pool.begin().await.map_err(map_db_error)?;
        let outcome = insert_audit_row(store.dialect, &mut tx, event).await?;
        if outcome.is_applied() {
            tx.commit().await.map_err(map_db_error)?;
        } else {
            tx.rollback().await.map_err(map_db_error)?;
        }
        Ok(outcome)
    })
}

async fn insert_audit_row(
    dialect: Dialect,
    tx: &mut Transaction<'_, Any>,
    event: &AuditEvent,
) -> Result<WriteOutcome, DomainError> {
    let (actor_type, actor_id) = audit_actor_parts(event.actor());
    let attributes = event
        .attributes()
        .iter()
        .map(|attribute| (attribute.key().to_owned(), attribute.value().to_owned()))
        .collect::<Vec<_>>();
    let sql = dialect.placeholders(
        "INSERT INTO audit_event (id, org_id, actor_type, actor_id, action, target, occurred_at, attributes) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    );
    match sqlx::query(&sql)
        .bind(event.id().as_str())
        .bind(event.organization_id().map(|id| id.as_str()))
        .bind(actor_type)
        .bind(actor_id)
        .bind(event.action().as_str())
        .bind(event.target().map(|target| target.as_str()))
        .bind(db_timestamp(event.occurred_at())?)
        .bind(encode_pairs(&attributes)?)
        .execute(&mut **tx)
        .await
    {
        Ok(_) => Ok(WriteOutcome::Applied),
        Err(error) => insert_outcome(error),
    }
}

async fn ensure_application_tenant(
    dialect: Dialect,
    tx: &mut Transaction<'_, Any>,
    tenant: &TenantContext,
    application_id: &Id<ApplicationEntity>,
) -> Result<(), DomainError> {
    let sql = dialect.placeholders("SELECT 1 FROM application WHERE id = ? AND org_id = ? LIMIT 1");
    let found = sqlx::query(&sql)
        .bind(application_id.as_str())
        .bind(tenant.organization_id().as_str())
        .fetch_optional(&mut **tx)
        .await
        .map_err(map_db_error)?;
    if found.is_none() {
        return Err(DomainError::forbidden(
            "the application does not belong to the requested tenant",
        ));
    }
    Ok(())
}

async fn ensure_role_tenant(
    dialect: Dialect,
    tx: &mut Transaction<'_, Any>,
    tenant: &TenantContext,
    role_id: &Id<RoleEntity>,
) -> Result<(), DomainError> {
    let sql = dialect.placeholders("SELECT 1 FROM role WHERE id = ? AND org_id = ? LIMIT 1");
    let found = sqlx::query(&sql)
        .bind(role_id.as_str())
        .bind(tenant.organization_id().as_str())
        .fetch_optional(&mut **tx)
        .await
        .map_err(map_db_error)?;
    if found.is_none() {
        return Err(DomainError::forbidden(
            "the role does not belong to the requested tenant",
        ));
    }
    Ok(())
}

async fn ensure_client_tenant(
    dialect: Dialect,
    tx: &mut Transaction<'_, Any>,
    tenant: &TenantContext,
    client_id: &Id<authkit_core::domain::id::OAuthClientEntity>,
) -> Result<(), DomainError> {
    let sql = dialect.placeholders(
        "SELECT 1 FROM oauth_client c JOIN application a ON a.id = c.application_id WHERE c.id = ? AND a.org_id = ? LIMIT 1",
    );
    let found = sqlx::query(&sql)
        .bind(client_id.as_str())
        .bind(tenant.organization_id().as_str())
        .fetch_optional(&mut **tx)
        .await
        .map_err(map_db_error)?;
    if found.is_none() {
        return Err(DomainError::forbidden(
            "the client does not belong to the requested tenant",
        ));
    }
    Ok(())
}

async fn ensure_refresh_family_tenant(
    dialect: Dialect,
    tx: &mut Transaction<'_, Any>,
    tenant: &TenantContext,
    family_id: &Id<authkit_core::domain::id::RefreshFamilyEntity>,
) -> Result<(), DomainError> {
    let sql =
        dialect.placeholders("SELECT 1 FROM refresh_family WHERE id = ? AND org_id = ? LIMIT 1");
    let found = sqlx::query(&sql)
        .bind(family_id.as_str())
        .bind(tenant.organization_id().as_str())
        .fetch_optional(&mut **tx)
        .await
        .map_err(map_db_error)?;
    if found.is_none() {
        return Err(DomainError::forbidden(
            "the refresh family does not belong to the requested tenant",
        ));
    }
    Ok(())
}

async fn delete_children(
    dialect: Dialect,
    tx: &mut Transaction<'_, Any>,
    table: &str,
    parent_column: &str,
    parent_id: &str,
) -> Result<(), DomainError> {
    let sql = dialect.placeholders(&format!("DELETE FROM {table} WHERE {parent_column} = ?"));
    sqlx::query(&sql)
        .bind(parent_id)
        .execute(&mut **tx)
        .await
        .map_err(map_db_error)?;
    Ok(())
}

async fn classify_update(
    dialect: Dialect,
    tx: &mut Transaction<'_, Any>,
    table: &str,
    id_column: &str,
    id: &str,
    tenant_id: Option<&str>,
    rows_affected: u64,
) -> Result<WriteOutcome, DomainError> {
    if rows_affected == 1 {
        return Ok(WriteOutcome::Applied);
    }
    let sql = match tenant_id {
        Some(_) => dialect.placeholders(&format!(
            "SELECT 1 FROM {table} WHERE {id_column} = ? AND org_id = ? LIMIT 1"
        )),
        None => dialect.placeholders(&format!(
            "SELECT 1 FROM {table} WHERE {id_column} = ? LIMIT 1"
        )),
    };
    let mut query = sqlx::query(&sql).bind(id);
    if let Some(tenant_id) = tenant_id {
        query = query.bind(tenant_id);
    }
    let exists = query
        .fetch_optional(&mut **tx)
        .await
        .map_err(map_db_error)?;
    Ok(if exists.is_some() {
        WriteOutcome::Conflict
    } else {
        WriteOutcome::NotFound
    })
}

async fn classify_oauth_client_update(
    dialect: Dialect,
    tx: &mut Transaction<'_, Any>,
    id: &str,
    tenant_id: &str,
    rows_affected: u64,
) -> Result<WriteOutcome, DomainError> {
    if rows_affected == 1 {
        return Ok(WriteOutcome::Applied);
    }
    let sql = dialect.placeholders(
        "SELECT 1 FROM oauth_client c JOIN application a ON a.id = c.application_id WHERE c.id = ? AND a.org_id = ? LIMIT 1",
    );
    let exists = sqlx::query(&sql)
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(map_db_error)?;
    Ok(if exists.is_some() {
        WriteOutcome::Conflict
    } else {
        WriteOutcome::NotFound
    })
}

async fn classify_refresh_token_update(
    dialect: Dialect,
    tx: &mut Transaction<'_, Any>,
    id: &str,
    tenant_id: &str,
    rows_affected: u64,
) -> Result<WriteOutcome, DomainError> {
    if rows_affected == 1 {
        return Ok(WriteOutcome::Applied);
    }
    let sql = dialect.placeholders(
        "SELECT 1 FROM refresh_token t JOIN refresh_family f ON f.id = t.family_id WHERE t.id = ? AND f.org_id = ? LIMIT 1",
    );
    let exists = sqlx::query(&sql)
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(map_db_error)?;
    Ok(if exists.is_some() {
        WriteOutcome::Conflict
    } else {
        WriteOutcome::NotFound
    })
}

fn insert_outcome(error: sqlx::Error) -> Result<WriteOutcome, DomainError> {
    if let sqlx::Error::Database(database) = &error
        && database.is_unique_violation()
    {
        return Ok(WriteOutcome::Conflict);
    }
    Err(map_db_error(error))
}

fn child_outcome(error: sqlx::Error) -> Result<WriteOutcome, DomainError> {
    if let sqlx::Error::Database(database) = &error
        && database.is_unique_violation()
    {
        return Ok(WriteOutcome::Conflict);
    }
    Err(map_db_error(error))
}
