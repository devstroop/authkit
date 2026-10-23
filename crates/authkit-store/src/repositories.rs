use std::collections::HashMap;

use authkit_core::domain::DomainError;
use authkit_core::domain::application::Application;
use authkit_core::domain::audit::AuditEvent;
use authkit_core::domain::credential::Credential;
use authkit_core::domain::email::Email;
use authkit_core::domain::grant::{AuthorizationCode, Consent, RefreshFamily, RefreshToken};
use authkit_core::domain::id::{
    ApplicationEntity, AuthorizationCodeEntity, ConsentEntity, CredentialEntity, Id,
    InvitationEntity, MembershipEntity, OAuthClientEntity, OrganizationEntity, RefreshFamilyEntity,
    RefreshTokenEntity, RoleBindingEntity, RoleEntity, SessionEntity, UserEntity,
};
use authkit_core::domain::invitation::Invitation;
use authkit_core::domain::membership::Membership;
use authkit_core::domain::oauth_client::OAuthClient;
use authkit_core::domain::organization::Organization;
use authkit_core::domain::role::{Role, RoleBinding};
use authkit_core::domain::secret::SecretHash;
use authkit_core::domain::session::Session;
use authkit_core::domain::slug::Slug;
use authkit_core::domain::tenant::TenantContext;
use authkit_core::domain::user::User;
use authkit_core::domain::write::WriteOutcome;
use authkit_core::ports::write::{UnitOfWork, WriteBatch, WriteCommand};
use authkit_core::ports::{
    ApplicationRepository, AuditRepository, AuthorizationCodeRepository, ConsentRepository,
    CredentialRepository, InvitationRepository, MembershipRepository, OAuthClientRepository,
    OrganizationRepository, RefreshFamilyRepository, RefreshTokenRepository, Repositories,
    RoleBindingRepository, RoleRepository, SessionRepository, UserRepository,
};
use sqlx::Any;

use crate::mapping::{
    id as stored_id, map_application, map_audit_event, map_authorization_code, map_consent,
    map_credential, map_invitation, map_membership, map_oauth_client, map_organization,
    map_refresh_family, map_refresh_token, map_role, map_role_binding, map_session, map_user, text,
};
use crate::{SqlStore, invalid_stored_value, map_db_error};

async fn fetch_strings(
    tx: &mut sqlx::Transaction<'_, Any>,
    query: &str,
    parent_id: &str,
) -> Result<Vec<String>, DomainError> {
    let rows = sqlx::query(query)
        .bind(parent_id)
        .fetch_all(&mut **tx)
        .await
        .map_err(map_db_error)?;
    rows.iter().map(|row| text(row, "value")).collect()
}

fn parse_role_ids(values: Vec<String>) -> Result<Vec<Id<RoleEntity>>, DomainError> {
    values
        .into_iter()
        .map(|value| Id::<RoleEntity>::parse(value).map_err(|_| invalid_stored_value()))
        .collect()
}

impl UserRepository for SqlStore {
    fn find_by_id(&self, id: &Id<UserEntity>) -> Result<Option<User>, DomainError> {
        let sql = self.sql(
            "SELECT id, email, email_verified_at, display_name, status, created_at, updated_at, version FROM user_account WHERE id = ?",
        );
        self.block_on(async {
            let row = sqlx::query(&sql)
                .bind(id.as_str())
                .fetch_optional(&self.pool)
                .await
                .map_err(map_db_error)?;
            row.as_ref().map(map_user).transpose()
        })
    }

    fn find_by_email(&self, email: &Email) -> Result<Option<User>, DomainError> {
        let sql = self.sql(
            "SELECT id, email, email_verified_at, display_name, status, created_at, updated_at, version FROM user_account WHERE email = ?",
        );
        self.block_on(async {
            let row = sqlx::query(&sql)
                .bind(email.as_str())
                .fetch_optional(&self.pool)
                .await
                .map_err(map_db_error)?;
            row.as_ref().map(map_user).transpose()
        })
    }

    fn insert(&self, user: &User) -> Result<WriteOutcome, DomainError> {
        self.commit(&WriteBatch::new().with(WriteCommand::InsertUser(user.clone())))
    }

    fn update(&self, user: &User, expected_version: u64) -> Result<WriteOutcome, DomainError> {
        self.commit(&WriteBatch::new().with(WriteCommand::UpdateUser {
            user: user.clone(),
            expected_version,
        }))
    }
}

impl OrganizationRepository for SqlStore {
    fn find_by_id(&self, id: &Id<OrganizationEntity>) -> Result<Option<Organization>, DomainError> {
        let sql = self.sql(
            "SELECT id, slug, name, status, created_at, updated_at, version FROM organization WHERE id = ?",
        );
        self.block_on(async {
            let row = sqlx::query(&sql)
                .bind(id.as_str())
                .fetch_optional(&self.pool)
                .await
                .map_err(map_db_error)?;
            row.as_ref().map(map_organization).transpose()
        })
    }

    fn find_by_slug(&self, slug: &Slug) -> Result<Option<Organization>, DomainError> {
        let sql = self.sql(
            "SELECT id, slug, name, status, created_at, updated_at, version FROM organization WHERE slug = ?",
        );
        self.block_on(async {
            let row = sqlx::query(&sql)
                .bind(slug.as_str())
                .fetch_optional(&self.pool)
                .await
                .map_err(map_db_error)?;
            row.as_ref().map(map_organization).transpose()
        })
    }

    fn insert(&self, organization: &Organization) -> Result<WriteOutcome, DomainError> {
        self.commit(&WriteBatch::new().with(WriteCommand::InsertOrganization(organization.clone())))
    }

    fn update(
        &self,
        organization: &Organization,
        expected_version: u64,
    ) -> Result<WriteOutcome, DomainError> {
        self.commit(&WriteBatch::new().with(WriteCommand::UpdateOrganization {
            organization: organization.clone(),
            expected_version,
        }))
    }
}

impl MembershipRepository for SqlStore {
    fn find_by_id(
        &self,
        tenant: &TenantContext,
        id: &Id<MembershipEntity>,
    ) -> Result<Option<Membership>, DomainError> {
        let sql = self.sql(
            "SELECT id, org_id, user_id, status, invited_by, joined_at, created_at, updated_at, version FROM membership WHERE id = ? AND org_id = ?",
        );
        self.block_on(async {
            let row = sqlx::query(&sql)
                .bind(id.as_str())
                .bind(tenant.organization_id().as_str())
                .fetch_optional(&self.pool)
                .await
                .map_err(map_db_error)?;
            row.as_ref().map(map_membership).transpose()
        })
    }

    fn find_by_user(
        &self,
        tenant: &TenantContext,
        user_id: &Id<UserEntity>,
    ) -> Result<Option<Membership>, DomainError> {
        let sql = self.sql(
            "SELECT id, org_id, user_id, status, invited_by, joined_at, created_at, updated_at, version FROM membership WHERE org_id = ? AND user_id = ?",
        );
        self.block_on(async {
            let row = sqlx::query(&sql)
                .bind(tenant.organization_id().as_str())
                .bind(user_id.as_str())
                .fetch_optional(&self.pool)
                .await
                .map_err(map_db_error)?;
            row.as_ref().map(map_membership).transpose()
        })
    }

    fn insert(
        &self,
        tenant: &TenantContext,
        membership: &Membership,
    ) -> Result<WriteOutcome, DomainError> {
        self.commit(&WriteBatch::new().with(WriteCommand::InsertMembership {
            tenant: tenant.clone(),
            membership: membership.clone(),
        }))
    }

    fn update(
        &self,
        tenant: &TenantContext,
        membership: &Membership,
        expected_version: u64,
    ) -> Result<WriteOutcome, DomainError> {
        self.commit(&WriteBatch::new().with(WriteCommand::UpdateMembership {
            tenant: tenant.clone(),
            membership: membership.clone(),
            expected_version,
        }))
    }
}

impl InvitationRepository for SqlStore {
    fn find_by_id(
        &self,
        tenant: &TenantContext,
        id: &Id<InvitationEntity>,
    ) -> Result<Option<Invitation>, DomainError> {
        let sql = self.sql(
            "SELECT id, org_id, email, token_hash, invited_by, status, expires_at, accepted_at, created_at, updated_at, version FROM invitation WHERE id = ? AND org_id = ?",
        );
        let roles_sql = self.sql(
            "SELECT role_id AS value FROM invitation_role WHERE invitation_id = ? ORDER BY position",
        );
        self.block_on(async {
            let mut tx = self.pool.begin().await.map_err(map_db_error)?;
            let row = sqlx::query(&sql)
                .bind(id.as_str())
                .bind(tenant.organization_id().as_str())
                .fetch_optional(&mut *tx)
                .await
                .map_err(map_db_error)?;
            let Some(row) = row else {
                tx.commit().await.map_err(map_db_error)?;
                return Ok(None);
            };
            let role_ids = parse_role_ids(fetch_strings(&mut tx, &roles_sql, id.as_str()).await?)?;
            tx.commit().await.map_err(map_db_error)?;
            Ok(Some(map_invitation(&row, role_ids)?))
        })
    }

    fn insert(
        &self,
        tenant: &TenantContext,
        invitation: &Invitation,
    ) -> Result<WriteOutcome, DomainError> {
        self.commit(&WriteBatch::new().with(WriteCommand::InsertInvitation {
            tenant: tenant.clone(),
            invitation: invitation.clone(),
        }))
    }

    fn update(
        &self,
        tenant: &TenantContext,
        invitation: &Invitation,
        expected_version: u64,
    ) -> Result<WriteOutcome, DomainError> {
        self.commit(&WriteBatch::new().with(WriteCommand::UpdateInvitation {
            tenant: tenant.clone(),
            invitation: invitation.clone(),
            expected_version,
        }))
    }
}

impl ApplicationRepository for SqlStore {
    fn find_by_id(
        &self,
        tenant: &TenantContext,
        id: &Id<ApplicationEntity>,
    ) -> Result<Option<Application>, DomainError> {
        let sql = self.sql(
            "SELECT id, org_id, slug, name, kind, first_party, status, created_at, updated_at, version FROM application WHERE id = ? AND org_id = ?",
        );
        self.block_on(async {
            let row = sqlx::query(&sql)
                .bind(id.as_str())
                .bind(tenant.organization_id().as_str())
                .fetch_optional(&self.pool)
                .await
                .map_err(map_db_error)?;
            row.as_ref().map(map_application).transpose()
        })
    }

    fn find_by_slug(
        &self,
        tenant: &TenantContext,
        slug: &Slug,
    ) -> Result<Option<Application>, DomainError> {
        let sql = self.sql(
            "SELECT id, org_id, slug, name, kind, first_party, status, created_at, updated_at, version FROM application WHERE org_id = ? AND slug = ?",
        );
        self.block_on(async {
            let row = sqlx::query(&sql)
                .bind(tenant.organization_id().as_str())
                .bind(slug.as_str())
                .fetch_optional(&self.pool)
                .await
                .map_err(map_db_error)?;
            row.as_ref().map(map_application).transpose()
        })
    }

    fn insert(
        &self,
        tenant: &TenantContext,
        application: &Application,
    ) -> Result<WriteOutcome, DomainError> {
        self.commit(&WriteBatch::new().with(WriteCommand::InsertApplication {
            tenant: tenant.clone(),
            application: application.clone(),
        }))
    }

    fn update(
        &self,
        tenant: &TenantContext,
        application: &Application,
        expected_version: u64,
    ) -> Result<WriteOutcome, DomainError> {
        self.commit(&WriteBatch::new().with(WriteCommand::UpdateApplication {
            tenant: tenant.clone(),
            application: application.clone(),
            expected_version,
        }))
    }
}

impl OAuthClientRepository for SqlStore {
    fn find_by_id(
        &self,
        tenant: &TenantContext,
        id: &Id<OAuthClientEntity>,
    ) -> Result<Option<OAuthClient>, DomainError> {
        let sql = self.sql(
            "SELECT c.id, c.application_id, c.client_id, c.name, c.client_type, c.token_endpoint_auth_method, c.secret_hash, c.require_pkce, c.status, c.created_at, c.updated_at, c.version FROM oauth_client c JOIN application a ON a.id = c.application_id WHERE c.id = ? AND a.org_id = ?",
        );
        self.find_oauth_client(sql, id.as_str(), Some(tenant.organization_id().as_str()))
    }

    fn find_by_client_id(
        &self,
        client_id: &authkit_core::domain::client_id::ClientId,
    ) -> Result<Option<OAuthClient>, DomainError> {
        let sql = self.sql(
            "SELECT id, application_id, client_id, name, client_type, token_endpoint_auth_method, secret_hash, require_pkce, status, created_at, updated_at, version FROM oauth_client WHERE client_id = ?",
        );
        self.find_oauth_client(sql, client_id.as_str(), None)
    }

    fn insert(
        &self,
        tenant: &TenantContext,
        client: &OAuthClient,
    ) -> Result<WriteOutcome, DomainError> {
        self.commit(&WriteBatch::new().with(WriteCommand::InsertOAuthClient {
            tenant: tenant.clone(),
            client: client.clone(),
        }))
    }

    fn update(
        &self,
        tenant: &TenantContext,
        client: &OAuthClient,
        expected_version: u64,
    ) -> Result<WriteOutcome, DomainError> {
        self.commit(&WriteBatch::new().with(WriteCommand::UpdateOAuthClient {
            tenant: tenant.clone(),
            client: client.clone(),
            expected_version,
        }))
    }
}

impl SqlStore {
    fn find_oauth_client(
        &self,
        parent_sql: String,
        identifier: &str,
        tenant_id: Option<&str>,
    ) -> Result<Option<OAuthClient>, DomainError> {
        let redirect_sql = self.sql(
            "SELECT uri AS value FROM oauth_client_redirect_uri WHERE client_row_id = ? ORDER BY position",
        );
        let post_logout_sql = self.sql(
            "SELECT uri AS value FROM oauth_client_post_logout_redirect_uri WHERE client_row_id = ? ORDER BY position",
        );
        let scope_sql = self.sql(
            "SELECT scope AS value FROM oauth_client_scope WHERE client_row_id = ? ORDER BY position",
        );
        let grant_sql = self.sql(
            "SELECT grant_type AS value FROM oauth_client_grant_type WHERE client_row_id = ? ORDER BY position",
        );
        self.block_on(async {
            let mut tx = self.pool.begin().await.map_err(map_db_error)?;
            let mut query = sqlx::query(&parent_sql).bind(identifier);
            if let Some(tenant_id) = tenant_id {
                query = query.bind(tenant_id);
            }
            let row = query.fetch_optional(&mut *tx).await.map_err(map_db_error)?;
            let Some(row) = row else {
                tx.commit().await.map_err(map_db_error)?;
                return Ok(None);
            };
            let client_row_id = stored_id::<OAuthClientEntity>(&row, "id")?;
            let redirect_uris =
                fetch_strings(&mut tx, &redirect_sql, client_row_id.as_str()).await?;
            let post_logout_uris =
                fetch_strings(&mut tx, &post_logout_sql, client_row_id.as_str()).await?;
            let scopes = fetch_strings(&mut tx, &scope_sql, client_row_id.as_str()).await?;
            let grants = fetch_strings(&mut tx, &grant_sql, client_row_id.as_str()).await?;
            tx.commit().await.map_err(map_db_error)?;
            Ok(Some(map_oauth_client(
                &row,
                redirect_uris,
                post_logout_uris,
                scopes,
                grants,
            )?))
        })
    }
}

impl CredentialRepository for SqlStore {
    fn find_by_id(&self, id: &Id<CredentialEntity>) -> Result<Option<Credential>, DomainError> {
        let sql = self.sql(
            "SELECT id, user_id, kind, password_verifier, webauthn_credential_id, webauthn_public_key, webauthn_aaguid, webauthn_sign_count, webauthn_transports, webauthn_discoverable, webauthn_backup_eligible, webauthn_backup_state, totp_ciphertext, totp_key_id, totp_nonce, totp_algorithm, totp_digits, totp_period, totp_last_accepted_step, status, created_at, updated_at, last_used_at, version FROM credential WHERE id = ?",
        );
        self.block_on(async {
            let row = sqlx::query(&sql)
                .bind(id.as_str())
                .fetch_optional(&self.pool)
                .await
                .map_err(map_db_error)?;
            row.as_ref().map(map_credential).transpose()
        })
    }

    fn list_for_user(&self, user_id: &Id<UserEntity>) -> Result<Vec<Credential>, DomainError> {
        let sql = self.sql(
            "SELECT id, user_id, kind, password_verifier, webauthn_credential_id, webauthn_public_key, webauthn_aaguid, webauthn_sign_count, webauthn_transports, webauthn_discoverable, webauthn_backup_eligible, webauthn_backup_state, totp_ciphertext, totp_key_id, totp_nonce, totp_algorithm, totp_digits, totp_period, totp_last_accepted_step, status, created_at, updated_at, last_used_at, version FROM credential WHERE user_id = ? ORDER BY created_at, id",
        );
        self.block_on(async {
            let rows = sqlx::query(&sql)
                .bind(user_id.as_str())
                .fetch_all(&self.pool)
                .await
                .map_err(map_db_error)?;
            rows.iter().map(map_credential).collect()
        })
    }

    fn insert(&self, credential: &Credential) -> Result<WriteOutcome, DomainError> {
        self.commit(&WriteBatch::new().with(WriteCommand::InsertCredential(credential.clone())))
    }

    fn update(
        &self,
        credential: &Credential,
        expected_version: u64,
    ) -> Result<WriteOutcome, DomainError> {
        self.commit(&WriteBatch::new().with(WriteCommand::UpdateCredential {
            credential: credential.clone(),
            expected_version,
        }))
    }
}

impl SessionRepository for SqlStore {
    fn find_by_id(&self, id: &Id<SessionEntity>) -> Result<Option<Session>, DomainError> {
        let sql = self.sql(
            "SELECT id, user_id, organization_id, audience, token_hash, status, created_at, last_seen_at, idle_expires_at, absolute_expires_at, revoked_at, rotated_from, version FROM session WHERE id = ?",
        );
        self.block_on(async {
            let row = sqlx::query(&sql)
                .bind(id.as_str())
                .fetch_optional(&self.pool)
                .await
                .map_err(map_db_error)?;
            row.as_ref().map(map_session).transpose()
        })
    }

    fn find_by_token_hash(&self, token_hash: &SecretHash) -> Result<Option<Session>, DomainError> {
        let sql = self.sql(
            "SELECT id, user_id, organization_id, audience, token_hash, status, created_at, last_seen_at, idle_expires_at, absolute_expires_at, revoked_at, rotated_from, version FROM session WHERE token_hash = ?",
        );
        self.block_on(async {
            let row = sqlx::query(&sql)
                .bind(token_hash.as_str())
                .fetch_optional(&self.pool)
                .await
                .map_err(map_db_error)?;
            row.as_ref().map(map_session).transpose()
        })
    }

    fn insert(&self, session: &Session) -> Result<WriteOutcome, DomainError> {
        self.commit(&WriteBatch::new().with(WriteCommand::InsertSession(session.clone())))
    }

    fn update(
        &self,
        session: &Session,
        expected_version: u64,
    ) -> Result<WriteOutcome, DomainError> {
        self.commit(&WriteBatch::new().with(WriteCommand::UpdateSession {
            session: session.clone(),
            expected_version,
        }))
    }
}

impl RoleRepository for SqlStore {
    fn find_by_id(
        &self,
        tenant: &TenantContext,
        id: &Id<RoleEntity>,
    ) -> Result<Option<Role>, DomainError> {
        let sql = self.sql(
            "SELECT id, org_id, application_id, slug, name, description, kind, created_at, updated_at, version FROM role WHERE id = ? AND org_id = ?",
        );
        let permissions_sql = self.sql(
            "SELECT permission AS value FROM role_permission WHERE role_id = ? ORDER BY position",
        );
        self.block_on(async {
            let mut tx = self.pool.begin().await.map_err(map_db_error)?;
            let row = sqlx::query(&sql)
                .bind(id.as_str())
                .bind(tenant.organization_id().as_str())
                .fetch_optional(&mut *tx)
                .await
                .map_err(map_db_error)?;
            let Some(row) = row else {
                tx.commit().await.map_err(map_db_error)?;
                return Ok(None);
            };
            let permissions = fetch_strings(&mut tx, &permissions_sql, id.as_str()).await?;
            tx.commit().await.map_err(map_db_error)?;
            Ok(Some(map_role(&row, permissions)?))
        })
    }

    fn list(&self, tenant: &TenantContext) -> Result<Vec<Role>, DomainError> {
        let sql = self.sql(
            "SELECT id, org_id, application_id, slug, name, description, kind, created_at, updated_at, version FROM role WHERE org_id = ? ORDER BY created_at, id",
        );
        let permissions_sql = self.sql(
            "SELECT role_permission.role_id, role_permission.permission AS value FROM role_permission JOIN role ON role.id = role_permission.role_id WHERE role.org_id = ? ORDER BY role_permission.role_id, role_permission.position",
        );
        self.block_on(async {
            let mut tx = self.pool.begin().await.map_err(map_db_error)?;
            let rows = sqlx::query(&sql)
                .bind(tenant.organization_id().as_str())
                .fetch_all(&mut *tx)
                .await
                .map_err(map_db_error)?;
            let permission_rows = sqlx::query(&permissions_sql)
                .bind(tenant.organization_id().as_str())
                .fetch_all(&mut *tx)
                .await
                .map_err(map_db_error)?;
            let mut permissions: HashMap<String, Vec<String>> = HashMap::new();
            for row in &permission_rows {
                let role_id = text(row, "role_id")?;
                let permission = text(row, "value")?;
                permissions.entry(role_id).or_default().push(permission);
            }
            let mut roles = Vec::with_capacity(rows.len());
            for row in &rows {
                let role_id = text(row, "id")?;
                let role_permissions = permissions.remove(&role_id).unwrap_or_default();
                roles.push(map_role(row, role_permissions)?);
            }
            tx.commit().await.map_err(map_db_error)?;
            Ok(roles)
        })
    }

    fn insert(&self, tenant: &TenantContext, role: &Role) -> Result<WriteOutcome, DomainError> {
        self.commit(&WriteBatch::new().with(WriteCommand::InsertRole {
            tenant: tenant.clone(),
            role: role.clone(),
        }))
    }

    fn update(
        &self,
        tenant: &TenantContext,
        role: &Role,
        expected_version: u64,
    ) -> Result<WriteOutcome, DomainError> {
        self.commit(&WriteBatch::new().with(WriteCommand::UpdateRole {
            tenant: tenant.clone(),
            role: role.clone(),
            expected_version,
        }))
    }
}

impl RoleBindingRepository for SqlStore {
    fn list_for_user(
        &self,
        tenant: &TenantContext,
        user_id: &Id<UserEntity>,
    ) -> Result<Vec<RoleBinding>, DomainError> {
        let sql = self.sql(
            "SELECT id, org_id, application_id, role_id, user_id, created_at FROM role_binding WHERE org_id = ? AND user_id = ? ORDER BY created_at, id",
        );
        self.block_on(async {
            let rows = sqlx::query(&sql)
                .bind(tenant.organization_id().as_str())
                .bind(user_id.as_str())
                .fetch_all(&self.pool)
                .await
                .map_err(map_db_error)?;
            rows.iter().map(map_role_binding).collect()
        })
    }

    fn insert(
        &self,
        tenant: &TenantContext,
        binding: &RoleBinding,
    ) -> Result<WriteOutcome, DomainError> {
        self.commit(&WriteBatch::new().with(WriteCommand::InsertRoleBinding {
            tenant: tenant.clone(),
            binding: binding.clone(),
        }))
    }

    fn delete(
        &self,
        tenant: &TenantContext,
        binding_id: &Id<RoleBindingEntity>,
    ) -> Result<WriteOutcome, DomainError> {
        self.commit(&WriteBatch::new().with(WriteCommand::DeleteRoleBinding {
            tenant: tenant.clone(),
            binding_id: binding_id.clone(),
        }))
    }
}

impl AuthorizationCodeRepository for SqlStore {
    fn find_by_id(
        &self,
        tenant: &TenantContext,
        id: &Id<AuthorizationCodeEntity>,
    ) -> Result<Option<AuthorizationCode>, DomainError> {
        let sql = self.sql(
            "SELECT id, org_id, application_id, client_id, user_id, code_hash, redirect_uri, pkce_challenge, nonce, created_at, expires_at, consumed_at, version FROM authorization_code WHERE id = ? AND org_id = ?",
        );
        self.find_authorization_code(sql, id.as_str(), Some(tenant.organization_id().as_str()))
    }

    fn find_by_hash(
        &self,
        tenant: &TenantContext,
        hash: &SecretHash,
    ) -> Result<Option<AuthorizationCode>, DomainError> {
        let sql = self.sql(
            "SELECT id, org_id, application_id, client_id, user_id, code_hash, redirect_uri, pkce_challenge, nonce, created_at, expires_at, consumed_at, version FROM authorization_code WHERE org_id = ? AND code_hash = ?",
        );
        self.find_authorization_code_by_hash(sql, tenant.organization_id().as_str(), hash.as_str())
    }

    fn insert(
        &self,
        tenant: &TenantContext,
        code: &AuthorizationCode,
    ) -> Result<WriteOutcome, DomainError> {
        self.commit(
            &WriteBatch::new().with(WriteCommand::InsertAuthorizationCode {
                tenant: tenant.clone(),
                code: code.clone(),
            }),
        )
    }

    fn update(
        &self,
        tenant: &TenantContext,
        code: &AuthorizationCode,
        expected_version: u64,
    ) -> Result<WriteOutcome, DomainError> {
        self.commit(
            &WriteBatch::new().with(WriteCommand::UpdateAuthorizationCode {
                tenant: tenant.clone(),
                code: code.clone(),
                expected_version,
            }),
        )
    }
}

impl SqlStore {
    fn find_authorization_code(
        &self,
        parent_sql: String,
        identifier: &str,
        tenant_id: Option<&str>,
    ) -> Result<Option<AuthorizationCode>, DomainError> {
        let scopes_sql = self.sql(
            "SELECT scope AS value FROM authorization_code_scope WHERE code_id = ? ORDER BY position",
        );
        self.block_on(async {
            let mut tx = self.pool.begin().await.map_err(map_db_error)?;
            let mut query = sqlx::query(&parent_sql).bind(identifier);
            if let Some(tenant_id) = tenant_id {
                query = query.bind(tenant_id);
            }
            let row = query.fetch_optional(&mut *tx).await.map_err(map_db_error)?;
            let Some(row) = row else {
                tx.commit().await.map_err(map_db_error)?;
                return Ok(None);
            };
            let scopes = fetch_strings(&mut tx, &scopes_sql, identifier).await?;
            tx.commit().await.map_err(map_db_error)?;
            Ok(Some(map_authorization_code(&row, scopes)?))
        })
    }

    fn find_authorization_code_by_hash(
        &self,
        parent_sql: String,
        tenant_id: &str,
        hash: &str,
    ) -> Result<Option<AuthorizationCode>, DomainError> {
        let scopes_sql = self.sql(
            "SELECT scope AS value FROM authorization_code_scope WHERE code_id = ? ORDER BY position",
        );
        self.block_on(async {
            let mut tx = self.pool.begin().await.map_err(map_db_error)?;
            let row = sqlx::query(&parent_sql)
                .bind(tenant_id)
                .bind(hash)
                .fetch_optional(&mut *tx)
                .await
                .map_err(map_db_error)?;
            let Some(row) = row else {
                tx.commit().await.map_err(map_db_error)?;
                return Ok(None);
            };
            let code_id = stored_id::<AuthorizationCodeEntity>(&row, "id")?;
            let scopes = fetch_strings(&mut tx, &scopes_sql, code_id.as_str()).await?;
            tx.commit().await.map_err(map_db_error)?;
            Ok(Some(map_authorization_code(&row, scopes)?))
        })
    }
}

impl ConsentRepository for SqlStore {
    fn find_by_id(
        &self,
        tenant: &TenantContext,
        id: &Id<ConsentEntity>,
    ) -> Result<Option<Consent>, DomainError> {
        let sql = self.sql(
            "SELECT id, org_id, user_id, client_id, created_at, updated_at, revoked_at, version FROM consent WHERE id = ? AND org_id = ?",
        );
        self.find_consent(
            sql,
            id.as_str(),
            Some(tenant.organization_id().as_str()),
            None,
        )
    }

    fn find_for_client_user(
        &self,
        tenant: &TenantContext,
        client_id: &Id<OAuthClientEntity>,
        user_id: &Id<UserEntity>,
    ) -> Result<Option<Consent>, DomainError> {
        let sql = self.sql(
            "SELECT id, org_id, user_id, client_id, created_at, updated_at, revoked_at, version FROM consent WHERE org_id = ? AND client_id = ? AND user_id = ?",
        );
        self.find_consent(
            sql,
            tenant.organization_id().as_str(),
            Some(client_id.as_str()),
            Some(user_id.as_str()),
        )
    }

    fn insert(
        &self,
        tenant: &TenantContext,
        consent: &Consent,
    ) -> Result<WriteOutcome, DomainError> {
        self.commit(&WriteBatch::new().with(WriteCommand::InsertConsent {
            tenant: tenant.clone(),
            consent: consent.clone(),
        }))
    }

    fn update(
        &self,
        tenant: &TenantContext,
        consent: &Consent,
        expected_version: u64,
    ) -> Result<WriteOutcome, DomainError> {
        self.commit(&WriteBatch::new().with(WriteCommand::UpdateConsent {
            tenant: tenant.clone(),
            consent: consent.clone(),
            expected_version,
        }))
    }
}

impl SqlStore {
    fn find_consent(
        &self,
        parent_sql: String,
        first: &str,
        second: Option<&str>,
        third: Option<&str>,
    ) -> Result<Option<Consent>, DomainError> {
        let scopes_sql = self
            .sql("SELECT scope AS value FROM consent_scope WHERE consent_id = ? ORDER BY position");
        self.block_on(async {
            let mut tx = self.pool.begin().await.map_err(map_db_error)?;
            let mut query = sqlx::query(&parent_sql).bind(first);
            if let Some(second) = second {
                query = query.bind(second);
            }
            if let Some(third) = third {
                query = query.bind(third);
            }
            let row = query.fetch_optional(&mut *tx).await.map_err(map_db_error)?;
            let Some(row) = row else {
                tx.commit().await.map_err(map_db_error)?;
                return Ok(None);
            };
            let consent_id = stored_id::<ConsentEntity>(&row, "id")?;
            let scopes = fetch_strings(&mut tx, &scopes_sql, consent_id.as_str()).await?;
            tx.commit().await.map_err(map_db_error)?;
            Ok(Some(map_consent(&row, scopes)?))
        })
    }
}

impl RefreshFamilyRepository for SqlStore {
    fn find_by_id(
        &self,
        tenant: &TenantContext,
        id: &Id<RefreshFamilyEntity>,
    ) -> Result<Option<RefreshFamily>, DomainError> {
        let sql = self.sql(
            "SELECT id, org_id, client_id, user_id, created_at, absolute_expires_at, revoked_at, version FROM refresh_family WHERE id = ? AND org_id = ?",
        );
        self.block_on(async {
            let row = sqlx::query(&sql)
                .bind(id.as_str())
                .bind(tenant.organization_id().as_str())
                .fetch_optional(&self.pool)
                .await
                .map_err(map_db_error)?;
            row.as_ref().map(map_refresh_family).transpose()
        })
    }

    fn insert(
        &self,
        tenant: &TenantContext,
        family: &RefreshFamily,
    ) -> Result<WriteOutcome, DomainError> {
        self.commit(&WriteBatch::new().with(WriteCommand::InsertRefreshFamily {
            tenant: tenant.clone(),
            family: family.clone(),
        }))
    }

    fn update(
        &self,
        tenant: &TenantContext,
        family: &RefreshFamily,
        expected_version: u64,
    ) -> Result<WriteOutcome, DomainError> {
        self.commit(&WriteBatch::new().with(WriteCommand::UpdateRefreshFamily {
            tenant: tenant.clone(),
            family: family.clone(),
            expected_version,
        }))
    }
}

impl RefreshTokenRepository for SqlStore {
    fn find_by_id(
        &self,
        tenant: &TenantContext,
        id: &Id<RefreshTokenEntity>,
    ) -> Result<Option<RefreshToken>, DomainError> {
        let sql = self.sql(
            "SELECT t.id, t.family_id, t.token_hash, t.created_at, t.expires_at, t.consumed_at, t.version FROM refresh_token t JOIN refresh_family f ON f.id = t.family_id WHERE t.id = ? AND f.org_id = ?",
        );
        self.block_on(async {
            let row = sqlx::query(&sql)
                .bind(id.as_str())
                .bind(tenant.organization_id().as_str())
                .fetch_optional(&self.pool)
                .await
                .map_err(map_db_error)?;
            row.as_ref().map(map_refresh_token).transpose()
        })
    }

    fn find_by_hash(
        &self,
        tenant: &TenantContext,
        hash: &SecretHash,
    ) -> Result<Option<RefreshToken>, DomainError> {
        let sql = self.sql(
            "SELECT t.id, t.family_id, t.token_hash, t.created_at, t.expires_at, t.consumed_at, t.version FROM refresh_token t JOIN refresh_family f ON f.id = t.family_id WHERE f.org_id = ? AND t.token_hash = ?",
        );
        self.block_on(async {
            let row = sqlx::query(&sql)
                .bind(tenant.organization_id().as_str())
                .bind(hash.as_str())
                .fetch_optional(&self.pool)
                .await
                .map_err(map_db_error)?;
            row.as_ref().map(map_refresh_token).transpose()
        })
    }

    fn insert(
        &self,
        tenant: &TenantContext,
        token: &RefreshToken,
    ) -> Result<WriteOutcome, DomainError> {
        self.commit(&WriteBatch::new().with(WriteCommand::InsertRefreshToken {
            tenant: tenant.clone(),
            token: token.clone(),
        }))
    }

    fn update(
        &self,
        tenant: &TenantContext,
        token: &RefreshToken,
        expected_version: u64,
    ) -> Result<WriteOutcome, DomainError> {
        self.commit(&WriteBatch::new().with(WriteCommand::UpdateRefreshToken {
            tenant: tenant.clone(),
            token: token.clone(),
            expected_version,
        }))
    }
}

impl AuditRepository for SqlStore {
    fn append(
        &self,
        tenant: &TenantContext,
        event: &AuditEvent,
    ) -> Result<WriteOutcome, DomainError> {
        self.commit(&WriteBatch::new().with(WriteCommand::AppendAudit {
            tenant: tenant.clone(),
            event: event.clone(),
        }))
    }
}

impl SqlStore {
    /// Lists audit events for a tenant in occurrence order.
    ///
    /// This read helper is intended for adapter diagnostics and contract tests; audit events
    /// are not exposed through a general-purpose core repository.
    pub fn list_audit_events(
        &self,
        tenant: &TenantContext,
    ) -> Result<Vec<AuditEvent>, DomainError> {
        let sql = self.sql(
            "SELECT id, org_id, actor_type, actor_id, action, target, occurred_at, attributes FROM audit_event WHERE org_id = ? ORDER BY occurred_at, id",
        );
        self.block_on(async {
            let rows = sqlx::query(&sql)
                .bind(tenant.organization_id().as_str())
                .fetch_all(&self.pool)
                .await
                .map_err(map_db_error)?;
            rows.iter().map(map_audit_event).collect()
        })
    }
}

impl SqlStore {
    /// Appends a security audit event without the tenant guard used by business audit
    /// writes.
    ///
    /// This is reserved for security infrastructure such as rejected CSRF requests. An
    /// event with an organization still records that organization ID; an event without one
    /// is deployment-global. Tenant business events must use [`AuditRepository::append`].
    pub fn append_security_audit(&self, event: &AuditEvent) -> Result<WriteOutcome, DomainError> {
        crate::commands::append_unscoped_audit(self, event)
    }

    /// Lists audit events for one action in occurrence order.
    ///
    /// This read helper is intended for adapter diagnostics and security tests. It is not
    /// tenant-filtered.
    pub fn list_audit_events_by_action(
        &self,
        action: &str,
    ) -> Result<Vec<AuditEvent>, DomainError> {
        let sql = self.sql(
            "SELECT id, org_id, actor_type, actor_id, action, target, occurred_at, attributes FROM audit_event WHERE action = ? ORDER BY occurred_at, id",
        );
        self.block_on(async {
            let rows = sqlx::query(&sql)
                .bind(action)
                .fetch_all(&self.pool)
                .await
                .map_err(map_db_error)?;
            rows.iter().map(map_audit_event).collect()
        })
    }
}

impl Repositories for SqlStore {}
