use authkit_core::domain::DomainError;
use authkit_core::domain::application::{Application, ApplicationKind, ApplicationStatus};
use authkit_core::domain::audit::{
    AuditAction, AuditActor, AuditAttribute, AuditEvent, AuditTarget,
};
use authkit_core::domain::client_id::ClientId;
use authkit_core::domain::credential::{
    AuthenticatorTransport, Credential, CredentialData, CredentialKind, CredentialStatus,
    EncryptedSecret, PasskeyCredential, PasskeyRegistration, PasswordVerifier, TotpAlgorithm,
    TotpConfig, TotpCredential,
};
use authkit_core::domain::email::Email;
use authkit_core::domain::grant::{AuthorizationCode, Consent, RefreshFamily, RefreshToken};
use authkit_core::domain::id::{
    ApplicationEntity, AuditEventEntity, AuthorizationCodeEntity, ConsentEntity, Entity, Id,
    InvitationEntity, MembershipEntity, OAuthClientEntity, OrganizationEntity, RefreshFamilyEntity,
    RefreshTokenEntity, RoleBindingEntity, RoleEntity, SessionEntity, UserEntity,
};
use authkit_core::domain::invitation::{Invitation, InvitationStatus};
use authkit_core::domain::membership::{Membership, MembershipStatus};
use authkit_core::domain::name::DisplayName;
use authkit_core::domain::oauth_client::{
    ClientStatus, ClientType, GrantType, OAuthClient, TokenEndpointAuthMethod,
};
use authkit_core::domain::organization::{Organization, OrganizationStatus};
use authkit_core::domain::permission::{Permission, PermissionSet};
use authkit_core::domain::pkce::{Nonce, PkceChallenge};
use authkit_core::domain::redirect_uri::RedirectUri;
use authkit_core::domain::role::{Role, RoleBinding, RoleKind};
use authkit_core::domain::scope::{Scope, ScopeSet};
use authkit_core::domain::secret::SecretHash;
use authkit_core::domain::session::{Session, SessionAudience, SessionStatus};
use authkit_core::domain::slug::Slug;
use authkit_core::domain::time::Timestamp;
use authkit_core::domain::user::{User, UserStatus};
use sqlx::Row;
use sqlx::any::AnyRow;

use crate::invalid_stored_value;

pub(crate) fn text(row: &AnyRow, column: &str) -> Result<String, DomainError> {
    row.try_get(column).map_err(|_| invalid_stored_value())
}

pub(crate) fn opt_text(row: &AnyRow, column: &str) -> Result<Option<String>, DomainError> {
    row.try_get(column).map_err(|_| invalid_stored_value())
}

pub(crate) fn int(row: &AnyRow, column: &str) -> Result<i64, DomainError> {
    row.try_get(column).map_err(|_| invalid_stored_value())
}

pub(crate) fn opt_int(row: &AnyRow, column: &str) -> Result<Option<i64>, DomainError> {
    row.try_get(column).map_err(|_| invalid_stored_value())
}

pub(crate) fn blob(row: &AnyRow, column: &str) -> Result<Vec<u8>, DomainError> {
    row.try_get(column).map_err(|_| invalid_stored_value())
}

pub(crate) fn flag(row: &AnyRow, column: &str) -> Result<bool, DomainError> {
    match int(row, column)? {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(invalid_stored_value()),
    }
}

pub(crate) fn timestamp(row: &AnyRow, column: &str) -> Result<Timestamp, DomainError> {
    timestamp_from_i64(int(row, column)?)
}

pub(crate) fn opt_timestamp(row: &AnyRow, column: &str) -> Result<Option<Timestamp>, DomainError> {
    opt_int(row, column)?.map(timestamp_from_i64).transpose()
}

pub(crate) fn version(row: &AnyRow, column: &str) -> Result<u64, DomainError> {
    u64_from_i64(int(row, column)?)
}

pub(crate) fn id<E: Entity>(row: &AnyRow, column: &str) -> Result<Id<E>, DomainError> {
    Id::parse(text(row, column)?).map_err(|_| invalid_stored_value())
}

pub(crate) fn opt_id<E: Entity>(row: &AnyRow, column: &str) -> Result<Option<Id<E>>, DomainError> {
    opt_text(row, column)?
        .map(|value| Id::parse(value).map_err(|_| invalid_stored_value()))
        .transpose()
}

pub(crate) fn timestamp_from_i64(value: i64) -> Result<Timestamp, DomainError> {
    u64::try_from(value)
        .map(Timestamp::from_millis)
        .map_err(|_| invalid_stored_value())
}

pub(crate) fn db_timestamp(value: Timestamp) -> Result<i64, DomainError> {
    i64::try_from(value.as_millis())
        .map_err(|_| DomainError::invalid("timestamp is outside the supported range"))
}

pub(crate) fn u64_from_i64(value: i64) -> Result<u64, DomainError> {
    u64::try_from(value).map_err(|_| invalid_stored_value())
}

pub(crate) fn u32_from_i64(value: i64) -> Result<u32, DomainError> {
    u32::try_from(value).map_err(|_| invalid_stored_value())
}

pub(crate) fn u8_from_i64(value: i64) -> Result<u8, DomainError> {
    u8::try_from(value).map_err(|_| invalid_stored_value())
}

pub(crate) fn db_version(value: u64) -> Result<i64, DomainError> {
    i64::try_from(value).map_err(|_| DomainError::invalid("version is outside the supported range"))
}

pub(crate) fn db_flag(value: bool) -> i64 {
    if value { 1 } else { 0 }
}

pub(crate) fn encode_strings(values: &[String]) -> Result<String, DomainError> {
    serde_json::to_string(values).map_err(|_| invalid_stored_value())
}

pub(crate) fn decode_strings(value: &str) -> Result<Vec<String>, DomainError> {
    serde_json::from_str(value).map_err(|_| invalid_stored_value())
}

pub(crate) fn encode_pairs(values: &[(String, String)]) -> Result<String, DomainError> {
    serde_json::to_string(values).map_err(|_| invalid_stored_value())
}

pub(crate) fn decode_pairs(value: &str) -> Result<Vec<(String, String)>, DomainError> {
    serde_json::from_str(value).map_err(|_| invalid_stored_value())
}

pub(crate) fn map_user(row: &AnyRow) -> Result<User, DomainError> {
    User::restore(
        id::<UserEntity>(row, "id")?,
        Email::parse(text(row, "email")?).map_err(|_| invalid_stored_value())?,
        opt_timestamp(row, "email_verified_at")?,
        DisplayName::parse(text(row, "display_name")?).map_err(|_| invalid_stored_value())?,
        user_status(&text(row, "status")?)?,
        timestamp(row, "created_at")?,
        timestamp(row, "updated_at")?,
        version(row, "version")?,
    )
}

pub(crate) fn map_organization(row: &AnyRow) -> Result<Organization, DomainError> {
    Organization::restore(
        id::<OrganizationEntity>(row, "id")?,
        Slug::parse(text(row, "slug")?).map_err(|_| invalid_stored_value())?,
        DisplayName::parse(text(row, "name")?).map_err(|_| invalid_stored_value())?,
        organization_status(&text(row, "status")?)?,
        timestamp(row, "created_at")?,
        timestamp(row, "updated_at")?,
        version(row, "version")?,
    )
}

pub(crate) fn map_application(row: &AnyRow) -> Result<Application, DomainError> {
    Application::restore(
        id::<ApplicationEntity>(row, "id")?,
        id::<OrganizationEntity>(row, "org_id")?,
        Slug::parse(text(row, "slug")?).map_err(|_| invalid_stored_value())?,
        DisplayName::parse(text(row, "name")?).map_err(|_| invalid_stored_value())?,
        application_kind(&text(row, "kind")?)?,
        flag(row, "first_party")?,
        application_status(&text(row, "status")?)?,
        timestamp(row, "created_at")?,
        timestamp(row, "updated_at")?,
        version(row, "version")?,
    )
}

pub(crate) fn map_membership(row: &AnyRow) -> Result<Membership, DomainError> {
    Membership::restore(
        id::<MembershipEntity>(row, "id")?,
        id::<OrganizationEntity>(row, "org_id")?,
        id::<UserEntity>(row, "user_id")?,
        membership_status(&text(row, "status")?)?,
        opt_id::<UserEntity>(row, "invited_by")?,
        opt_timestamp(row, "joined_at")?,
        timestamp(row, "created_at")?,
        timestamp(row, "updated_at")?,
        version(row, "version")?,
    )
}

pub(crate) fn map_invitation(
    row: &AnyRow,
    role_ids: Vec<Id<RoleEntity>>,
) -> Result<Invitation, DomainError> {
    Invitation::restore(
        id::<InvitationEntity>(row, "id")?,
        id::<OrganizationEntity>(row, "org_id")?,
        Email::parse(text(row, "email")?).map_err(|_| invalid_stored_value())?,
        SecretHash::parse(text(row, "token_hash")?).map_err(|_| invalid_stored_value())?,
        role_ids,
        id::<UserEntity>(row, "invited_by")?,
        invitation_status(&text(row, "status")?)?,
        timestamp(row, "expires_at")?,
        opt_timestamp(row, "accepted_at")?,
        timestamp(row, "created_at")?,
        timestamp(row, "updated_at")?,
        version(row, "version")?,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn map_oauth_client(
    row: &AnyRow,
    redirect_uri_values: Vec<String>,
    post_logout_uri_values: Vec<String>,
    allowed_scopes: Vec<String>,
    allowed_grant_types: Vec<String>,
) -> Result<OAuthClient, DomainError> {
    OAuthClient::restore(
        id::<OAuthClientEntity>(row, "id")?,
        id::<ApplicationEntity>(row, "application_id")?,
        ClientId::parse(text(row, "client_id")?).map_err(|_| invalid_stored_value())?,
        DisplayName::parse(text(row, "name")?).map_err(|_| invalid_stored_value())?,
        client_type(&text(row, "client_type")?)?,
        token_endpoint_auth_method(&text(row, "token_endpoint_auth_method")?)?,
        opt_text(row, "secret_hash")?
            .map(SecretHash::parse)
            .transpose()
            .map_err(|_| invalid_stored_value())?,
        flag(row, "require_pkce")?,
        redirect_uris(redirect_uri_values)?,
        redirect_uris(post_logout_uri_values)?,
        scope_set(allowed_scopes)?,
        grant_types(allowed_grant_types)?,
        client_status(&text(row, "status")?)?,
        timestamp(row, "created_at")?,
        timestamp(row, "updated_at")?,
        version(row, "version")?,
    )
}

pub(crate) fn map_credential(row: &AnyRow) -> Result<Credential, DomainError> {
    let kind = credential_kind(&text(row, "kind")?)?;
    let data = match kind {
        CredentialKind::Password => {
            let verifier = opt_text(row, "password_verifier")?.ok_or_else(invalid_stored_value)?;
            CredentialData::Password(
                PasswordVerifier::parse(verifier).map_err(|_| invalid_stored_value())?,
            )
        }
        CredentialKind::Passkey => {
            let registration = PasskeyRegistration::new(
                blob(row, "webauthn_credential_id")?,
                blob(row, "webauthn_public_key")?,
                aaguid(blob(row, "webauthn_aaguid")?)?,
                transports(opt_text(row, "webauthn_transports")?)?,
                flag(row, "webauthn_discoverable")?,
                flag(row, "webauthn_backup_eligible")?,
                flag(row, "webauthn_backup_state")?,
            )
            .map_err(|_| invalid_stored_value())?;
            CredentialData::Passkey(PasskeyCredential::restore(
                registration,
                u32_from_i64(int(row, "webauthn_sign_count")?)?,
            ))
        }
        CredentialKind::Totp => {
            let secret = EncryptedSecret::new(
                opt_text(row, "totp_key_id")?.ok_or_else(invalid_stored_value)?,
                blob(row, "totp_nonce")?,
                blob(row, "totp_ciphertext")?,
            )
            .map_err(|_| invalid_stored_value())?;
            let config = TotpConfig::new(
                totp_algorithm(&text(row, "totp_algorithm")?)?,
                u8_from_i64(int(row, "totp_digits")?)?,
                u64_from_i64(int(row, "totp_period")?)?,
            )
            .map_err(|_| invalid_stored_value())?;
            let last_step = opt_int(row, "totp_last_accepted_step")?
                .map(u64_from_i64)
                .transpose()?;
            CredentialData::Totp(TotpCredential::restore(secret, config, last_step))
        }
    };

    Credential::restore(
        id::<authkit_core::domain::id::CredentialEntity>(row, "id")?,
        id::<UserEntity>(row, "user_id")?,
        data,
        credential_status(&text(row, "status")?)?,
        timestamp(row, "created_at")?,
        timestamp(row, "updated_at")?,
        opt_timestamp(row, "last_used_at")?,
        version(row, "version")?,
    )
}

pub(crate) fn map_session(row: &AnyRow) -> Result<Session, DomainError> {
    Session::restore(
        id::<SessionEntity>(row, "id")?,
        id::<UserEntity>(row, "user_id")?,
        opt_id::<OrganizationEntity>(row, "organization_id")?,
        session_audience(&text(row, "audience")?)?,
        SecretHash::parse(text(row, "token_hash")?).map_err(|_| invalid_stored_value())?,
        session_status(&text(row, "status")?)?,
        timestamp(row, "created_at")?,
        timestamp(row, "last_seen_at")?,
        timestamp(row, "idle_expires_at")?,
        timestamp(row, "absolute_expires_at")?,
        opt_timestamp(row, "revoked_at")?,
        opt_id::<SessionEntity>(row, "rotated_from")?,
        version(row, "version")?,
    )
}

pub(crate) fn map_role(row: &AnyRow, permissions: Vec<String>) -> Result<Role, DomainError> {
    Role::restore(
        id::<RoleEntity>(row, "id")?,
        id::<OrganizationEntity>(row, "org_id")?,
        opt_id::<ApplicationEntity>(row, "application_id")?,
        Slug::parse(text(row, "slug")?).map_err(|_| invalid_stored_value())?,
        DisplayName::parse(text(row, "name")?).map_err(|_| invalid_stored_value())?,
        opt_text(row, "description")?,
        role_kind(&text(row, "kind")?)?,
        permission_set(permissions)?,
        timestamp(row, "created_at")?,
        timestamp(row, "updated_at")?,
        version(row, "version")?,
    )
}

pub(crate) fn map_role_binding(row: &AnyRow) -> Result<RoleBinding, DomainError> {
    Ok(RoleBinding::restore(
        id::<RoleBindingEntity>(row, "id")?,
        id::<OrganizationEntity>(row, "org_id")?,
        opt_id::<ApplicationEntity>(row, "application_id")?,
        id::<RoleEntity>(row, "role_id")?,
        id::<UserEntity>(row, "user_id")?,
        timestamp(row, "created_at")?,
    ))
}

pub(crate) fn map_authorization_code(
    row: &AnyRow,
    scopes: Vec<String>,
) -> Result<AuthorizationCode, DomainError> {
    AuthorizationCode::restore(
        id::<AuthorizationCodeEntity>(row, "id")?,
        id::<OrganizationEntity>(row, "org_id")?,
        id::<ApplicationEntity>(row, "application_id")?,
        id::<OAuthClientEntity>(row, "client_id")?,
        id::<UserEntity>(row, "user_id")?,
        SecretHash::parse(text(row, "code_hash")?).map_err(|_| invalid_stored_value())?,
        RedirectUri::parse(text(row, "redirect_uri")?).map_err(|_| invalid_stored_value())?,
        scope_set(scopes)?,
        PkceChallenge::parse(text(row, "pkce_challenge")?).map_err(|_| invalid_stored_value())?,
        opt_text(row, "nonce")?
            .map(Nonce::parse)
            .transpose()
            .map_err(|_| invalid_stored_value())?,
        timestamp(row, "auth_time")?,
        opt_id::<SessionEntity>(row, "session_id")?,
        timestamp(row, "created_at")?,
        timestamp(row, "expires_at")?,
        opt_timestamp(row, "consumed_at")?,
        version(row, "version")?,
    )
}

pub(crate) fn map_consent(row: &AnyRow, scopes: Vec<String>) -> Result<Consent, DomainError> {
    Consent::restore(
        id::<ConsentEntity>(row, "id")?,
        id::<OrganizationEntity>(row, "org_id")?,
        id::<UserEntity>(row, "user_id")?,
        id::<OAuthClientEntity>(row, "client_id")?,
        scope_set(scopes)?,
        timestamp(row, "created_at")?,
        timestamp(row, "updated_at")?,
        opt_timestamp(row, "revoked_at")?,
        version(row, "version")?,
    )
}

pub(crate) fn map_refresh_family(row: &AnyRow) -> Result<RefreshFamily, DomainError> {
    RefreshFamily::restore(
        id::<RefreshFamilyEntity>(row, "id")?,
        id::<OrganizationEntity>(row, "org_id")?,
        id::<OAuthClientEntity>(row, "client_id")?,
        id::<UserEntity>(row, "user_id")?,
        timestamp(row, "created_at")?,
        timestamp(row, "absolute_expires_at")?,
        opt_timestamp(row, "revoked_at")?,
        version(row, "version")?,
    )
}

pub(crate) fn map_refresh_token(row: &AnyRow) -> Result<RefreshToken, DomainError> {
    RefreshToken::restore(
        id::<RefreshTokenEntity>(row, "id")?,
        id::<RefreshFamilyEntity>(row, "family_id")?,
        SecretHash::parse(text(row, "token_hash")?).map_err(|_| invalid_stored_value())?,
        timestamp(row, "created_at")?,
        timestamp(row, "expires_at")?,
        opt_timestamp(row, "consumed_at")?,
        version(row, "version")?,
    )
}

pub(crate) fn map_audit_event(row: &AnyRow) -> Result<AuditEvent, DomainError> {
    let actor_type = text(row, "actor_type")?;
    let actor_id = opt_text(row, "actor_id")?;
    let actor = match actor_type.as_str() {
        "user" => AuditActor::User(
            Id::<UserEntity>::parse(actor_id.ok_or_else(invalid_stored_value)?)
                .map_err(|_| invalid_stored_value())?,
        ),
        "client" => AuditActor::Client(
            Id::<OAuthClientEntity>::parse(actor_id.ok_or_else(invalid_stored_value)?)
                .map_err(|_| invalid_stored_value())?,
        ),
        "system" => AuditActor::System,
        "anonymous" => AuditActor::Anonymous,
        _ => return Err(invalid_stored_value()),
    };
    let attributes = decode_pairs(&text(row, "attributes")?)?
        .into_iter()
        .map(|(key, value)| AuditAttribute::new(key, value))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| invalid_stored_value())?;

    AuditEvent::new(
        id::<AuditEventEntity>(row, "id")?,
        opt_id::<OrganizationEntity>(row, "org_id")?,
        actor,
        AuditAction::parse(text(row, "action")?).map_err(|_| invalid_stored_value())?,
        opt_text(row, "target")?
            .map(AuditTarget::parse)
            .transpose()
            .map_err(|_| invalid_stored_value())?,
        timestamp(row, "occurred_at")?,
        attributes,
    )
}

pub(crate) fn redirect_uris(values: Vec<String>) -> Result<Vec<RedirectUri>, DomainError> {
    values
        .into_iter()
        .map(|value| RedirectUri::parse(value).map_err(|_| invalid_stored_value()))
        .collect()
}

pub(crate) fn scope_set(values: Vec<String>) -> Result<ScopeSet, DomainError> {
    values
        .into_iter()
        .map(|value| Scope::parse(value).map_err(|_| invalid_stored_value()))
        .collect::<Result<Vec<_>, _>>()
        .map(ScopeSet::new)
}

pub(crate) fn permission_set(values: Vec<String>) -> Result<PermissionSet, DomainError> {
    values
        .into_iter()
        .map(|value| Permission::parse(value).map_err(|_| invalid_stored_value()))
        .collect::<Result<Vec<_>, _>>()
        .map(PermissionSet::new)
}

pub(crate) fn grant_types(values: Vec<String>) -> Result<Vec<GrantType>, DomainError> {
    values.into_iter().map(|value| grant_type(&value)).collect()
}

fn aaguid(value: Vec<u8>) -> Result<[u8; 16], DomainError> {
    value.try_into().map_err(|_| invalid_stored_value())
}

fn transports(value: Option<String>) -> Result<Vec<AuthenticatorTransport>, DomainError> {
    value
        .map(|value| {
            decode_strings(&value)?
                .into_iter()
                .map(|transport| {
                    AuthenticatorTransport::parse(&transport).map_err(|_| invalid_stored_value())
                })
                .collect()
        })
        .transpose()
        .map(Option::unwrap_or_default)
}

fn user_status(value: &str) -> Result<UserStatus, DomainError> {
    match value {
        "active" => Ok(UserStatus::Active),
        "suspended" => Ok(UserStatus::Suspended),
        "deleted" => Ok(UserStatus::Deleted),
        _ => Err(invalid_stored_value()),
    }
}

fn organization_status(value: &str) -> Result<OrganizationStatus, DomainError> {
    match value {
        "active" => Ok(OrganizationStatus::Active),
        "suspended" => Ok(OrganizationStatus::Suspended),
        "deleted" => Ok(OrganizationStatus::Deleted),
        _ => Err(invalid_stored_value()),
    }
}

fn application_kind(value: &str) -> Result<ApplicationKind, DomainError> {
    match value {
        "web" => Ok(ApplicationKind::Web),
        "admin" => Ok(ApplicationKind::Admin),
        "native" => Ok(ApplicationKind::Native),
        "service" => Ok(ApplicationKind::Service),
        "cli" => Ok(ApplicationKind::Cli),
        _ => Err(invalid_stored_value()),
    }
}

fn application_status(value: &str) -> Result<ApplicationStatus, DomainError> {
    match value {
        "active" => Ok(ApplicationStatus::Active),
        "disabled" => Ok(ApplicationStatus::Disabled),
        _ => Err(invalid_stored_value()),
    }
}

fn membership_status(value: &str) -> Result<MembershipStatus, DomainError> {
    match value {
        "invited" => Ok(MembershipStatus::Invited),
        "active" => Ok(MembershipStatus::Active),
        "suspended" => Ok(MembershipStatus::Suspended),
        "removed" => Ok(MembershipStatus::Removed),
        _ => Err(invalid_stored_value()),
    }
}

fn invitation_status(value: &str) -> Result<InvitationStatus, DomainError> {
    match value {
        "pending" => Ok(InvitationStatus::Pending),
        "accepted" => Ok(InvitationStatus::Accepted),
        "revoked" => Ok(InvitationStatus::Revoked),
        _ => Err(invalid_stored_value()),
    }
}

fn client_type(value: &str) -> Result<ClientType, DomainError> {
    match value {
        "confidential" => Ok(ClientType::Confidential),
        "public" => Ok(ClientType::Public),
        _ => Err(invalid_stored_value()),
    }
}

fn client_status(value: &str) -> Result<ClientStatus, DomainError> {
    match value {
        "active" => Ok(ClientStatus::Active),
        "disabled" => Ok(ClientStatus::Disabled),
        _ => Err(invalid_stored_value()),
    }
}

fn token_endpoint_auth_method(value: &str) -> Result<TokenEndpointAuthMethod, DomainError> {
    match value {
        "client_secret_basic" => Ok(TokenEndpointAuthMethod::ClientSecretBasic),
        "client_secret_post" => Ok(TokenEndpointAuthMethod::ClientSecretPost),
        "none" => Ok(TokenEndpointAuthMethod::None),
        _ => Err(invalid_stored_value()),
    }
}

fn grant_type(value: &str) -> Result<GrantType, DomainError> {
    match value {
        "authorization_code" => Ok(GrantType::AuthorizationCode),
        "refresh_token" => Ok(GrantType::RefreshToken),
        "client_credentials" => Ok(GrantType::ClientCredentials),
        _ => Err(invalid_stored_value()),
    }
}

fn credential_kind(value: &str) -> Result<CredentialKind, DomainError> {
    match value {
        "password" => Ok(CredentialKind::Password),
        "passkey" => Ok(CredentialKind::Passkey),
        "totp" => Ok(CredentialKind::Totp),
        _ => Err(invalid_stored_value()),
    }
}

fn credential_status(value: &str) -> Result<CredentialStatus, DomainError> {
    match value {
        "active" => Ok(CredentialStatus::Active),
        "disabled" => Ok(CredentialStatus::Disabled),
        "revoked" => Ok(CredentialStatus::Revoked),
        _ => Err(invalid_stored_value()),
    }
}

fn totp_algorithm(value: &str) -> Result<TotpAlgorithm, DomainError> {
    match value {
        "sha1" => Ok(TotpAlgorithm::Sha1),
        "sha256" => Ok(TotpAlgorithm::Sha256),
        "sha512" => Ok(TotpAlgorithm::Sha512),
        _ => Err(invalid_stored_value()),
    }
}

fn session_audience(value: &str) -> Result<SessionAudience, DomainError> {
    match value {
        "account" => Ok(SessionAudience::Account),
        "admin" => Ok(SessionAudience::Admin),
        _ => Err(invalid_stored_value()),
    }
}

fn session_status(value: &str) -> Result<SessionStatus, DomainError> {
    match value {
        "active" => Ok(SessionStatus::Active),
        "revoked" => Ok(SessionStatus::Revoked),
        _ => Err(invalid_stored_value()),
    }
}

fn role_kind(value: &str) -> Result<RoleKind, DomainError> {
    match value {
        "owner" => Ok(RoleKind::Owner),
        "admin" => Ok(RoleKind::Admin),
        "member" => Ok(RoleKind::Member),
        "custom" => Ok(RoleKind::Custom),
        _ => Err(invalid_stored_value()),
    }
}

pub(crate) fn user_status_str(value: UserStatus) -> &'static str {
    match value {
        UserStatus::Active => "active",
        UserStatus::Suspended => "suspended",
        UserStatus::Deleted => "deleted",
    }
}

pub(crate) fn organization_status_str(value: OrganizationStatus) -> &'static str {
    match value {
        OrganizationStatus::Active => "active",
        OrganizationStatus::Suspended => "suspended",
        OrganizationStatus::Deleted => "deleted",
    }
}

pub(crate) fn application_kind_str(value: ApplicationKind) -> &'static str {
    match value {
        ApplicationKind::Web => "web",
        ApplicationKind::Admin => "admin",
        ApplicationKind::Native => "native",
        ApplicationKind::Service => "service",
        ApplicationKind::Cli => "cli",
    }
}

pub(crate) fn application_status_str(value: ApplicationStatus) -> &'static str {
    match value {
        ApplicationStatus::Active => "active",
        ApplicationStatus::Disabled => "disabled",
    }
}

pub(crate) fn membership_status_str(value: MembershipStatus) -> &'static str {
    match value {
        MembershipStatus::Invited => "invited",
        MembershipStatus::Active => "active",
        MembershipStatus::Suspended => "suspended",
        MembershipStatus::Removed => "removed",
    }
}

pub(crate) fn invitation_status_str(value: InvitationStatus) -> &'static str {
    match value {
        InvitationStatus::Pending => "pending",
        InvitationStatus::Accepted => "accepted",
        InvitationStatus::Revoked => "revoked",
    }
}

pub(crate) fn client_type_str(value: ClientType) -> &'static str {
    match value {
        ClientType::Confidential => "confidential",
        ClientType::Public => "public",
    }
}

pub(crate) fn client_status_str(value: ClientStatus) -> &'static str {
    match value {
        ClientStatus::Active => "active",
        ClientStatus::Disabled => "disabled",
    }
}

pub(crate) fn token_endpoint_auth_method_str(value: TokenEndpointAuthMethod) -> &'static str {
    match value {
        TokenEndpointAuthMethod::ClientSecretBasic => "client_secret_basic",
        TokenEndpointAuthMethod::ClientSecretPost => "client_secret_post",
        TokenEndpointAuthMethod::None => "none",
    }
}

pub(crate) fn grant_type_str(value: GrantType) -> &'static str {
    match value {
        GrantType::AuthorizationCode => "authorization_code",
        GrantType::RefreshToken => "refresh_token",
        GrantType::ClientCredentials => "client_credentials",
    }
}

pub(crate) fn credential_kind_str(value: CredentialKind) -> &'static str {
    match value {
        CredentialKind::Password => "password",
        CredentialKind::Passkey => "passkey",
        CredentialKind::Totp => "totp",
    }
}

pub(crate) fn credential_status_str(value: CredentialStatus) -> &'static str {
    match value {
        CredentialStatus::Active => "active",
        CredentialStatus::Disabled => "disabled",
        CredentialStatus::Revoked => "revoked",
    }
}

pub(crate) fn totp_algorithm_str(value: TotpAlgorithm) -> &'static str {
    match value {
        TotpAlgorithm::Sha1 => "sha1",
        TotpAlgorithm::Sha256 => "sha256",
        TotpAlgorithm::Sha512 => "sha512",
    }
}

pub(crate) fn session_audience_str(value: SessionAudience) -> &'static str {
    match value {
        SessionAudience::Account => "account",
        SessionAudience::Admin => "admin",
    }
}

pub(crate) fn session_status_str(value: SessionStatus) -> &'static str {
    match value {
        SessionStatus::Active => "active",
        SessionStatus::Revoked => "revoked",
    }
}

pub(crate) fn role_kind_str(value: RoleKind) -> &'static str {
    match value {
        RoleKind::Owner => "owner",
        RoleKind::Admin => "admin",
        RoleKind::Member => "member",
        RoleKind::Custom => "custom",
    }
}

pub(crate) fn transport_strings(values: &[AuthenticatorTransport]) -> Vec<String> {
    values
        .iter()
        .map(|value| value.as_str().to_owned())
        .collect()
}

pub(crate) fn audit_actor_parts(actor: &AuditActor) -> (&'static str, Option<String>) {
    match actor {
        AuditActor::User(id) => ("user", Some(id.as_str().to_owned())),
        AuditActor::Client(id) => ("client", Some(id.as_str().to_owned())),
        AuditActor::System => ("system", None),
        AuditActor::Anonymous => ("anonymous", None),
    }
}
