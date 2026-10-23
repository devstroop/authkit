use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use authkit_core::domain::id::{Entity, Id, OrganizationEntity, UserEntity};
use authkit_core::domain::{
    Application, ApplicationKind, AuditAction, AuditActor, AuditAttribute, AuditEvent, AuditTarget,
    AuthenticatorTransport, AuthorizationCode, ClientId, ClientType, Consent, Credential,
    DisplayName, DomainError, Email, EncryptedSecret, ErrorCode, GrantType, Invitation, Membership,
    Nonce, OAuthClient, OAuthClientSpec, Organization, PasskeyRegistration, PasswordVerifier,
    Permission, PermissionSet, PkceChallenge, RedirectUri, RefreshFamily, RefreshToken, Role,
    RoleBinding, Scope, ScopeSet, SecretHash, Session, SessionAudience, SessionStatus, Slug,
    TenantContext, Timestamp, TokenEndpointAuthMethod, TotpAlgorithm, TotpConfig, User,
    WriteOutcome,
};
use authkit_core::ports::write::{UnitOfWork, WriteBatch, WriteCommand};
use authkit_core::ports::{
    ApplicationRepository, AuditRepository, AuthorizationCodeRepository, ConsentRepository,
    CredentialRepository, InvitationRepository, MembershipRepository, OAuthClientRepository,
    OrganizationRepository, RefreshFamilyRepository, RefreshTokenRepository, Repositories,
    RoleBindingRepository, RoleRepository, SessionRepository, UserRepository,
};
use authkit_store::SqlStore;

const VALID_PHC: &str = "$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHRzb21lc2FsdA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

static NEXT_BASE: AtomicU64 = AtomicU64::new(0);

struct Fixture {
    tenant: TenantContext,
    user: User,
    organization: Organization,
    membership: Membership,
    application: Application,
    client: OAuthClient,
    role: Role,
    role2: Role,
    binding: RoleBinding,
    invitation: Invitation,
    code: AuthorizationCode,
    consent: Consent,
    family: RefreshFamily,
    token: RefreshToken,
    password: Credential,
    passkey: Credential,
    totp: Credential,
    session: Session,
    audit: AuditEvent,
}

fn typed_id<E: Entity>(value: u64) -> Id<E> {
    Id::from_suffix(&format!("{value:016x}")).expect("valid identifier suffix")
}

fn unique_base() -> u64 {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock after epoch")
        .as_nanos() as u64;
    let sequence = NEXT_BASE.fetch_add(1, Ordering::Relaxed);
    nanos.wrapping_add(sequence.wrapping_mul(0x9e37_79b9_7f4a_7c15))
}

fn fixture(base: u64) -> Result<Fixture, DomainError> {
    let now = Timestamp::from_millis(1_000);
    let idle_expires = Timestamp::from_millis(5_000);
    let expires = Timestamp::from_millis(10_000);
    let absolute_expires = Timestamp::from_millis(20_000);

    let user = User::new(
        typed_id(base.wrapping_add(1)),
        Email::parse(format!("owner-{base:016x}@example.com"))?,
        DisplayName::parse("Owner")?,
        now,
    );
    let organization = Organization::new(
        typed_id(base.wrapping_add(2)),
        Slug::parse(format!("org-{base:016x}"))?,
        DisplayName::parse("Contract Organization")?,
        now,
    );
    let tenant = TenantContext::new(organization.id().clone());
    let membership = Membership::active(
        typed_id(base.wrapping_add(3)),
        organization.id().clone(),
        user.id().clone(),
        now,
    );
    let application = Application::new(
        typed_id(base.wrapping_add(4)),
        organization.id().clone(),
        Slug::parse(format!("app-{base:016x}"))?,
        DisplayName::parse("Contract Application")?,
        ApplicationKind::Web,
        true,
        now,
    );
    let client = OAuthClient::new(
        typed_id(base.wrapping_add(5)),
        OAuthClientSpec {
            application_id: application.id().clone(),
            client_id: ClientId::parse(format!("client-{base:016x}"))?,
            name: DisplayName::parse("Contract Client")?,
            client_type: ClientType::Confidential,
            token_endpoint_auth_method: TokenEndpointAuthMethod::ClientSecretBasic,
            secret_hash: Some(SecretHash::parse(format!("sha256:{base:016x}client"))?),
            require_pkce: true,
            redirect_uris: vec![RedirectUri::parse("https://app.example.com/callback")?],
            post_logout_redirect_uris: vec![RedirectUri::parse("https://app.example.com/logout")?],
            allowed_scopes: ScopeSet::new([Scope::parse("openid")?, Scope::parse("email")?]),
            allowed_grant_types: vec![GrantType::AuthorizationCode, GrantType::RefreshToken],
        },
        now,
    )?;
    let role = Role::custom(
        typed_id(base.wrapping_add(6)),
        organization.id().clone(),
        Some(application.id().clone()),
        Slug::parse(format!("role-{base:016x}"))?,
        DisplayName::parse("Contract Role")?,
        Some("Contract test role".to_owned()),
        PermissionSet::new([Permission::parse("org.member.read")?]),
        now,
    )?;
    let role2 = Role::custom(
        typed_id(base.wrapping_add(7)),
        organization.id().clone(),
        None,
        Slug::parse(format!("role2-{base:016x}"))?,
        DisplayName::parse("Contract Role Two")?,
        None,
        PermissionSet::new([Permission::parse("org.audit.read")?]),
        now,
    )?;
    let binding = RoleBinding::organization(
        typed_id(base.wrapping_add(8)),
        organization.id().clone(),
        role.id().clone(),
        user.id().clone(),
        now,
    );
    let invitation = Invitation::new(
        typed_id(base.wrapping_add(9)),
        organization.id().clone(),
        Email::parse(format!("invitee-{base:016x}@example.com"))?,
        SecretHash::parse(format!("sha256:{base:016x}invite"))?,
        vec![role.id().clone()],
        user.id().clone(),
        now,
        expires,
    )?;
    let code = AuthorizationCode::new(
        typed_id(base.wrapping_add(10)),
        organization.id().clone(),
        application.id().clone(),
        client.id().clone(),
        user.id().clone(),
        SecretHash::parse(format!("sha256:{base:016x}code"))?,
        RedirectUri::parse("https://app.example.com/callback")?,
        ScopeSet::new([Scope::parse("openid")?, Scope::parse("email")?]),
        PkceChallenge::parse("A".repeat(43))?,
        Some(Nonce::parse("contract-nonce")?),
        now,
        None,
        now,
        expires,
    )?;
    let consent = Consent::new(
        typed_id(base.wrapping_add(11)),
        organization.id().clone(),
        user.id().clone(),
        client.id().clone(),
        ScopeSet::new([Scope::parse("openid")?, Scope::parse("email")?]),
        now,
    );
    let family = RefreshFamily::new(
        typed_id(base.wrapping_add(12)),
        organization.id().clone(),
        client.id().clone(),
        user.id().clone(),
        now,
        absolute_expires,
    )?;
    let token = RefreshToken::new(
        typed_id(base.wrapping_add(13)),
        family.id().clone(),
        SecretHash::parse(format!("sha256:{base:016x}refresh"))?,
        now,
        absolute_expires,
    )?;
    let password = Credential::password(
        typed_id(base.wrapping_add(14)),
        user.id().clone(),
        PasswordVerifier::parse(VALID_PHC)?,
        now,
    );
    let passkey = Credential::passkey(
        typed_id(base.wrapping_add(15)),
        user.id().clone(),
        PasskeyRegistration::new(
            base.to_be_bytes().to_vec(),
            vec![0xa0, 1, 2, 3, 4],
            [7; 16],
            vec![
                AuthenticatorTransport::Internal,
                AuthenticatorTransport::Hybrid,
            ],
            true,
            true,
            false,
        )?,
        now,
    );
    let totp = Credential::totp(
        typed_id(base.wrapping_add(16)),
        user.id().clone(),
        EncryptedSecret::new(format!("key-{base:016x}"), vec![1; 12], vec![2; 32])?,
        TotpConfig::new(TotpAlgorithm::Sha256, 8, 60)?,
        now,
    );
    let session = Session::new(
        typed_id(base.wrapping_add(17)),
        user.id().clone(),
        Some(organization.id().clone()),
        SessionAudience::Account,
        SecretHash::parse(format!("sha256:{base:016x}session"))?,
        now,
        idle_expires,
        absolute_expires,
        None,
    )?;
    let audit = AuditEvent::new(
        typed_id(base.wrapping_add(18)),
        Some(organization.id().clone()),
        AuditActor::User(user.id().clone()),
        AuditAction::parse("client.create")?,
        Some(AuditTarget::parse(client.id().as_str())?),
        now,
        vec![AuditAttribute::new("source", "contract")?],
    )?;

    Ok(Fixture {
        tenant,
        user,
        organization,
        membership,
        application,
        client,
        role,
        role2,
        binding,
        invitation,
        code,
        consent,
        family,
        token,
        password,
        passkey,
        totp,
        session,
        audit,
    })
}

fn insert_all<S: Repositories>(store: &S, fixture: &Fixture) {
    assert_eq!(
        UserRepository::insert(store, &fixture.user).expect("insert user"),
        WriteOutcome::Applied
    );
    assert_eq!(
        OrganizationRepository::insert(store, &fixture.organization).expect("insert organization"),
        WriteOutcome::Applied
    );
    assert_eq!(
        MembershipRepository::insert(store, &fixture.tenant, &fixture.membership)
            .expect("insert membership"),
        WriteOutcome::Applied
    );
    assert_eq!(
        ApplicationRepository::insert(store, &fixture.tenant, &fixture.application)
            .expect("insert application"),
        WriteOutcome::Applied
    );
    assert_eq!(
        OAuthClientRepository::insert(store, &fixture.tenant, &fixture.client)
            .expect("insert client"),
        WriteOutcome::Applied
    );
    assert_eq!(
        RoleRepository::insert(store, &fixture.tenant, &fixture.role).expect("insert role"),
        WriteOutcome::Applied
    );
    assert_eq!(
        RoleRepository::insert(store, &fixture.tenant, &fixture.role2).expect("insert second role"),
        WriteOutcome::Applied
    );
    assert_eq!(
        RoleBindingRepository::insert(store, &fixture.tenant, &fixture.binding)
            .expect("insert binding"),
        WriteOutcome::Applied
    );
    assert_eq!(
        InvitationRepository::insert(store, &fixture.tenant, &fixture.invitation)
            .expect("insert invitation"),
        WriteOutcome::Applied
    );
    assert_eq!(
        AuthorizationCodeRepository::insert(store, &fixture.tenant, &fixture.code)
            .expect("insert authorization code"),
        WriteOutcome::Applied
    );
    assert_eq!(
        ConsentRepository::insert(store, &fixture.tenant, &fixture.consent)
            .expect("insert consent"),
        WriteOutcome::Applied
    );
    assert_eq!(
        RefreshFamilyRepository::insert(store, &fixture.tenant, &fixture.family)
            .expect("insert refresh family"),
        WriteOutcome::Applied
    );
    assert_eq!(
        RefreshTokenRepository::insert(store, &fixture.tenant, &fixture.token)
            .expect("insert refresh token"),
        WriteOutcome::Applied
    );
    for credential in [&fixture.password, &fixture.passkey, &fixture.totp] {
        assert_eq!(
            CredentialRepository::insert(store, credential).expect("insert credential"),
            WriteOutcome::Applied
        );
    }
    assert_eq!(
        SessionRepository::insert(store, &fixture.session).expect("insert session"),
        WriteOutcome::Applied
    );
    assert_eq!(
        AuditRepository::append(store, &fixture.tenant, &fixture.audit).expect("append audit"),
        WriteOutcome::Applied
    );
}

fn assert_reads<S: Repositories>(store: &S, fixture: &Fixture) {
    assert_eq!(
        UserRepository::find_by_id(store, fixture.user.id()).expect("find user"),
        Some(fixture.user.clone())
    );
    assert_eq!(
        UserRepository::find_by_email(store, fixture.user.email()).expect("find user by email"),
        Some(fixture.user.clone())
    );
    assert_eq!(
        OrganizationRepository::find_by_id(store, fixture.organization.id())
            .expect("find organization"),
        Some(fixture.organization.clone())
    );
    assert_eq!(
        OrganizationRepository::find_by_slug(store, fixture.organization.slug())
            .expect("find organization by slug"),
        Some(fixture.organization.clone())
    );
    assert_eq!(
        MembershipRepository::find_by_id(store, &fixture.tenant, fixture.membership.id())
            .expect("find membership"),
        Some(fixture.membership.clone())
    );
    assert_eq!(
        MembershipRepository::find_by_user(store, &fixture.tenant, fixture.user.id())
            .expect("find membership by user"),
        Some(fixture.membership.clone())
    );
    assert_eq!(
        ApplicationRepository::find_by_id(store, &fixture.tenant, fixture.application.id())
            .expect("find application"),
        Some(fixture.application.clone())
    );
    assert_eq!(
        ApplicationRepository::find_by_slug(store, &fixture.tenant, fixture.application.slug())
            .expect("find application by slug"),
        Some(fixture.application.clone())
    );
    assert_eq!(
        OAuthClientRepository::find_by_id(store, &fixture.tenant, fixture.client.id())
            .expect("find client"),
        Some(fixture.client.clone())
    );
    assert_eq!(
        OAuthClientRepository::find_by_client_id(store, fixture.client.client_id())
            .expect("find client by public id"),
        Some(fixture.client.clone())
    );
    assert_eq!(
        RoleRepository::find_by_id(store, &fixture.tenant, fixture.role.id()).expect("find role"),
        Some(fixture.role.clone())
    );
    let roles = RoleRepository::list(store, &fixture.tenant).expect("list roles");
    assert_eq!(roles.len(), 2);
    assert!(roles.contains(&fixture.role));
    assert!(roles.contains(&fixture.role2));
    assert_eq!(
        RoleBindingRepository::list_for_user(store, &fixture.tenant, fixture.user.id())
            .expect("list bindings"),
        vec![fixture.binding.clone()]
    );
    assert_eq!(
        InvitationRepository::find_by_id(store, &fixture.tenant, fixture.invitation.id())
            .expect("find invitation"),
        Some(fixture.invitation.clone())
    );
    assert_eq!(
        AuthorizationCodeRepository::find_by_id(store, &fixture.tenant, fixture.code.id())
            .expect("find authorization code"),
        Some(fixture.code.clone())
    );
    assert_eq!(
        AuthorizationCodeRepository::find_by_hash(store, &fixture.tenant, fixture.code.code_hash())
            .expect("find authorization code by hash"),
        Some(fixture.code.clone())
    );
    assert_eq!(
        ConsentRepository::find_by_id(store, &fixture.tenant, fixture.consent.id())
            .expect("find consent"),
        Some(fixture.consent.clone())
    );
    assert_eq!(
        ConsentRepository::find_for_client_user(
            store,
            &fixture.tenant,
            fixture.client.id(),
            fixture.user.id()
        )
        .expect("find consent for client and user"),
        Some(fixture.consent.clone())
    );
    assert_eq!(
        RefreshFamilyRepository::find_by_id(store, &fixture.tenant, fixture.family.id())
            .expect("find refresh family"),
        Some(fixture.family.clone())
    );
    assert_eq!(
        RefreshTokenRepository::find_by_id(store, &fixture.tenant, fixture.token.id())
            .expect("find refresh token"),
        Some(fixture.token.clone())
    );
    assert_eq!(
        RefreshTokenRepository::find_by_hash(store, &fixture.tenant, fixture.token.token_hash())
            .expect("find refresh token by hash"),
        Some(fixture.token.clone())
    );
    for credential in [&fixture.password, &fixture.passkey, &fixture.totp] {
        assert_eq!(
            CredentialRepository::find_by_id(store, credential.id()).expect("find credential"),
            Some(credential.clone())
        );
    }
    let mut loaded_credentials =
        CredentialRepository::list_for_user(store, fixture.user.id()).expect("list credentials");
    let mut expected_credentials = vec![
        fixture.password.clone(),
        fixture.passkey.clone(),
        fixture.totp.clone(),
    ];
    loaded_credentials.sort_by(|left, right| left.id().as_str().cmp(right.id().as_str()));
    expected_credentials.sort_by(|left, right| left.id().as_str().cmp(right.id().as_str()));
    assert_eq!(loaded_credentials, expected_credentials);
    assert_eq!(
        SessionRepository::find_by_id(store, fixture.session.id()).expect("find session"),
        Some(fixture.session.clone())
    );
    assert_eq!(
        SessionRepository::find_by_token_hash(store, fixture.session.token_hash())
            .expect("find session by token hash"),
        Some(fixture.session.clone())
    );
}

fn assert_isolation<S: Repositories>(store: &S, fixture: &Fixture, base: u64) {
    let other = TenantContext::new(typed_id::<OrganizationEntity>(base.wrapping_add(0x900)));
    assert_eq!(
        MembershipRepository::find_by_id(store, &other, fixture.membership.id())
            .expect("find membership in other tenant"),
        None
    );
    assert_eq!(
        MembershipRepository::find_by_user(store, &other, fixture.user.id())
            .expect("find membership by user in other tenant"),
        None
    );
    assert_eq!(
        ApplicationRepository::find_by_id(store, &other, fixture.application.id())
            .expect("find application in other tenant"),
        None
    );
    assert_eq!(
        OAuthClientRepository::find_by_id(store, &other, fixture.client.id())
            .expect("find client in other tenant"),
        None
    );
    assert_eq!(
        RoleRepository::find_by_id(store, &other, fixture.role.id())
            .expect("find role in other tenant"),
        None
    );
    assert!(
        RoleRepository::list(store, &other)
            .expect("list roles in other tenant")
            .is_empty()
    );
    assert!(
        RoleBindingRepository::list_for_user(store, &other, fixture.user.id())
            .expect("list bindings in other tenant")
            .is_empty()
    );
    assert_eq!(
        InvitationRepository::find_by_id(store, &other, fixture.invitation.id())
            .expect("find invitation in other tenant"),
        None
    );
    assert_eq!(
        AuthorizationCodeRepository::find_by_id(store, &other, fixture.code.id())
            .expect("find authorization code in other tenant"),
        None
    );
    assert_eq!(
        AuthorizationCodeRepository::find_by_hash(store, &other, fixture.code.code_hash())
            .expect("find authorization code by hash in other tenant"),
        None
    );
    assert_eq!(
        ConsentRepository::find_by_id(store, &other, fixture.consent.id())
            .expect("find consent in other tenant"),
        None
    );
    assert_eq!(
        ConsentRepository::find_for_client_user(
            store,
            &other,
            fixture.client.id(),
            fixture.user.id()
        )
        .expect("find consent for client and user in other tenant"),
        None
    );
    assert_eq!(
        RefreshFamilyRepository::find_by_id(store, &other, fixture.family.id())
            .expect("find refresh family in other tenant"),
        None
    );
    assert_eq!(
        RefreshTokenRepository::find_by_id(store, &other, fixture.token.id())
            .expect("find refresh token in other tenant"),
        None
    );
    assert_eq!(
        RefreshTokenRepository::find_by_hash(store, &other, fixture.token.token_hash())
            .expect("find refresh token by hash in other tenant"),
        None
    );

    let forbidden = MembershipRepository::insert(store, &other, &fixture.membership)
        .expect_err("cross-tenant membership insert must fail");
    assert_eq!(forbidden.code(), ErrorCode::Forbidden);
    let forbidden = ApplicationRepository::insert(store, &other, &fixture.application)
        .expect_err("cross-tenant application insert must fail");
    assert_eq!(forbidden.code(), ErrorCode::Forbidden);
    let forbidden = OAuthClientRepository::insert(store, &other, &fixture.client)
        .expect_err("cross-tenant client insert must fail");
    assert_eq!(forbidden.code(), ErrorCode::Forbidden);
    let forbidden = RoleRepository::insert(store, &other, &fixture.role)
        .expect_err("cross-tenant role insert must fail");
    assert_eq!(forbidden.code(), ErrorCode::Forbidden);
    let forbidden = AuthorizationCodeRepository::insert(store, &other, &fixture.code)
        .expect_err("cross-tenant authorization code insert must fail");
    assert_eq!(forbidden.code(), ErrorCode::Forbidden);
    let forbidden = ConsentRepository::insert(store, &other, &fixture.consent)
        .expect_err("cross-tenant consent insert must fail");
    assert_eq!(forbidden.code(), ErrorCode::Forbidden);
    let forbidden = RefreshFamilyRepository::insert(store, &other, &fixture.family)
        .expect_err("cross-tenant refresh family insert must fail");
    assert_eq!(forbidden.code(), ErrorCode::Forbidden);
    let forbidden = RefreshTokenRepository::insert(store, &other, &fixture.token)
        .expect_err("cross-tenant refresh token insert must fail");
    assert_eq!(forbidden.code(), ErrorCode::Forbidden);
}

fn assert_updates<S: Repositories>(
    store: &S,
    fixture: &Fixture,
    base: u64,
) -> Result<(), DomainError> {
    let later = Timestamp::from_millis(2_000);

    let mut user = fixture.user.clone();
    user.rename(DisplayName::parse("Renamed Owner")?, later)?;
    assert_eq!(
        UserRepository::update(store, &user, 0).expect("update user"),
        WriteOutcome::Applied
    );
    assert_eq!(
        UserRepository::update(store, &user, 0).expect("repeat update user"),
        WriteOutcome::Conflict
    );
    assert_eq!(
        UserRepository::find_by_id(store, user.id())
            .expect("find updated user")
            .expect("updated user exists")
            .display_name(),
        user.display_name()
    );

    let mut organization = fixture.organization.clone();
    organization.rename(DisplayName::parse("Renamed Organization")?, later)?;
    assert_eq!(
        OrganizationRepository::update(store, &organization, 0).expect("update organization"),
        WriteOutcome::Applied
    );
    assert_eq!(
        OrganizationRepository::find_by_id(store, organization.id())
            .expect("find updated organization")
            .expect("updated organization exists")
            .name(),
        organization.name()
    );

    let mut application = fixture.application.clone();
    application.change_slug(Slug::parse(format!("app2-{base:016x}"))?, later);
    assert_eq!(
        ApplicationRepository::update(store, &fixture.tenant, &application, 0)
            .expect("update application"),
        WriteOutcome::Applied
    );
    assert_eq!(
        ApplicationRepository::find_by_id(store, &fixture.tenant, application.id())
            .expect("find updated application")
            .expect("updated application exists")
            .slug(),
        application.slug()
    );

    let mut membership = fixture.membership.clone();
    membership.suspend(later)?;
    assert_eq!(
        MembershipRepository::update(store, &fixture.tenant, &membership, 0)
            .expect("update membership"),
        WriteOutcome::Applied
    );

    let mut client = fixture.client.clone();
    client.add_redirect_uri(
        RedirectUri::parse("https://app.example.com/other-callback")?,
        later,
    )?;
    client.replace_scopes(
        ScopeSet::new([Scope::parse("openid")?, Scope::parse("profile")?]),
        later,
    );
    assert_eq!(
        OAuthClientRepository::update(store, &fixture.tenant, &client, 0).expect("update client"),
        WriteOutcome::Applied
    );
    let loaded_client = OAuthClientRepository::find_by_id(store, &fixture.tenant, client.id())
        .expect("find updated client")
        .expect("updated client exists");
    assert_eq!(loaded_client.redirect_uris().len(), 2);
    assert_eq!(loaded_client.allowed_scopes().as_slice().len(), 2);
    assert_eq!(
        OAuthClientRepository::find_by_client_id(store, client.client_id())
            .expect("find updated client by public id")
            .expect("updated client exists by public id")
            .redirect_uris()
            .len(),
        2
    );

    let mut role = fixture.role.clone();
    role.add_permission(Permission::parse("org.role.read")?, later)?;
    assert_eq!(
        RoleRepository::update(store, &fixture.tenant, &role, 0).expect("update role"),
        WriteOutcome::Applied
    );
    assert!(
        RoleRepository::find_by_id(store, &fixture.tenant, role.id())
            .expect("find updated role")
            .expect("updated role exists")
            .grants(&Permission::parse("org.role.read")?)
    );

    let invitation = Invitation::restore(
        fixture.invitation.id().clone(),
        fixture.organization.id().clone(),
        fixture.invitation.email().clone(),
        fixture.invitation.token_hash().clone(),
        vec![fixture.role.id().clone(), fixture.role2.id().clone()],
        fixture.invitation.invited_by().clone(),
        fixture.invitation.status(),
        fixture.invitation.expires_at(),
        fixture.invitation.accepted_at(),
        fixture.invitation.created_at(),
        later,
        1,
    )?;
    assert_eq!(
        InvitationRepository::update(store, &fixture.tenant, &invitation, 0)
            .expect("update invitation"),
        WriteOutcome::Applied
    );
    assert_eq!(
        InvitationRepository::find_by_id(store, &fixture.tenant, invitation.id())
            .expect("find updated invitation")
            .expect("updated invitation exists")
            .role_ids(),
        invitation.role_ids()
    );

    let mut code = fixture.code.clone();
    code.consume(later)?;
    assert_eq!(
        AuthorizationCodeRepository::update(store, &fixture.tenant, &code, 0)
            .expect("update authorization code"),
        WriteOutcome::Applied
    );
    assert_eq!(
        AuthorizationCodeRepository::find_by_id(store, &fixture.tenant, code.id())
            .expect("find updated authorization code")
            .expect("updated authorization code exists")
            .consumed_at(),
        Some(later)
    );

    let mut consent = fixture.consent.clone();
    consent.replace_scopes(ScopeSet::new([Scope::parse("openid")?]), later);
    assert_eq!(
        ConsentRepository::update(store, &fixture.tenant, &consent, 0).expect("update consent"),
        WriteOutcome::Applied
    );
    assert_eq!(
        ConsentRepository::find_by_id(store, &fixture.tenant, consent.id())
            .expect("find updated consent")
            .expect("updated consent exists")
            .scopes()
            .as_slice()
            .len(),
        1
    );

    let mut family = fixture.family.clone();
    family.revoke(later);
    assert_eq!(
        RefreshFamilyRepository::update(store, &fixture.tenant, &family, 0)
            .expect("update refresh family"),
        WriteOutcome::Applied
    );
    assert_eq!(
        RefreshFamilyRepository::find_by_id(store, &fixture.tenant, family.id())
            .expect("find updated refresh family")
            .expect("updated refresh family exists")
            .revoked_at(),
        Some(later)
    );

    let mut token = fixture.token.clone();
    token.consume(later)?;
    assert_eq!(
        RefreshTokenRepository::update(store, &fixture.tenant, &token, 0)
            .expect("update refresh token"),
        WriteOutcome::Applied
    );
    assert_eq!(
        RefreshTokenRepository::find_by_id(store, &fixture.tenant, token.id())
            .expect("find updated refresh token")
            .expect("updated refresh token exists")
            .consumed_at(),
        Some(later)
    );

    let mut password = fixture.password.clone();
    password.record_use(later)?;
    assert_eq!(
        CredentialRepository::update(store, &password, 0).expect("update password credential"),
        WriteOutcome::Applied
    );
    assert_eq!(
        CredentialRepository::find_by_id(store, password.id())
            .expect("find updated password credential")
            .expect("updated password credential exists")
            .last_used_at(),
        Some(later)
    );

    let mut passkey = fixture.passkey.clone();
    passkey.record_passkey_authentication(7, later)?;
    assert_eq!(
        CredentialRepository::update(store, &passkey, 0).expect("update passkey credential"),
        WriteOutcome::Applied
    );
    assert_eq!(
        CredentialRepository::find_by_id(store, passkey.id())
            .expect("find updated passkey credential")
            .expect("updated passkey credential exists")
            .as_passkey()
            .expect("passkey data")
            .sign_count(),
        7
    );

    let mut totp = fixture.totp.clone();
    totp.accept_totp_step(42, later)?;
    assert_eq!(
        CredentialRepository::update(store, &totp, 0).expect("update TOTP credential"),
        WriteOutcome::Applied
    );
    let loaded_totp = CredentialRepository::find_by_id(store, totp.id())
        .expect("find updated TOTP credential")
        .expect("updated TOTP credential exists");
    let loaded_totp_data = loaded_totp.as_totp().expect("TOTP data");
    assert_eq!(loaded_totp_data.last_accepted_step(), Some(42));
    assert_eq!(loaded_totp_data.config().period_seconds(), 60);

    let mut session = fixture.session.clone();
    session.revoke(later);
    assert_eq!(
        SessionRepository::update(store, &session, 0).expect("update session"),
        WriteOutcome::Applied
    );
    assert_eq!(
        SessionRepository::find_by_id(store, session.id())
            .expect("find updated session")
            .expect("updated session exists")
            .status(),
        SessionStatus::Revoked
    );

    Ok(())
}

fn assert_batch_atomicity<S: Repositories>(store: &S, base: u64) -> Result<(), DomainError> {
    let now = Timestamp::from_millis(2_000);
    let first = User::new(
        typed_id(base.wrapping_add(0x800)),
        Email::parse(format!("batch-{base:016x}@example.com"))?,
        DisplayName::parse("Batch First")?,
        now,
    );
    let second = User::new(
        typed_id(base.wrapping_add(0x801)),
        first.email().clone(),
        DisplayName::parse("Batch Second")?,
        now,
    );
    let batch = WriteBatch::new()
        .with(WriteCommand::InsertUser(first.clone()))
        .with(WriteCommand::InsertUser(second));
    assert_eq!(
        UnitOfWork::commit(store, &batch).expect("commit conflicting batch"),
        WriteOutcome::Conflict
    );
    assert_eq!(
        UserRepository::find_by_email(store, first.email()).expect("find rolled back user"),
        None
    );

    let missing = User::new(
        typed_id(base.wrapping_add(0x802)),
        Email::parse(format!("missing-{base:016x}@example.com"))?,
        DisplayName::parse("Missing User")?,
        now,
    );
    assert_eq!(
        UserRepository::update(store, &missing, 0).expect("update missing user"),
        WriteOutcome::NotFound
    );

    let orphan_organization = typed_id::<OrganizationEntity>(base.wrapping_add(0x803));
    let orphan = Membership::active(
        typed_id(base.wrapping_add(0x804)),
        orphan_organization.clone(),
        typed_id::<UserEntity>(base.wrapping_add(0x805)),
        now,
    );
    let orphan_tenant = TenantContext::new(orphan_organization);
    let error = MembershipRepository::insert(store, &orphan_tenant, &orphan)
        .expect_err("membership with missing references must fail");
    assert_eq!(error.code(), ErrorCode::NotFound);

    Ok(())
}

fn assert_binding_delete<S: Repositories>(store: &S, fixture: &Fixture) {
    assert_eq!(
        RoleBindingRepository::delete(store, &fixture.tenant, fixture.binding.id())
            .expect("delete binding"),
        WriteOutcome::Applied
    );
    assert!(
        RoleBindingRepository::list_for_user(store, &fixture.tenant, fixture.user.id())
            .expect("list bindings after delete")
            .is_empty()
    );
    assert_eq!(
        RoleBindingRepository::delete(store, &fixture.tenant, fixture.binding.id())
            .expect("delete missing binding"),
        WriteOutcome::NotFound
    );
}

fn run_contract<S: Repositories>(store: &S, base: u64) -> Result<Fixture, DomainError> {
    let fixture = fixture(base)?;
    insert_all(store, &fixture);
    assert_reads(store, &fixture);
    assert_isolation(store, &fixture, base);
    assert_updates(store, &fixture, base)?;
    assert_batch_atomicity(store, base)?;
    assert_eq!(
        UserRepository::insert(store, &fixture.user).expect("insert duplicate user"),
        WriteOutcome::Conflict
    );
    assert_binding_delete(store, &fixture);
    Ok(fixture)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn store_methods_run_from_spawn_blocking() {
    let outcome = tokio::task::spawn_blocking(|| {
        let store = SqlStore::sqlite_in_memory().expect("create SQLite store");
        store.migrate().expect("apply SQLite migrations");
        store
            .commit(&WriteBatch::new())
            .expect("commit empty batch")
    })
    .await
    .expect("blocking task");
    assert_eq!(outcome, WriteOutcome::Applied);
}

#[test]
fn sqlite_memory_url_shares_one_database() {
    let store = SqlStore::connect_sqlite("sqlite::memory:").expect("create SQLite store");
    store.migrate().expect("apply SQLite migrations");
    let tenant = TenantContext::new(typed_id::<OrganizationEntity>(unique_base()));
    let results = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..8)
            .map(|_| scope.spawn(|| store.list_audit_events(&tenant)))
            .collect();
        handles
            .into_iter()
            .map(|handle| handle.join().expect("join query thread"))
            .collect::<Vec<_>>()
    });
    assert!(results.into_iter().all(|result| result.is_ok()));
}

#[test]
fn sqlite_repository_contract() {
    let store = SqlStore::sqlite_in_memory().expect("create SQLite store");
    store.migrate().expect("apply SQLite migrations");
    store.migrate().expect("reapply SQLite migrations");
    let base = unique_base();
    let fixture = run_contract(&store, base).expect("run SQLite contract");
    assert_eq!(
        store
            .list_audit_events(&fixture.tenant)
            .expect("list audit events"),
        vec![fixture.audit.clone()]
    );
}

#[test]
fn postgres_repository_contract() {
    let Some(url) = std::env::var("TEST_POSTGRES_URL").ok() else {
        eprintln!("skipping Postgres contract: TEST_POSTGRES_URL is not set");
        return;
    };
    let store = SqlStore::connect_postgres(&url).expect("create Postgres store");
    store.migrate().expect("apply Postgres migrations");
    store.migrate().expect("reapply Postgres migrations");
    let base = unique_base();
    let fixture = run_contract(&store, base).expect("run Postgres contract");
    assert_eq!(
        store
            .list_audit_events(&fixture.tenant)
            .expect("list audit events"),
        vec![fixture.audit.clone()]
    );
}
