//! Application use-case tests backed by an in-memory unit of work.

use std::cell::{Cell, RefCell};

use authkit_core::application::{CreateOrganization, CreateUser};
use authkit_core::domain::id::{
    ApplicationEntity, Id as TypedId, MembershipEntity, OAuthClientEntity, OrganizationEntity,
    RoleBindingEntity, RoleEntity, UserEntity,
};
use authkit_core::domain::write::WriteOutcome;
use authkit_core::domain::{
    AuditAction, AuditActor, AuditEvent, AuthorizationCode, DisplayName, DomainError, Email,
    Entity, ErrorCode, IdError, Invitation, InvitationStatus, Membership, Organization,
    PkceChallenge, RedirectUri, RefreshFamily, RefreshToken, Role, RoleBinding, Scope, ScopeSet,
    SecretHash, Slug, TenantContext, Timestamp, User,
};
use authkit_core::ports::write::{EntityKind, UnitOfWork, WriteBatch, WriteCommand};
use authkit_core::ports::{
    Clock, IdGenerator, MembershipRepository, OrganizationRepository, RoleBindingRepository,
    RoleRepository, UserRepository,
};

#[derive(Default)]
struct SequentialIds {
    next: Cell<u64>,
}

impl IdGenerator for SequentialIds {
    fn generate<E: Entity>(&self) -> Result<TypedId<E>, IdError> {
        let value = self.next.get();
        self.next.set(value.saturating_add(1));
        TypedId::from_suffix(&format!("{value:016x}"))
    }
}

struct FixedClock(Timestamp);

impl Clock for FixedClock {
    fn now(&self) -> Timestamp {
        self.0
    }
}

#[derive(Clone, Default)]
struct Data {
    users: Vec<User>,
    organizations: Vec<Organization>,
    memberships: Vec<Membership>,
    roles: Vec<Role>,
    bindings: Vec<RoleBinding>,
    invitations: Vec<Invitation>,
    authorization_codes: Vec<AuthorizationCode>,
    refresh_families: Vec<RefreshFamily>,
    refresh_tokens: Vec<RefreshToken>,
    audits: Vec<AuditEvent>,
    fail_on: Option<EntityKind>,
}

#[derive(Default)]
struct MemoryStore {
    data: RefCell<Data>,
}

impl MemoryStore {
    fn fail_on(&self, kind: EntityKind) {
        self.data.borrow_mut().fail_on = Some(kind);
    }

    fn seed_user(&self, user: User) {
        self.data.borrow_mut().users.push(user);
    }

    fn organizations(&self) -> Vec<Organization> {
        self.data.borrow().organizations.clone()
    }

    fn memberships(&self) -> Vec<Membership> {
        self.data.borrow().memberships.clone()
    }

    fn roles(&self) -> Vec<Role> {
        self.data.borrow().roles.clone()
    }

    fn bindings(&self) -> Vec<RoleBinding> {
        self.data.borrow().bindings.clone()
    }

    fn invitations(&self) -> Vec<Invitation> {
        self.data.borrow().invitations.clone()
    }

    fn authorization_codes(&self) -> Vec<AuthorizationCode> {
        self.data.borrow().authorization_codes.clone()
    }

    fn refresh_families(&self) -> Vec<RefreshFamily> {
        self.data.borrow().refresh_families.clone()
    }

    fn refresh_tokens(&self) -> Vec<RefreshToken> {
        self.data.borrow().refresh_tokens.clone()
    }

    fn audits(&self) -> Vec<AuditEvent> {
        self.data.borrow().audits.clone()
    }
}

impl UserRepository for MemoryStore {
    fn find_by_id(&self, id: &TypedId<UserEntity>) -> Result<Option<User>, DomainError> {
        Ok(self
            .data
            .borrow()
            .users
            .iter()
            .find(|user| user.id() == id)
            .cloned())
    }

    fn find_by_email(&self, email: &Email) -> Result<Option<User>, DomainError> {
        Ok(self
            .data
            .borrow()
            .users
            .iter()
            .find(|user| user.email() == email)
            .cloned())
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

impl OrganizationRepository for MemoryStore {
    fn find_by_id(
        &self,
        id: &TypedId<OrganizationEntity>,
    ) -> Result<Option<Organization>, DomainError> {
        Ok(self
            .data
            .borrow()
            .organizations
            .iter()
            .find(|organization| organization.id() == id)
            .cloned())
    }

    fn find_by_slug(&self, slug: &Slug) -> Result<Option<Organization>, DomainError> {
        Ok(self
            .data
            .borrow()
            .organizations
            .iter()
            .find(|organization| organization.slug() == slug)
            .cloned())
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

impl MembershipRepository for MemoryStore {
    fn find_by_id(
        &self,
        tenant: &TenantContext,
        id: &TypedId<MembershipEntity>,
    ) -> Result<Option<Membership>, DomainError> {
        Ok(self
            .data
            .borrow()
            .memberships
            .iter()
            .find(|membership| {
                membership.organization_id() == tenant.organization_id() && membership.id() == id
            })
            .cloned())
    }

    fn find_by_user(
        &self,
        tenant: &TenantContext,
        user_id: &TypedId<UserEntity>,
    ) -> Result<Option<Membership>, DomainError> {
        Ok(self
            .data
            .borrow()
            .memberships
            .iter()
            .find(|membership| {
                membership.organization_id() == tenant.organization_id()
                    && membership.user_id() == user_id
            })
            .cloned())
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

impl RoleRepository for MemoryStore {
    fn find_by_id(
        &self,
        tenant: &TenantContext,
        id: &TypedId<RoleEntity>,
    ) -> Result<Option<Role>, DomainError> {
        Ok(self
            .data
            .borrow()
            .roles
            .iter()
            .find(|role| role.organization_id() == tenant.organization_id() && role.id() == id)
            .cloned())
    }

    fn list(&self, tenant: &TenantContext) -> Result<Vec<Role>, DomainError> {
        Ok(self
            .data
            .borrow()
            .roles
            .iter()
            .filter(|role| role.organization_id() == tenant.organization_id())
            .cloned()
            .collect())
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

impl RoleBindingRepository for MemoryStore {
    fn list_for_user(
        &self,
        tenant: &TenantContext,
        user_id: &TypedId<UserEntity>,
    ) -> Result<Vec<RoleBinding>, DomainError> {
        Ok(self
            .data
            .borrow()
            .bindings
            .iter()
            .filter(|binding| {
                binding.organization_id() == tenant.organization_id()
                    && binding.user_id() == user_id
            })
            .cloned()
            .collect())
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
        binding_id: &TypedId<RoleBindingEntity>,
    ) -> Result<WriteOutcome, DomainError> {
        self.commit(&WriteBatch::new().with(WriteCommand::DeleteRoleBinding {
            tenant: tenant.clone(),
            binding_id: binding_id.clone(),
        }))
    }
}

impl UnitOfWork for MemoryStore {
    fn commit(&self, batch: &WriteBatch) -> Result<WriteOutcome, DomainError> {
        let mut staged = self.data.borrow().clone();

        for command in batch.commands() {
            if staged.fail_on == Some(command.entity_kind()) {
                return Err(DomainError::new(
                    ErrorCode::Unavailable,
                    "injected storage failure",
                ));
            }

            match command {
                WriteCommand::InsertUser(user) => {
                    if staged.users.iter().any(|existing| {
                        existing.id() == user.id() || existing.email() == user.email()
                    }) {
                        return Ok(WriteOutcome::Conflict);
                    }
                    staged.users.push(user.clone());
                }
                WriteCommand::UpdateUser {
                    user,
                    expected_version,
                } => {
                    let Some(existing) = staged
                        .users
                        .iter_mut()
                        .find(|existing| existing.id() == user.id())
                    else {
                        return Ok(WriteOutcome::NotFound);
                    };
                    if existing.version() != *expected_version {
                        return Ok(WriteOutcome::Conflict);
                    }
                    *existing = user.clone();
                }
                WriteCommand::InsertOrganization(organization) => {
                    if staged
                        .organizations
                        .iter()
                        .any(|existing| existing.slug() == organization.slug())
                    {
                        return Ok(WriteOutcome::Conflict);
                    }
                    staged.organizations.push(organization.clone());
                }
                WriteCommand::UpdateOrganization {
                    organization,
                    expected_version,
                } => {
                    let Some(existing) = staged
                        .organizations
                        .iter_mut()
                        .find(|existing| existing.id() == organization.id())
                    else {
                        return Ok(WriteOutcome::NotFound);
                    };
                    if existing.version() != *expected_version {
                        return Ok(WriteOutcome::Conflict);
                    }
                    *existing = organization.clone();
                }
                WriteCommand::InsertMembership { tenant, membership } => {
                    if staged.memberships.iter().any(|existing| {
                        existing.organization_id() == tenant.organization_id()
                            && existing.user_id() == membership.user_id()
                    }) {
                        return Ok(WriteOutcome::Conflict);
                    }
                    staged.memberships.push(membership.clone());
                }
                WriteCommand::UpdateMembership {
                    tenant,
                    membership,
                    expected_version,
                } => {
                    let Some(existing) = staged.memberships.iter_mut().find(|existing| {
                        existing.organization_id() == tenant.organization_id()
                            && existing.id() == membership.id()
                    }) else {
                        return Ok(WriteOutcome::NotFound);
                    };
                    if existing.version() != *expected_version {
                        return Ok(WriteOutcome::Conflict);
                    }
                    *existing = membership.clone();
                }
                WriteCommand::InsertRole { tenant, role } => {
                    if staged.roles.iter().any(|existing| {
                        existing.organization_id() == tenant.organization_id()
                            && (existing.id() == role.id() || existing.slug() == role.slug())
                    }) {
                        return Ok(WriteOutcome::Conflict);
                    }
                    staged.roles.push(role.clone());
                }
                WriteCommand::UpdateRole {
                    tenant,
                    role,
                    expected_version,
                } => {
                    let Some(existing) = staged.roles.iter_mut().find(|existing| {
                        existing.organization_id() == tenant.organization_id()
                            && existing.id() == role.id()
                    }) else {
                        return Ok(WriteOutcome::NotFound);
                    };
                    if existing.version() != *expected_version {
                        return Ok(WriteOutcome::Conflict);
                    }
                    *existing = role.clone();
                }
                WriteCommand::InsertRoleBinding { tenant, binding } => {
                    if staged.bindings.iter().any(|existing| {
                        existing.organization_id() == tenant.organization_id()
                            && (existing.id() == binding.id()
                                || (existing.role_id() == binding.role_id()
                                    && existing.user_id() == binding.user_id()
                                    && existing.application_id() == binding.application_id()))
                    }) {
                        return Ok(WriteOutcome::Conflict);
                    }
                    staged.bindings.push(binding.clone());
                }
                WriteCommand::DeleteRoleBinding { tenant, binding_id } => {
                    let before = staged.bindings.len();
                    staged.bindings.retain(|existing| {
                        !(existing.organization_id() == tenant.organization_id()
                            && existing.id() == binding_id)
                    });
                    if staged.bindings.len() == before {
                        return Ok(WriteOutcome::NotFound);
                    }
                }
                WriteCommand::InsertInvitation { tenant, invitation } => {
                    if staged.invitations.iter().any(|existing| {
                        existing.organization_id() == tenant.organization_id()
                            && (existing.id() == invitation.id()
                                || existing.token_hash() == invitation.token_hash())
                    }) {
                        return Ok(WriteOutcome::Conflict);
                    }
                    staged.invitations.push(invitation.clone());
                }
                WriteCommand::UpdateInvitation {
                    tenant,
                    invitation,
                    expected_version,
                } => {
                    let Some(existing) = staged.invitations.iter_mut().find(|existing| {
                        existing.organization_id() == tenant.organization_id()
                            && existing.id() == invitation.id()
                    }) else {
                        return Ok(WriteOutcome::NotFound);
                    };
                    if existing.version() != *expected_version {
                        return Ok(WriteOutcome::Conflict);
                    }
                    *existing = invitation.clone();
                }
                WriteCommand::InsertAuthorizationCode { tenant, code } => {
                    if staged.authorization_codes.iter().any(|existing| {
                        existing.organization_id() == tenant.organization_id()
                            && (existing.id() == code.id()
                                || existing.code_hash() == code.code_hash())
                    }) {
                        return Ok(WriteOutcome::Conflict);
                    }
                    staged.authorization_codes.push(code.clone());
                }
                WriteCommand::UpdateAuthorizationCode {
                    tenant,
                    code,
                    expected_version,
                } => {
                    let Some(existing) = staged.authorization_codes.iter_mut().find(|existing| {
                        existing.organization_id() == tenant.organization_id()
                            && existing.id() == code.id()
                    }) else {
                        return Ok(WriteOutcome::NotFound);
                    };
                    if existing.version() != *expected_version {
                        return Ok(WriteOutcome::Conflict);
                    }
                    *existing = code.clone();
                }
                WriteCommand::InsertRefreshFamily { tenant, family } => {
                    if staged.refresh_families.iter().any(|existing| {
                        existing.organization_id() == tenant.organization_id()
                            && existing.id() == family.id()
                    }) {
                        return Ok(WriteOutcome::Conflict);
                    }
                    staged.refresh_families.push(family.clone());
                }
                WriteCommand::UpdateRefreshFamily {
                    tenant,
                    family,
                    expected_version,
                } => {
                    let Some(existing) = staged.refresh_families.iter_mut().find(|existing| {
                        existing.organization_id() == tenant.organization_id()
                            && existing.id() == family.id()
                    }) else {
                        return Ok(WriteOutcome::NotFound);
                    };
                    if existing.version() != *expected_version {
                        return Ok(WriteOutcome::Conflict);
                    }
                    *existing = family.clone();
                }
                WriteCommand::InsertRefreshToken { token, .. } => {
                    if staged.refresh_tokens.iter().any(|existing| {
                        existing.id() == token.id() || existing.token_hash() == token.token_hash()
                    }) {
                        return Ok(WriteOutcome::Conflict);
                    }
                    staged.refresh_tokens.push(token.clone());
                }
                WriteCommand::UpdateRefreshToken {
                    token,
                    expected_version,
                    ..
                } => {
                    let Some(existing) = staged
                        .refresh_tokens
                        .iter_mut()
                        .find(|existing| existing.id() == token.id())
                    else {
                        return Ok(WriteOutcome::NotFound);
                    };
                    if existing.version() != *expected_version {
                        return Ok(WriteOutcome::Conflict);
                    }
                    *existing = token.clone();
                }
                WriteCommand::AppendAudit { event, .. } => {
                    staged.audits.push(event.clone());
                }
                _ => {
                    return Err(DomainError::new(
                        ErrorCode::Unavailable,
                        "command is not supported by the in-memory test store",
                    ));
                }
            }
        }

        *self.data.borrow_mut() = staged;
        Ok(WriteOutcome::Applied)
    }
}

fn email() -> Email {
    Email::parse("owner@example.com").expect("valid email")
}

fn name() -> DisplayName {
    DisplayName::parse("Owner").expect("valid name")
}

fn slug() -> Slug {
    Slug::parse("acme").expect("valid slug")
}

fn now() -> Timestamp {
    Timestamp::from_millis(1_000)
}

fn owner() -> User {
    User::new(
        TypedId::<UserEntity>::from_suffix("00000000000000aa").expect("valid id"),
        email(),
        name(),
        now(),
    )
}

fn organization_id() -> TypedId<OrganizationEntity> {
    TypedId::from_suffix("00000000000000bb").expect("valid id")
}

fn tenant() -> TenantContext {
    TenantContext::new(organization_id())
}

fn audit_event(action: &str) -> AuditEvent {
    AuditEvent::new(
        TypedId::from_suffix("00000000000000cc").expect("valid id"),
        Some(organization_id()),
        AuditActor::System,
        AuditAction::parse(action).expect("valid action"),
        None,
        now(),
        Vec::new(),
    )
    .expect("valid audit event")
}

fn authorization_code() -> AuthorizationCode {
    AuthorizationCode::new(
        TypedId::from_suffix("00000000000000dd").expect("valid id"),
        organization_id(),
        TypedId::<ApplicationEntity>::from_suffix("00000000000000ee").expect("valid id"),
        TypedId::<OAuthClientEntity>::from_suffix("00000000000000ff").expect("valid id"),
        owner().id().clone(),
        SecretHash::parse("sha256:0123456789abcdef").expect("valid hash"),
        RedirectUri::parse("https://client.example/callback").expect("valid redirect"),
        ScopeSet::new([
            Scope::parse("openid").expect("valid scope"),
            Scope::parse("profile").expect("valid scope"),
        ]),
        PkceChallenge::parse("A".repeat(43)).expect("valid challenge"),
        None,
        now(),
        Timestamp::from_millis(2_000),
    )
    .expect("valid authorization code")
}

fn refresh_family() -> RefreshFamily {
    RefreshFamily::new(
        TypedId::from_suffix("00000000000000ba").expect("valid id"),
        organization_id(),
        TypedId::<OAuthClientEntity>::from_suffix("00000000000000ff").expect("valid id"),
        owner().id().clone(),
        now(),
        Timestamp::from_millis(10_000),
    )
    .expect("valid refresh family")
}

fn refresh_token(family: &RefreshFamily) -> RefreshToken {
    RefreshToken::new(
        TypedId::from_suffix("00000000000000ca").expect("valid id"),
        family.id().clone(),
        SecretHash::parse("sha256:0011223344556677").expect("valid hash"),
        now(),
        Timestamp::from_millis(2_000),
    )
    .expect("valid refresh token")
}

fn invitation() -> Invitation {
    Invitation::new(
        TypedId::from_suffix("00000000000000ab").expect("valid id"),
        organization_id(),
        Email::parse("invitee@example.com").expect("valid email"),
        SecretHash::parse("sha256:fedcba9876543210").expect("valid hash"),
        vec![TypedId::<RoleEntity>::from_suffix("00000000000000cd").expect("valid id")],
        owner().id().clone(),
        now(),
        Timestamp::from_millis(2_000),
    )
    .expect("valid invitation")
}

#[test]
fn create_user_can_be_called_with_a_dyn_clock() {
    let store = MemoryStore::default();
    let clock = FixedClock(now());
    let user = CreateUser {
        email: email(),
        display_name: name(),
    }
    .execute(&store, &clock, &SequentialIds::default())
    .expect("create user");

    assert_eq!(user.email(), &email());
    assert!(store.find_by_email(&email()).expect("lookup").is_some());
}

#[test]
fn create_organization_provisions_an_active_owner() {
    let store = MemoryStore::default();
    let owner = owner();
    store.seed_user(owner.clone());
    let ids = SequentialIds::default();

    let organization = CreateOrganization {
        slug: slug(),
        name: name(),
        owner_id: owner.id().clone(),
    }
    .execute(&store, &FixedClock(now()), &ids)
    .expect("create organization");

    let memberships = store.memberships();
    assert_eq!(memberships.len(), 1);
    assert!(memberships[0].is_active());
    assert_eq!(memberships[0].user_id(), owner.id());
    assert_eq!(memberships[0].organization_id(), organization.id());

    let roles = store.roles();
    assert_eq!(roles.len(), 1);
    assert_eq!(roles[0].kind(), authkit_core::domain::RoleKind::Owner);

    let bindings = store.bindings();
    assert_eq!(bindings.len(), 1);
    assert_eq!(bindings[0].user_id(), owner.id());
    assert_eq!(bindings[0].role_id(), roles[0].id());
    assert_eq!(bindings[0].organization_id(), organization.id());

    let audits = store.audits();
    assert_eq!(audits.len(), 1);
    assert_eq!(audits[0].action().as_str(), "organization.create");
    assert_eq!(audits[0].organization_id(), Some(organization.id()));
}

#[test]
fn create_organization_rejects_a_missing_owner() {
    let store = MemoryStore::default();
    let owner = owner();

    let error = CreateOrganization {
        slug: slug(),
        name: name(),
        owner_id: owner.id().clone(),
    }
    .execute(&store, &FixedClock(now()), &SequentialIds::default())
    .expect_err("missing owner");

    assert_eq!(error.code(), ErrorCode::NotFound);
    assert!(store.organizations().is_empty());
    assert!(store.memberships().is_empty());
}

#[test]
fn create_organization_rejects_an_inactive_owner() {
    let store = MemoryStore::default();
    let mut owner = owner();
    owner.suspend(now()).expect("suspend");
    store.seed_user(owner.clone());

    let error = CreateOrganization {
        slug: slug(),
        name: name(),
        owner_id: owner.id().clone(),
    }
    .execute(&store, &FixedClock(now()), &SequentialIds::default())
    .expect_err("inactive owner");

    assert_eq!(error.code(), ErrorCode::Forbidden);
    assert!(store.organizations().is_empty());
}

#[test]
fn create_organization_rolls_back_every_write_when_a_late_command_fails() {
    let store = MemoryStore::default();
    let owner = owner();
    store.seed_user(owner.clone());
    store.fail_on(EntityKind::RoleBinding);

    let error = CreateOrganization {
        slug: slug(),
        name: name(),
        owner_id: owner.id().clone(),
    }
    .execute(&store, &FixedClock(now()), &SequentialIds::default())
    .expect_err("injected failure");

    assert_eq!(error.code(), ErrorCode::Unavailable);
    assert!(store.organizations().is_empty());
    assert!(store.memberships().is_empty());
    assert!(store.roles().is_empty());
    assert!(store.bindings().is_empty());
    assert!(store.audits().is_empty());
}

#[test]
fn duplicate_slugs_lose_the_race_without_partial_owner_state() {
    let store = MemoryStore::default();
    let owner = owner();
    store.seed_user(owner.clone());
    let ids = SequentialIds::default();
    let command = CreateOrganization {
        slug: slug(),
        name: name(),
        owner_id: owner.id().clone(),
    };

    command
        .execute(&store, &FixedClock(now()), &ids)
        .expect("first organization");
    let error = command
        .execute(&store, &FixedClock(now()), &ids)
        .expect_err("duplicate slug");

    assert_eq!(error.code(), ErrorCode::Conflict);
    assert_eq!(store.organizations().len(), 1);
    assert_eq!(store.memberships().len(), 1);
    assert_eq!(store.roles().len(), 1);
    assert_eq!(store.bindings().len(), 1);
    assert_eq!(store.audits().len(), 1);
}

#[test]
fn a_guard_conflict_rolls_back_earlier_commands() {
    let store = MemoryStore::default();
    let owner = owner();
    store.seed_user(owner.clone());
    let ids = SequentialIds::default();

    let first = Organization::new(
        ids.generate::<OrganizationEntity>().expect("first org id"),
        Slug::parse("first").expect("valid slug"),
        name(),
        now(),
    );
    let mut membership = Membership::invited(
        ids.generate::<MembershipEntity>().expect("membership id"),
        first.id().clone(),
        owner.id().clone(),
        None,
        now(),
    );
    membership.activate(now()).expect("activate");
    assert_eq!(
        store
            .commit(
                &WriteBatch::new()
                    .with(WriteCommand::InsertOrganization(first.clone()))
                    .with(WriteCommand::InsertMembership {
                        tenant: TenantContext::new(first.id().clone()),
                        membership: membership.clone(),
                    })
            )
            .expect("seed commit"),
        WriteOutcome::Applied
    );

    let second = Organization::new(
        ids.generate::<OrganizationEntity>().expect("second org id"),
        Slug::parse("second").expect("valid slug"),
        name(),
        now(),
    );
    let conflicting = WriteBatch::new()
        .with(WriteCommand::InsertOrganization(second))
        .with(WriteCommand::UpdateMembership {
            tenant: TenantContext::new(first.id().clone()),
            membership,
            expected_version: 0,
        });

    assert_eq!(
        store.commit(&conflicting).expect("conflicting commit"),
        WriteOutcome::Conflict
    );
    assert_eq!(store.organizations().len(), 1);
    assert_eq!(store.organizations()[0].slug().as_str(), "first");
}

#[test]
fn authorization_code_consumption_is_guarded_and_atomic_with_audit() {
    let store = MemoryStore::default();
    let tenant = tenant();
    let code = authorization_code();

    assert_eq!(
        store
            .commit(
                &WriteBatch::new().with(WriteCommand::InsertAuthorizationCode {
                    tenant: tenant.clone(),
                    code: code.clone(),
                })
            )
            .expect("seed code"),
        WriteOutcome::Applied
    );

    let mut consumed = code.clone();
    consumed
        .consume(Timestamp::from_millis(1_500))
        .expect("consume code");

    let batch = WriteBatch::new()
        .with(WriteCommand::UpdateAuthorizationCode {
            tenant: tenant.clone(),
            code: consumed.clone(),
            expected_version: code.version(),
        })
        .with(WriteCommand::AppendAudit {
            tenant: tenant.clone(),
            event: audit_event("authorization_code.consume"),
        });

    assert_eq!(
        store.commit(&batch).expect("consume commit"),
        WriteOutcome::Applied
    );
    assert_eq!(
        store.authorization_codes()[0].consumed_at(),
        Some(Timestamp::from_millis(1_500))
    );
    assert_eq!(store.audits().len(), 1);

    let replay = WriteBatch::new()
        .with(WriteCommand::UpdateAuthorizationCode {
            tenant: tenant.clone(),
            code: consumed,
            expected_version: code.version(),
        })
        .with(WriteCommand::AppendAudit {
            tenant: tenant.clone(),
            event: audit_event("authorization_code.consume"),
        });

    assert_eq!(
        store.commit(&replay).expect("replay commit"),
        WriteOutcome::Conflict
    );
    assert_eq!(store.audits().len(), 1);
}

#[test]
fn invitation_acceptance_is_atomic_with_membership_and_audit() {
    let store = MemoryStore::default();
    let tenant = tenant();
    let invitation = invitation();

    assert_eq!(
        store
            .commit(&WriteBatch::new().with(WriteCommand::InsertInvitation {
                tenant: tenant.clone(),
                invitation: invitation.clone(),
            }))
            .expect("seed invitation"),
        WriteOutcome::Applied
    );

    let mut accepted = invitation.clone();
    accepted
        .accept(Timestamp::from_millis(1_500))
        .expect("accept invitation");
    let membership = Membership::active(
        TypedId::from_suffix("00000000000000bc").expect("valid id"),
        organization_id(),
        owner().id().clone(),
        Timestamp::from_millis(1_500),
    );

    let batch = WriteBatch::new()
        .with(WriteCommand::UpdateInvitation {
            tenant: tenant.clone(),
            invitation: accepted.clone(),
            expected_version: invitation.version(),
        })
        .with(WriteCommand::InsertMembership {
            tenant: tenant.clone(),
            membership,
        })
        .with(WriteCommand::AppendAudit {
            tenant: tenant.clone(),
            event: audit_event("invitation.accept"),
        });

    assert_eq!(
        store.commit(&batch).expect("accept commit"),
        WriteOutcome::Applied
    );
    assert_eq!(store.invitations()[0].status(), InvitationStatus::Accepted);
    assert_eq!(store.memberships().len(), 1);
    assert_eq!(store.audits().len(), 1);

    let replay = WriteBatch::new()
        .with(WriteCommand::UpdateInvitation {
            tenant: tenant.clone(),
            invitation: accepted,
            expected_version: invitation.version(),
        })
        .with(WriteCommand::AppendAudit {
            tenant: tenant.clone(),
            event: audit_event("invitation.accept"),
        });

    assert_eq!(
        store.commit(&replay).expect("replay commit"),
        WriteOutcome::Conflict
    );
    assert_eq!(store.memberships().len(), 1);
    assert_eq!(store.audits().len(), 1);
}

#[test]
fn refresh_rotation_and_family_revocation_are_one_atomic_guard() {
    let store = MemoryStore::default();
    let tenant = tenant();
    let family = refresh_family();
    let token = refresh_token(&family);

    assert_eq!(
        store
            .commit(
                &WriteBatch::new()
                    .with(WriteCommand::InsertRefreshFamily {
                        tenant: tenant.clone(),
                        family: family.clone(),
                    })
                    .with(WriteCommand::InsertRefreshToken {
                        tenant: tenant.clone(),
                        token: token.clone(),
                    })
            )
            .expect("seed refresh state"),
        WriteOutcome::Applied
    );

    let mut revoked_family = family.clone();
    revoked_family.revoke(Timestamp::from_millis(1_500));
    let mut consumed = token.clone();
    consumed
        .consume(Timestamp::from_millis(1_500))
        .expect("consume token");
    let replacement = RefreshToken::new(
        TypedId::from_suffix("00000000000000cb").expect("valid id"),
        family.id().clone(),
        SecretHash::parse("sha256:8899aabbccddeeff").expect("valid hash"),
        Timestamp::from_millis(1_500),
        Timestamp::from_millis(3_000),
    )
    .expect("valid replacement token");

    let batch = WriteBatch::new()
        .with(WriteCommand::UpdateRefreshFamily {
            tenant: tenant.clone(),
            family: revoked_family.clone(),
            expected_version: family.version(),
        })
        .with(WriteCommand::UpdateRefreshToken {
            tenant: tenant.clone(),
            token: consumed.clone(),
            expected_version: token.version(),
        })
        .with(WriteCommand::InsertRefreshToken {
            tenant: tenant.clone(),
            token: replacement,
        })
        .with(WriteCommand::AppendAudit {
            tenant: tenant.clone(),
            event: audit_event("refresh.rotate"),
        });

    assert_eq!(
        store.commit(&batch).expect("rotate commit"),
        WriteOutcome::Applied
    );
    assert_eq!(
        store.refresh_families()[0].revoked_at(),
        Some(Timestamp::from_millis(1_500))
    );
    assert_eq!(
        store.refresh_tokens()[0].consumed_at(),
        Some(Timestamp::from_millis(1_500))
    );
    assert_eq!(store.refresh_tokens().len(), 2);
    assert_eq!(store.audits().len(), 1);

    let replay = WriteBatch::new()
        .with(WriteCommand::UpdateRefreshToken {
            tenant: tenant.clone(),
            token: consumed,
            expected_version: token.version(),
        })
        .with(WriteCommand::AppendAudit {
            tenant: tenant.clone(),
            event: audit_event("refresh.rotate"),
        });

    assert_eq!(
        store.commit(&replay).expect("replay commit"),
        WriteOutcome::Conflict
    );
    assert_eq!(store.refresh_tokens().len(), 2);
    assert_eq!(store.audits().len(), 1);
}
