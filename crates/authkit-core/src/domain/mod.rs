//! Domain types and invariants.
//!
//! Domain modules do not know about transport, storage, templates, or runtime types.

pub mod application;
pub mod audit;
pub mod client_id;
pub mod credential;
pub mod email;
pub mod error;
pub mod grant;
pub mod id;
pub mod invitation;
pub mod membership;
pub mod name;
pub mod oauth_client;
pub mod organization;
pub mod permission;
pub mod pkce;
pub mod redirect_uri;
pub mod role;
pub mod scope;
pub mod secret;
pub mod session;
pub mod slug;
pub mod tenant;
pub mod time;
pub mod user;
pub mod value;
pub mod write;

pub use application::{Application, ApplicationKind, ApplicationStatus};
pub use audit::{AuditAction, AuditActor, AuditAttribute, AuditEvent, AuditTarget};
pub use client_id::ClientId;
pub use credential::{Credential, CredentialKind, CredentialStatus};
pub use email::Email;
pub use error::{DomainError, ErrorCode};
pub use grant::{AuthorizationCode, Consent, RefreshFamily, RefreshToken};
pub use id::{Entity, Id, IdError};
pub use invitation::{Invitation, InvitationStatus};
pub use membership::{Membership, MembershipStatus, ensure_owner_remains};
pub use name::DisplayName;
pub use oauth_client::{
    ClientStatus, ClientType, GrantType, OAuthClient, OAuthClientSpec, TokenEndpointAuthMethod,
};
pub use organization::{Organization, OrganizationStatus};
pub use permission::{Permission, PermissionSet};
pub use pkce::{Nonce, PkceChallenge};
pub use redirect_uri::RedirectUri;
pub use role::{Role, RoleBinding, RoleKind, RoleScope};
pub use scope::{Scope, ScopeSet};
pub use secret::SecretHash;
pub use session::{Session, SessionAudience, SessionStatus};
pub use slug::Slug;
pub use tenant::TenantContext;
pub use time::Timestamp;
pub use user::{User, UserStatus};
pub use value::ValueError;
pub use write::WriteOutcome;
