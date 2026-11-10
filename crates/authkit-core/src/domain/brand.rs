use crate::domain::DomainError;
use crate::domain::id::{ApplicationEntity, BrandEntity, Id};
use crate::domain::time::Timestamp;

/// A branding profile applied to a deployment or organization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Brand {
    id: Id<BrandEntity>,
    application_id: Option<Id<ApplicationEntity>>,
    domain: Option<String>,
    title: String,
    logo_url: Option<String>,
    favicon_url: Option<String>,
    custom_css: Option<String>,
    created_at: Timestamp,
    updated_at: Timestamp,
    version: u64,
}

impl Brand {
    /// Creates a new brand.
    pub fn new(
        id: Id<BrandEntity>,
        application_id: Option<Id<ApplicationEntity>>,
        domain: Option<String>,
        title: String,
        now: Timestamp,
    ) -> Self {
        Self {
            id,
            application_id,
            domain,
            title,
            logo_url: None,
            favicon_url: None,
            custom_css: None,
            created_at: now,
            updated_at: now,
            version: 0,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn restore(
        id: Id<BrandEntity>,
        application_id: Option<Id<ApplicationEntity>>,
        domain: Option<String>,
        title: String,
        logo_url: Option<String>,
        favicon_url: Option<String>,
        custom_css: Option<String>,
        created_at: Timestamp,
        updated_at: Timestamp,
        version: u64,
    ) -> Result<Self, DomainError> {
        if updated_at < created_at {
            return Err(DomainError::invalid(
                "brand updated_at must not precede created_at",
            ));
        }
        Ok(Self {
            id,
            application_id,
            domain,
            title,
            logo_url,
            favicon_url,
            custom_css,
            created_at,
            updated_at,
            version,
        })
    }

    pub const fn id(&self) -> &Id<BrandEntity> {
        &self.id
    }
    pub const fn application_id(&self) -> Option<&Id<ApplicationEntity>> {
        self.application_id.as_ref()
    }
    pub fn domain(&self) -> Option<&str> {
        self.domain.as_deref()
    }
    pub fn title(&self) -> &str {
        &self.title
    }
    pub fn logo_url(&self) -> Option<&str> {
        self.logo_url.as_deref()
    }
    pub fn favicon_url(&self) -> Option<&str> {
        self.favicon_url.as_deref()
    }
    pub fn custom_css(&self) -> Option<&str> {
        self.custom_css.as_deref()
    }
    pub const fn created_at(&self) -> Timestamp {
        self.created_at
    }
    pub const fn updated_at(&self) -> Timestamp {
        self.updated_at
    }
    pub const fn version(&self) -> u64 {
        self.version
    }

    pub fn update_title(&mut self, title: String, now: Timestamp) {
        self.title = title;
        self.touch(now);
    }
    pub fn set_logo_url(&mut self, url: Option<String>, now: Timestamp) {
        self.logo_url = url;
        self.touch(now);
    }
    pub fn set_favicon_url(&mut self, url: Option<String>, now: Timestamp) {
        self.favicon_url = url;
        self.touch(now);
    }
    pub fn set_custom_css(&mut self, css: Option<String>, now: Timestamp) {
        self.custom_css = css;
        self.touch(now);
    }

    fn touch(&mut self, now: Timestamp) {
        self.updated_at = now;
        self.version += 1;
    }
}

impl Brand {
    pub fn set_domain(&mut self, domain: Option<String>, now: Timestamp) {
        self.domain = domain;
        self.touch(now);
    }
    pub fn set_org(&mut self, application_id: Option<Id<ApplicationEntity>>, now: Timestamp) {
        self.application_id = application_id;
        self.touch(now);
    }
}
