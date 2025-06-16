use reqsign_core::Context;

/// Config carries all the configuration for Google services.
#[derive(Clone, Debug)]
pub struct Config {
    /// Credential file path.
    pub credential_path: Option<String>,
    /// Credential content.
    pub credential_content: Option<String>,
    /// Disable reading from environment variables.
    pub disable_env: bool,
    /// Disable reading from well-known locations.
    pub disable_well_known_location: bool,
    /// Service to be used (e.g., "storage" for Google Cloud Storage).
    pub service: Option<String>,
    /// Region to be used.
    pub region: Option<String>,
    /// Scope for OAuth2 token requests.
    pub scope: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            credential_path: None,
            credential_content: None,
            disable_env: false,
            disable_well_known_location: false,
            service: None,
            region: Some("auto".to_string()),
            scope: None,
        }
    }
}

impl Config {
    /// Create a new config.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set credential file path.
    pub fn with_credential_path(mut self, path: impl Into<String>) -> Self {
        self.credential_path = Some(path.into());
        self
    }

    /// Set credential content.
    pub fn with_credential_content(mut self, content: impl Into<String>) -> Self {
        self.credential_content = Some(content.into());
        self
    }

    /// Disable reading from environment variables.
    pub fn with_disable_env(mut self) -> Self {
        self.disable_env = true;
        self
    }

    /// Disable reading from well-known locations.
    pub fn with_disable_well_known_location(mut self) -> Self {
        self.disable_well_known_location = true;
        self
    }

    /// Set the service name.
    pub fn with_service(mut self, service: impl Into<String>) -> Self {
        self.service = Some(service.into());
        self
    }

    /// Set the region.
    pub fn with_region(mut self, region: impl Into<String>) -> Self {
        self.region = Some(region.into());
        self
    }

    /// Set the OAuth2 scope.
    pub fn with_scope(mut self, scope: impl Into<String>) -> Self {
        self.scope = Some(scope.into());
        self
    }

    /// Load config from environment variables.
    pub fn from_env(ctx: &Context) -> Self {
        let mut cfg = Self::default();

        if let Some(v) = ctx.env_var("GOOGLE_APPLICATION_CREDENTIALS") {
            cfg.credential_path = Some(v);
        }

        if let Some(v) = ctx.env_var("GOOGLE_SERVICE") {
            cfg.service = Some(v);
        }

        if let Some(v) = ctx.env_var("GOOGLE_REGION") {
            cfg.region = Some(v);
        }

        if let Some(v) = ctx.env_var("GOOGLE_SCOPE") {
            cfg.scope = Some(v);
        }

        cfg
    }
}
