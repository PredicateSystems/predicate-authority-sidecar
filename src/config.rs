//! Configuration file support for predicate-authorityd.
//!
//! Supports TOML configuration files with the following precedence:
//! 1. CLI arguments (highest)
//! 2. Environment variables
//! 3. Configuration file
//! 4. Default values (lowest)

use serde::{Deserialize, Serialize};
use std::path::Path;

/// Root configuration structure
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Server configuration
    pub server: ServerConfig,

    /// Policy configuration
    pub policy: PolicyConfig,

    /// SSRF protection configuration
    pub ssrf: SsrfConfig,

    /// Identity registry configuration
    pub identity: IdentityConfig,

    /// Identity provider configuration
    pub idp: IdpConfig,

    /// Control-plane configuration
    pub control_plane: ControlPlaneFileConfig,

    /// Logging configuration
    pub logging: LoggingConfig,
}

/// SSRF protection configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct SsrfConfig {
    /// Allowed endpoints that bypass SSRF protection (host:port format)
    /// Example: ["172.30.192.1:11434", "127.0.0.1:9200"]
    pub allowed_endpoints: Vec<String>,

    /// Disable SSRF protection entirely (not recommended)
    pub disabled: bool,
}

/// Server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ServerConfig {
    /// Host to bind to
    pub host: String,

    /// Port to bind to
    pub port: u16,

    /// Operating mode: local_only or cloud_connected
    pub mode: String,

    /// Graceful shutdown timeout in seconds
    pub shutdown_timeout_s: u64,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            port: 8787,
            mode: "local_only".to_string(),
            shutdown_timeout_s: 30,
        }
    }
}

/// Policy configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct PolicyConfig {
    /// Path to policy JSON file
    pub file: Option<String>,

    /// Enable hot-reload of policy file
    pub hot_reload: bool,

    /// Hot-reload check interval in seconds
    pub hot_reload_interval_s: u64,

    /// Secret required for /policy/reload endpoint (bearer token)
    /// If set, requests must include `Authorization: Bearer <secret>`
    pub reload_secret: Option<String>,

    /// Disable the /policy/reload endpoint entirely
    /// If true, the endpoint returns 404
    pub disable_reload: bool,
}

/// Identity registry configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct IdentityConfig {
    /// Path to local identity registry JSON file
    pub file: Option<String>,

    /// Default TTL for task identities in seconds
    pub default_ttl_s: i64,

    /// TTL for queue items in seconds (24 hours default)
    pub queue_item_ttl_s: i64,
}

impl Default for IdentityConfig {
    fn default() -> Self {
        Self {
            file: None,
            default_ttl_s: 900,      // 15 minutes
            queue_item_ttl_s: 86400, // 24 hours
        }
    }
}

/// Identity provider configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct IdpConfig {
    /// Identity mode: local, local-idp, oidc, entra, or okta
    pub mode: String,

    /// Allow local/local-idp identity in cloud_connected mode
    pub allow_local_fallback: bool,

    /// IdP token TTL in seconds
    pub idp_token_ttl_s: i64,

    /// Mandate TTL in seconds
    pub mandate_ttl_s: i64,

    /// Local IdP configuration
    pub local_idp: LocalIdpConfig,

    /// OIDC configuration
    pub oidc: OidcConfig,

    /// Entra (Azure AD) configuration
    pub entra: EntraConfig,

    /// Okta configuration
    pub okta: OktaConfig,
}

impl Default for IdpConfig {
    fn default() -> Self {
        Self {
            mode: "local".to_string(),
            allow_local_fallback: false,
            idp_token_ttl_s: 300,
            mandate_ttl_s: 300,
            local_idp: LocalIdpConfig::default(),
            oidc: OidcConfig::default(),
            entra: EntraConfig::default(),
            okta: OktaConfig::default(),
        }
    }
}

/// Local IdP configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LocalIdpConfig {
    /// Issuer URL
    pub issuer: String,

    /// Audience
    pub audience: String,

    /// Environment variable name for signing key
    pub signing_key_env: String,
}

impl Default for LocalIdpConfig {
    fn default() -> Self {
        Self {
            issuer: "http://localhost/predicate-local-idp".to_string(),
            audience: "api://predicate-authority".to_string(),
            signing_key_env: "LOCAL_IDP_SIGNING_KEY".to_string(),
        }
    }
}

/// OIDC configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct OidcConfig {
    /// Issuer URL
    pub issuer: Option<String>,

    /// Client ID
    pub client_id: Option<String>,

    /// Audience
    pub audience: Option<String>,
}

/// Entra (Azure AD) configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct EntraConfig {
    /// Tenant ID
    pub tenant_id: Option<String>,

    /// Client ID
    pub client_id: Option<String>,

    /// Audience
    pub audience: Option<String>,
}

/// Okta configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct OktaConfig {
    /// Issuer URL
    pub issuer: Option<String>,

    /// Client ID
    pub client_id: Option<String>,

    /// Audience
    pub audience: Option<String>,

    /// Required claims (comma-separated)
    pub required_claims: Vec<String>,

    /// Required scopes (comma-separated)
    pub required_scopes: Vec<String>,

    /// Required roles/groups (comma-separated)
    pub required_roles: Vec<String>,

    /// Allowed tenant identifiers
    pub allowed_tenants: Vec<String>,

    /// Claim name for tenant identifier
    pub tenant_claim: String,

    /// Claim name for scopes
    pub scope_claim: String,

    /// Claim name for roles/groups
    pub role_claim: String,
}

impl Default for OktaConfig {
    fn default() -> Self {
        Self {
            issuer: None,
            client_id: None,
            audience: None,
            required_claims: Vec::new(),
            required_scopes: Vec::new(),
            required_roles: Vec::new(),
            allowed_tenants: Vec::new(),
            tenant_claim: "tenant_id".to_string(),
            scope_claim: "scope".to_string(),
            role_claim: "groups".to_string(),
        }
    }
}

/// Control-plane configuration (from file)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ControlPlaneFileConfig {
    /// Control-plane base URL
    pub url: Option<String>,

    /// Tenant ID
    pub tenant_id: Option<String>,

    /// Project ID
    pub project_id: Option<String>,

    /// API key (prefer env var PREDICATE_API_KEY for secrets)
    pub api_key: Option<String>,

    /// Enable sync
    pub sync_enabled: bool,

    /// Sync wait timeout in seconds
    pub sync_wait_timeout_s: f64,

    /// Environment for sync
    pub sync_environment: Option<String>,

    /// Fail open if control-plane unreachable
    pub fail_open: bool,

    /// Request timeout in seconds
    pub timeout_s: f64,

    /// Max retries
    pub max_retries: u32,
}

/// Logging configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LoggingConfig {
    /// Log level: trace, debug, info, warn, error
    pub level: String,

    /// Output format: compact, pretty, json
    pub format: String,

    /// Include target in log output
    pub include_target: bool,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            format: "compact".to_string(),
            include_target: true,
        }
    }
}

impl Config {
    /// Load configuration from a TOML file
    pub fn from_file(path: &Path) -> Result<Self, ConfigError> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| ConfigError::ReadError(path.display().to_string(), e.to_string()))?;

        toml::from_str(&content)
            .map_err(|e| ConfigError::ParseError(path.display().to_string(), e.to_string()))
    }

    /// Try to load from default locations
    pub fn from_default_locations() -> Option<Self> {
        let candidates = [
            // Current directory
            "./predicate-authorityd.toml".to_string(),
            "./config/predicate-authorityd.toml".to_string(),
            // Home directory
            format!(
                "{}/.predicate/authorityd.toml",
                std::env::var("HOME").unwrap_or_default()
            ),
            // System config
            "/etc/predicate/authorityd.toml".to_string(),
        ];

        for path in candidates {
            let p = Path::new(&path);
            if p.exists() {
                if let Ok(config) = Self::from_file(p) {
                    tracing::info!("Loaded configuration from: {}", path);
                    return Some(config);
                }
            }
        }

        None
    }

    /// Generate an example configuration file
    pub fn example_toml() -> String {
        r#"# Predicate Authority Daemon Configuration
# This file can be placed at:
#   ./predicate-authorityd.toml
#   ~/.predicate/authorityd.toml
#   /etc/predicate/authorityd.toml

[server]
host = "127.0.0.1"
port = 8787
mode = "local_only"  # or "cloud_connected"
shutdown_timeout_s = 30

[policy]
# file = "/path/to/policy.json"
hot_reload = false
hot_reload_interval_s = 30
# reload_secret = "your-secret-here"  # Require bearer token for /policy/reload
# disable_reload = false              # Set to true to disable /policy/reload entirely

# SSRF Protection Configuration
# By default, SSRF blocks private IPs, localhost, and cloud metadata endpoints
[ssrf]
# allowed_endpoints = ["172.30.192.1:11434", "127.0.0.1:9200"]  # Bypass SSRF for these
# disabled = false  # Set to true to disable all SSRF protection (not recommended)

[identity]
# file = "~/.predicate/local-identity-registry.json"
default_ttl_s = 900      # 15 minutes
queue_item_ttl_s = 86400 # 24 hours

# Identity Provider Configuration
# Supported modes: local, local-idp, oidc, entra, okta
[idp]
mode = "local"
allow_local_fallback = false  # Required when using local/local-idp in cloud_connected mode
idp_token_ttl_s = 300
mandate_ttl_s = 300           # Must be <= idp_token_ttl_s

# Local IdP settings (for local-idp mode)
[idp.local_idp]
issuer = "http://localhost/predicate-local-idp"
audience = "api://predicate-authority"
signing_key_env = "LOCAL_IDP_SIGNING_KEY"

# OIDC settings (for oidc mode)
[idp.oidc]
# issuer = "https://your-oidc-provider.com"
# client_id = "your-client-id"
# audience = "api://predicate-authority"

# Entra (Azure AD) settings (for entra mode)
[idp.entra]
# tenant_id = "your-tenant-id"
# client_id = "your-client-id"
# audience = "api://predicate-authority"

# Okta settings (for okta mode)
[idp.okta]
# issuer = "https://your-org.okta.com/oauth2/default"
# client_id = "your-client-id"
# audience = "api://predicate-authority"
# required_claims = ["sub", "tenant_id"]
# required_scopes = ["authority:check"]
# required_roles = ["authority-operator"]
# allowed_tenants = ["tenant-a", "tenant-b"]
tenant_claim = "tenant_id"
scope_claim = "scope"
role_claim = "groups"

[control_plane]
# url = "https://api.predicatesystems.dev"
# tenant_id = "your-tenant-id"
# project_id = "your-project-id"
# api_key = "prefer-env-var-PREDICATE_API_KEY"
sync_enabled = false
sync_wait_timeout_s = 15.0
# sync_environment = "production"
fail_open = true
timeout_s = 2.0
max_retries = 2

[logging]
level = "info"        # trace, debug, info, warn, error
format = "compact"    # compact, pretty, json
include_target = true
"#
        .to_string()
    }
}

/// Configuration error types
#[derive(Debug, Clone, thiserror::Error)]
pub enum ConfigError {
    #[error("Failed to read config file '{0}': {1}")]
    ReadError(String, String),

    #[error("Failed to parse config file '{0}': {1}")]
    ParseError(String, String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.server.host, "127.0.0.1");
        assert_eq!(config.server.port, 8787);
        assert_eq!(config.server.mode, "local_only");
        assert_eq!(config.logging.level, "info");
    }

    #[test]
    fn test_parse_toml() {
        let toml_content = r#"
[server]
host = "0.0.0.0"
port = 9000
mode = "cloud_connected"

[logging]
level = "debug"
"#;

        let config: Config = toml::from_str(toml_content).unwrap();
        assert_eq!(config.server.host, "0.0.0.0");
        assert_eq!(config.server.port, 9000);
        assert_eq!(config.server.mode, "cloud_connected");
        assert_eq!(config.logging.level, "debug");
    }

    #[test]
    fn test_example_toml_is_valid() {
        let example = Config::example_toml();
        let _config: Config = toml::from_str(&example).unwrap();
    }
}
