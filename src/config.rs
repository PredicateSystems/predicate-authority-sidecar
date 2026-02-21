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

    /// Identity registry configuration
    pub identity: IdentityConfig,

    /// Control-plane configuration
    pub control_plane: ControlPlaneFileConfig,

    /// Logging configuration
    pub logging: LoggingConfig,
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

[identity]
# file = "~/.predicate/local-identity-registry.json"
default_ttl_s = 900      # 15 minutes
queue_item_ttl_s = 86400 # 24 hours

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
