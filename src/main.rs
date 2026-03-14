//! Predicate Authority Sidecar Daemon (Rust)
//!
//! A high-performance authorization sidecar that enforces policy rules
//! for agent actions.

use clap::{Parser, Subcommand};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::signal;
use tokio::sync::watch;
use tracing::{info, warn, Level};
use tracing_subscriber::FmtSubscriber;

use predicate_authorityd::bridge;
use predicate_authorityd::config::Config;
use predicate_authorityd::control_plane::{
    ControlPlaneClient, ControlPlaneConfig, RevocationCache,
};
use predicate_authorityd::http::{create_router, AppState, DelegationState};
use predicate_authorityd::identity::LocalIdentityRegistry;
use predicate_authorityd::mandate::{LocalMandateSigner, SigningAlgorithm};
use predicate_authorityd::models;
use predicate_authorityd::policy::PolicyEngine;
use predicate_authorityd::policy_loader;
use predicate_authorityd::ui;

/// Predicate Authority Sidecar Daemon
#[derive(Parser, Debug)]
#[command(name = "predicate-authorityd")]
#[command(about = "Predicate Authority sidecar daemon for agent authorization")]
#[command(version, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Path to configuration file (TOML)
    #[arg(short, long, global = true, env = "PREDICATE_CONFIG")]
    config: Option<String>,

    /// Host to bind to
    #[arg(long, env = "PREDICATE_HOST")]
    host: Option<String>,

    /// Port to bind to
    #[arg(long, env = "PREDICATE_PORT")]
    port: Option<u16>,

    /// Operating mode: local_only or cloud_connected
    #[arg(long, env = "PREDICATE_MODE")]
    mode: Option<String>,

    /// Path to policy file (JSON or YAML). Format auto-detected by extension (.yaml/.yml for YAML, others default to JSON)
    #[arg(long, env = "PREDICATE_POLICY_FILE")]
    policy_file: Option<String>,

    /// Enable audit/dry-run mode (log decisions but don't actually block)
    #[arg(long, env = "PREDICATE_AUDIT_MODE")]
    audit_mode: bool,

    /// Path to local identity registry JSON file
    #[arg(long, env = "PREDICATE_IDENTITY_FILE")]
    identity_file: Option<String>,

    /// Log level: trace, debug, info, warn, error
    #[arg(long, env = "PREDICATE_LOG_LEVEL")]
    log_level: Option<String>,

    // --- Control-plane options (cloud_connected mode) ---
    /// Control-plane base URL
    #[arg(long, env = "PREDICATE_CONTROL_PLANE_URL")]
    control_plane_url: Option<String>,

    /// Tenant ID for control-plane
    #[arg(long, env = "PREDICATE_TENANT_ID")]
    tenant_id: Option<String>,

    /// Project ID for control-plane
    #[arg(long, env = "PREDICATE_PROJECT_ID")]
    project_id: Option<String>,

    /// API key for control-plane authentication
    #[arg(long = "predicate-api-key", env = "PREDICATE_API_KEY")]
    api_key: Option<String>,

    /// Enable control-plane sync
    #[arg(long, env = "PREDICATE_SYNC_ENABLED")]
    sync_enabled: Option<bool>,

    /// Sync wait timeout in seconds
    #[arg(long, env = "PREDICATE_SYNC_WAIT_TIMEOUT_S")]
    sync_wait_timeout_s: Option<f64>,

    /// Environment for sync (e.g., production, staging)
    #[arg(long, env = "PREDICATE_SYNC_ENVIRONMENT")]
    sync_environment: Option<String>,

    /// Fail open if control-plane is unreachable
    #[arg(long, env = "PREDICATE_FAIL_OPEN")]
    fail_open: Option<bool>,

    // --- Identity provider options ---
    /// Identity mode: local, local-idp, oidc, entra, or okta
    #[arg(long, env = "PREDICATE_IDENTITY_MODE", value_parser = ["local", "local-idp", "oidc", "entra", "okta"])]
    identity_mode: Option<String>,

    /// Allow local/local-idp identity in cloud_connected mode (requires explicit opt-in)
    #[arg(long, env = "PREDICATE_ALLOW_LOCAL_FALLBACK")]
    allow_local_fallback: bool,

    /// IdP token TTL in seconds
    #[arg(long, env = "PREDICATE_IDP_TOKEN_TTL_S")]
    idp_token_ttl_s: Option<i64>,

    /// Mandate TTL in seconds (should be <= idp_token_ttl_s)
    #[arg(long, env = "PREDICATE_MANDATE_TTL_S")]
    mandate_ttl_s: Option<i64>,

    // --- Local IdP options ---
    /// Local IdP issuer URL
    #[arg(long, env = "LOCAL_IDP_ISSUER")]
    local_idp_issuer: Option<String>,

    /// Local IdP audience
    #[arg(long, env = "LOCAL_IDP_AUDIENCE")]
    local_idp_audience: Option<String>,

    /// Environment variable name for Local IdP signing key
    #[arg(long, default_value = "LOCAL_IDP_SIGNING_KEY")]
    local_idp_signing_key_env: String,

    // --- OIDC options ---
    /// OIDC issuer URL
    #[arg(long, env = "OIDC_ISSUER")]
    oidc_issuer: Option<String>,

    /// OIDC client ID
    #[arg(long, env = "OIDC_CLIENT_ID")]
    oidc_client_id: Option<String>,

    /// OIDC audience
    #[arg(long, env = "OIDC_AUDIENCE")]
    oidc_audience: Option<String>,

    // --- Entra (Azure AD) options ---
    /// Entra tenant ID
    #[arg(long, env = "ENTRA_TENANT_ID")]
    entra_tenant_id: Option<String>,

    /// Entra client ID
    #[arg(long, env = "ENTRA_CLIENT_ID")]
    entra_client_id: Option<String>,

    /// Entra audience
    #[arg(long, env = "ENTRA_AUDIENCE")]
    entra_audience: Option<String>,

    // --- Okta options ---
    /// Okta issuer URL
    #[arg(long, env = "OKTA_ISSUER")]
    okta_issuer: Option<String>,

    /// Okta client ID
    #[arg(long, env = "OKTA_CLIENT_ID")]
    okta_client_id: Option<String>,

    /// Okta audience
    #[arg(long, env = "OKTA_AUDIENCE")]
    okta_audience: Option<String>,

    /// Required Okta claims (comma-separated, can be repeated)
    #[arg(long, env = "OKTA_REQUIRED_CLAIMS", value_delimiter = ',')]
    okta_required_claims: Vec<String>,

    /// Required Okta scopes (comma-separated, can be repeated)
    #[arg(long, env = "OKTA_REQUIRED_SCOPES", value_delimiter = ',')]
    okta_required_scopes: Vec<String>,

    /// Required Okta roles/groups (comma-separated, can be repeated)
    #[arg(long, env = "OKTA_REQUIRED_ROLES", value_delimiter = ',')]
    okta_required_roles: Vec<String>,

    /// Allowed tenant identifiers (comma-separated, can be repeated)
    #[arg(long, env = "OKTA_ALLOWED_TENANTS", value_delimiter = ',')]
    okta_allowed_tenants: Vec<String>,

    /// Claim name carrying tenant identifier
    #[arg(long, env = "OKTA_TENANT_CLAIM", default_value = "tenant_id")]
    okta_tenant_claim: String,

    /// Claim name carrying scopes
    #[arg(long, env = "OKTA_SCOPE_CLAIM", default_value = "scope")]
    okta_scope_claim: String,

    /// Claim name carrying roles/groups
    #[arg(long, env = "OKTA_ROLE_CLAIM", default_value = "groups")]
    okta_role_claim: String,

    // --- Chain Delegation options ---
    /// Enable chain delegation support (/v1/delegate endpoint)
    #[arg(long, env = "PREDICATE_ENABLE_DELEGATION")]
    enable_delegation: bool,

    /// Maximum delegation depth (default: 5)
    #[arg(long, env = "PREDICATE_MAX_DELEGATION_DEPTH", default_value = "5")]
    max_delegation_depth: u32,

    // --- Policy reload security options ---
    /// Secret required for /policy/reload endpoint (bearer token)
    #[arg(long, env = "PREDICATE_POLICY_RELOAD_SECRET")]
    policy_reload_secret: Option<String>,

    /// Disable the /policy/reload endpoint entirely
    #[arg(long, env = "PREDICATE_DISABLE_POLICY_RELOAD")]
    disable_policy_reload: bool,

    // --- SSRF protection options ---
    /// Allowed endpoints that bypass SSRF protection (comma-separated, host:port format)
    /// Example: --ssrf-allow 172.30.192.1:11434,127.0.0.1:9200
    #[arg(
        long = "ssrf-allow",
        env = "PREDICATE_SSRF_ALLOW",
        value_delimiter = ','
    )]
    ssrf_allow: Vec<String>,

    /// Disable SSRF protection entirely (not recommended)
    #[arg(long, env = "PREDICATE_SSRF_DISABLED")]
    ssrf_disabled: bool,

    // --- Web UI options ---
    /// Enable embedded Web UI for browser-based monitoring
    #[arg(long, env = "PREDICATE_WEB_UI", global = true)]
    web_ui: bool,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Start the daemon (default)
    Run,

    /// Launch interactive terminal dashboard with HTTP server
    Dashboard {
        /// UI refresh interval in milliseconds
        #[arg(long, default_value = "100")]
        refresh_ms: u64,
    },

    /// Generate example configuration file
    InitConfig {
        /// Output path for config file
        #[arg(short, long, default_value = "./predicate-authorityd.toml")]
        output: String,
    },

    /// Validate configuration
    CheckConfig {
        /// Path to config file
        #[arg(short, long)]
        config: String,
    },

    /// Show version and build information
    Version,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Handle subcommands
    match &cli.command {
        Some(Commands::InitConfig { output }) => {
            let content = Config::example_toml();
            std::fs::write(output, content)?;
            println!("Configuration file written to: {}", output);
            return Ok(());
        }
        Some(Commands::CheckConfig { config }) => {
            match Config::from_file(std::path::Path::new(config)) {
                Ok(_) => {
                    println!("Configuration file is valid: {}", config);
                    return Ok(());
                }
                Err(e) => {
                    eprintln!("Configuration error: {}", e);
                    std::process::exit(1);
                }
            }
        }
        Some(Commands::Version) => {
            println!("predicate-authorityd {}", env!("CARGO_PKG_VERSION"));
            println!("Rust sidecar daemon for Predicate Authority");
            println!();
            println!("Build info:");
            println!("  Target: {}", std::env::consts::ARCH);
            println!("  OS: {}", std::env::consts::OS);
            return Ok(());
        }
        Some(Commands::Dashboard { refresh_ms }) => {
            // Dashboard mode: run HTTP server + TUI together
            // Store refresh_ms for later use
            std::env::set_var("PREDICATE_TUI_REFRESH_MS", refresh_ms.to_string());
            // Continue with startup, TUI will be launched after server setup
        }
        Some(Commands::Run) | None => {
            // Continue with normal startup
        }
    }

    // Load configuration with precedence: CLI > env > config file > defaults
    let file_config = cli
        .config
        .as_ref()
        .map(|p| Config::from_file(std::path::Path::new(p)))
        .transpose()?
        .or_else(Config::from_default_locations)
        .unwrap_or_default();

    // Merge CLI args over file config
    let host = cli.host.unwrap_or(file_config.server.host);
    let port = cli.port.unwrap_or(file_config.server.port);
    let mode = cli.mode.unwrap_or(file_config.server.mode);
    let log_level = cli.log_level.unwrap_or(file_config.logging.level);
    let policy_file = cli.policy_file.or(file_config.policy.file);
    let identity_file = cli.identity_file.or(file_config.identity.file);

    let control_plane_url = cli.control_plane_url.or(file_config.control_plane.url);
    let tenant_id = cli.tenant_id.or(file_config.control_plane.tenant_id);
    let project_id = cli.project_id.or(file_config.control_plane.project_id);
    let api_key = cli.api_key.or(file_config.control_plane.api_key);
    let sync_enabled = cli
        .sync_enabled
        .unwrap_or(file_config.control_plane.sync_enabled);
    let sync_wait_timeout_s = cli
        .sync_wait_timeout_s
        .unwrap_or(file_config.control_plane.sync_wait_timeout_s);
    let sync_environment = cli
        .sync_environment
        .or(file_config.control_plane.sync_environment);
    let fail_open = cli.fail_open.unwrap_or(file_config.control_plane.fail_open);

    // Identity provider configuration
    let identity_mode = cli.identity_mode.unwrap_or(file_config.idp.mode.clone());
    let allow_local_fallback = cli.allow_local_fallback || file_config.idp.allow_local_fallback;
    let idp_token_ttl_s = cli
        .idp_token_ttl_s
        .unwrap_or(file_config.idp.idp_token_ttl_s);
    let mandate_ttl_s = cli.mandate_ttl_s.unwrap_or(file_config.idp.mandate_ttl_s);

    // Local IdP config
    let local_idp_issuer = cli
        .local_idp_issuer
        .unwrap_or(file_config.idp.local_idp.issuer.clone());
    let local_idp_audience = cli
        .local_idp_audience
        .unwrap_or(file_config.idp.local_idp.audience.clone());
    let local_idp_signing_key_env = cli.local_idp_signing_key_env;

    // OIDC config
    let oidc_issuer = cli.oidc_issuer.or(file_config.idp.oidc.issuer.clone());
    let oidc_client_id = cli
        .oidc_client_id
        .or(file_config.idp.oidc.client_id.clone());
    let oidc_audience = cli.oidc_audience.or(file_config.idp.oidc.audience.clone());

    // Entra config
    let entra_tenant_id = cli
        .entra_tenant_id
        .or(file_config.idp.entra.tenant_id.clone());
    let entra_client_id = cli
        .entra_client_id
        .or(file_config.idp.entra.client_id.clone());
    let entra_audience = cli
        .entra_audience
        .or(file_config.idp.entra.audience.clone());

    // Okta config
    let okta_issuer = cli.okta_issuer.or(file_config.idp.okta.issuer.clone());
    let okta_client_id = cli
        .okta_client_id
        .or(file_config.idp.okta.client_id.clone());
    let okta_audience = cli.okta_audience.or(file_config.idp.okta.audience.clone());
    let okta_required_claims = if cli.okta_required_claims.is_empty() {
        file_config.idp.okta.required_claims.clone()
    } else {
        cli.okta_required_claims
    };
    let okta_required_scopes = if cli.okta_required_scopes.is_empty() {
        file_config.idp.okta.required_scopes.clone()
    } else {
        cli.okta_required_scopes
    };
    let okta_required_roles = if cli.okta_required_roles.is_empty() {
        file_config.idp.okta.required_roles.clone()
    } else {
        cli.okta_required_roles
    };
    let okta_allowed_tenants = if cli.okta_allowed_tenants.is_empty() {
        file_config.idp.okta.allowed_tenants.clone()
    } else {
        cli.okta_allowed_tenants
    };
    let okta_tenant_claim = cli.okta_tenant_claim;
    let okta_scope_claim = cli.okta_scope_claim;
    let okta_role_claim = cli.okta_role_claim;

    // Initialize logging
    let level = match log_level.as_str() {
        "trace" => Level::TRACE,
        "debug" => Level::DEBUG,
        "info" => Level::INFO,
        "warn" => Level::WARN,
        "error" => Level::ERROR,
        _ => Level::INFO,
    };

    FmtSubscriber::builder()
        .with_max_level(level)
        .with_target(file_config.logging.include_target)
        .with_thread_ids(false)
        .compact()
        .init();

    info!(
        "Starting predicate-authorityd v{}",
        env!("CARGO_PKG_VERSION")
    );
    info!("Mode: {}", mode);
    info!("Identity mode: {}", identity_mode);

    // Validate TTL constraints: idp_token_ttl_s >= mandate_ttl_s
    if idp_token_ttl_s < mandate_ttl_s {
        return Err(anyhow::anyhow!(
            "idp_token_ttl_s ({}) must be >= mandate_ttl_s ({})",
            idp_token_ttl_s,
            mandate_ttl_s
        ));
    }

    // Validate local fallback in cloud_connected mode
    if mode == "cloud_connected"
        && (identity_mode == "local" || identity_mode == "local-idp")
        && !allow_local_fallback
    {
        return Err(anyhow::anyhow!(
            "cloud_connected mode with {0} identity requires explicit --allow-local-fallback. \
             Without this flag, implicit local fallback is denied for security.",
            identity_mode
        ));
    }

    // Validate IdP-specific required fields
    match identity_mode.as_str() {
        "oidc" => {
            if oidc_issuer.is_none() || oidc_client_id.is_none() || oidc_audience.is_none() {
                return Err(anyhow::anyhow!(
                    "identity-mode=oidc requires --oidc-issuer, --oidc-client-id, and --oidc-audience"
                ));
            }
            info!("OIDC issuer: {}", oidc_issuer.as_ref().unwrap());
        }
        "entra" => {
            if entra_tenant_id.is_none() || entra_client_id.is_none() || entra_audience.is_none() {
                return Err(anyhow::anyhow!(
                    "identity-mode=entra requires --entra-tenant-id, --entra-client-id, and --entra-audience"
                ));
            }
            info!("Entra tenant: {}", entra_tenant_id.as_ref().unwrap());
        }
        "okta" => {
            if okta_issuer.is_none() || okta_client_id.is_none() || okta_audience.is_none() {
                return Err(anyhow::anyhow!(
                    "identity-mode=okta requires --okta-issuer, --okta-client-id, and --okta-audience"
                ));
            }
            info!("Okta issuer: {}", okta_issuer.as_ref().unwrap());
        }
        "local-idp" => {
            info!("Local IdP issuer: {}", local_idp_issuer);
        }
        "local" => {
            // Local mode requires no additional config
        }
        _ => {
            // Unknown mode - will be caught by IdpBridgeProvider::new()
        }
    }

    // Initialize policy engine
    let policy_engine = PolicyEngine::new();

    // Collect SSRF configuration from CLI and config file
    let ssrf_disabled = cli.ssrf_disabled || file_config.ssrf.disabled;
    let mut ssrf_allowed_endpoints: Vec<String> = if !cli.ssrf_allow.is_empty() {
        cli.ssrf_allow.clone()
    } else {
        file_config.ssrf.allowed_endpoints.clone()
    };

    // Load policy file if specified (supports JSON and YAML formats)
    // This must happen before SSRF setup to extract ssrf_whitelist from policy
    if let Some(ref policy_path) = policy_file {
        let format = policy_loader::detect_format(policy_path);
        info!(
            "Loading policy from: {} (format: {:?})",
            policy_path, format
        );
        match policy_loader::load_policy_file(policy_path) {
            Ok(result) => {
                let count = result.rules.len();
                policy_engine.replace_rules(result.rules);
                if result.skipped_rules > 0 {
                    warn!(
                        "Loaded {} policy rules, skipped {} malformed rules",
                        count, result.skipped_rules
                    );
                } else {
                    info!("Loaded {} policy rules", count);
                }

                // Merge ssrf_whitelist from policy file (if CLI/config didn't provide any)
                if !result.ssrf_whitelist.is_empty() {
                    if ssrf_allowed_endpoints.is_empty() {
                        ssrf_allowed_endpoints = result.ssrf_whitelist;
                        info!(
                            "SSRF whitelist loaded from policy file: {:?}",
                            ssrf_allowed_endpoints
                        );
                    } else {
                        // CLI/config takes precedence, but we can merge
                        for endpoint in result.ssrf_whitelist {
                            if !ssrf_allowed_endpoints.contains(&endpoint) {
                                ssrf_allowed_endpoints.push(endpoint);
                            }
                        }
                        info!(
                            "SSRF whitelist merged with policy file entries: {:?}",
                            ssrf_allowed_endpoints
                        );
                    }
                }

                // Detect audit mode from policy file name
                let path_lower = policy_path.to_lowercase();
                if path_lower.contains("audit")
                    || path_lower.contains("dry-run")
                    || path_lower.contains("dryrun")
                {
                    policy_engine.set_audit_mode(true);
                    info!("Audit mode enabled (detected from policy filename)");
                }
            }
            Err(e) => {
                warn!("Failed to load policy file: {}", e);
            }
        }
    }

    // Configure SSRF protection (after policy loading to include policy-based whitelist)
    if ssrf_disabled {
        policy_engine.set_ssrf_protection(None);
        warn!("SSRF protection disabled - all endpoints allowed");
    } else if !ssrf_allowed_endpoints.is_empty() {
        use predicate_authorityd::ssrf::SsrfProtection;
        let ssrf = SsrfProtection::new().with_whitelist(ssrf_allowed_endpoints.clone());
        policy_engine.set_ssrf_protection(Some(ssrf));
        info!(
            "SSRF protection enabled with {} allowed endpoints: {:?}",
            ssrf_allowed_endpoints.len(),
            ssrf_allowed_endpoints
        );
    }

    // Enable audit mode if explicitly requested via CLI
    if cli.audit_mode {
        policy_engine.set_audit_mode(true);
        info!("Audit mode enabled via --audit-mode flag");
    }

    // Merge policy reload config
    let policy_reload_secret = cli
        .policy_reload_secret
        .or(file_config.policy.reload_secret);
    let disable_policy_reload = cli.disable_policy_reload || file_config.policy.disable_reload;

    // Generate Web UI token if enabled
    let web_ui_token = if cli.web_ui {
        use rand::Rng;
        let token: String = rand::thread_rng()
            .sample_iter(&rand::distributions::Alphanumeric)
            .take(32)
            .map(char::from)
            .collect();
        Some(token)
    } else {
        None
    };

    // Create shutdown signal channel for SSE streams
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // Create application state
    let mut state = AppState::new(policy_engine, &mode)
        .with_policy_reload_secret(policy_reload_secret.clone())
        .with_policy_reload_disabled(disable_policy_reload)
        .with_web_ui_token(web_ui_token.clone())
        .with_policy_file_path(policy_file.as_ref().map(PathBuf::from))
        .with_shutdown_signal(shutdown_rx);

    if disable_policy_reload {
        info!("Policy reload endpoint disabled");
    } else if policy_reload_secret.is_some() {
        info!("Policy reload endpoint protected with bearer token");
    }

    // Initialize IdP bridge based on identity_mode
    let local_idp_signing_key = std::env::var(&local_idp_signing_key_env)
        .unwrap_or_else(|_| "predicate-local-idp-dev-key".to_string());

    let local_idp_config = Some(bridge::LocalIdpBridgeConfig {
        issuer: local_idp_issuer.clone(),
        audience: local_idp_audience.clone(),
        signing_key: local_idp_signing_key,
        token_ttl_seconds: idp_token_ttl_s,
    });

    let oidc_config = if let (Some(iss), Some(cid), Some(aud)) = (
        oidc_issuer.clone(),
        oidc_client_id.clone(),
        oidc_audience.clone(),
    ) {
        Some(bridge::OidcBridgeConfig {
            issuer: iss,
            client_id: cid,
            audience: aud,
            token_ttl_seconds: idp_token_ttl_s,
        })
    } else {
        None
    };

    let entra_config = if let (Some(tid), Some(cid), Some(aud)) = (
        entra_tenant_id.clone(),
        entra_client_id.clone(),
        entra_audience.clone(),
    ) {
        Some(bridge::EntraBridgeConfig {
            tenant_id: tid,
            client_id: cid,
            audience: aud,
            token_ttl_seconds: idp_token_ttl_s,
        })
    } else {
        None
    };

    let okta_config = if let (Some(iss), Some(cid), Some(aud)) = (
        okta_issuer.clone(),
        okta_client_id.clone(),
        okta_audience.clone(),
    ) {
        Some(bridge::OktaBridgeConfig {
            issuer: iss.clone(),
            client_id: cid,
            audience: aud,
            token_ttl_seconds: idp_token_ttl_s,
            required_claims: okta_required_claims,
            allowed_signing_algs: vec!["RS256".to_string()],
            clock_skew_leeway_seconds: 30,
            tenant_claim: okta_tenant_claim,
            scope_claim: okta_scope_claim,
            role_claim: okta_role_claim,
            allowed_tenants: okta_allowed_tenants,
            required_scopes: okta_required_scopes,
            required_roles: okta_required_roles,
            enable_jwks_validation: true,
            jwks_url: None,
            discovery_url: Some(format!("{}/.well-known/openid-configuration", iss)),
            jwks_cache_ttl_seconds: 300,
            jwks_timeout_s: 2.0,
            jwks_max_retries: 2,
            jwks_backoff_initial_s: 0.1,
        })
    } else {
        None
    };

    let idp_bridge = bridge::IdpBridgeProvider::new(
        &identity_mode,
        local_idp_config,
        oidc_config,
        entra_config,
        okta_config,
    )
    .map_err(|e| anyhow::anyhow!("Failed to create IdP bridge: {}", e))?;

    state = state.with_idp_bridge(idp_bridge, &identity_mode);

    // Initialize local identity registry
    let identity_path = identity_file.unwrap_or_else(|| {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        format!("{}/.predicate/local-identity-registry.json", home)
    });

    let registry = LocalIdentityRegistry::new(
        &PathBuf::from(&identity_path),
        Some(file_config.identity.default_ttl_s),
        Some(file_config.identity.queue_item_ttl_s),
    );
    state = state.with_identity_registry(registry);
    info!("Local identity registry: {}", identity_path);

    // Initialize chain delegation if enabled
    if cli.enable_delegation {
        // Use the same signing key as the local IdP for mandate signing
        let delegation_signing_key = std::env::var(&local_idp_signing_key_env)
            .unwrap_or_else(|_| "predicate-local-idp-dev-key".to_string());

        // Default TTL for delegated mandates (5 minutes)
        let delegation_ttl_s = file_config.identity.default_ttl_s;

        let mandate_signer = LocalMandateSigner::new(
            &delegation_signing_key,
            delegation_ttl_s,
            SigningAlgorithm::HS256,
            true, // allow_legacy_hs256_verify
            Some(&local_idp_issuer),
            Some(&local_idp_audience),
        );

        let delegation_state =
            DelegationState::new(mandate_signer).with_max_depth(cli.max_delegation_depth);

        state = state.with_delegation(delegation_state);
        info!(
            "Chain delegation enabled (max_depth: {}, ttl: {}s)",
            cli.max_delegation_depth, delegation_ttl_s
        );

        // Add mandate store for /v1/execute endpoint support
        // This enables execution proxying (zero-trust mode)
        use predicate_authorityd::mandate::MandateStore;
        let mandate_store = MandateStore::new();
        state = state.with_mandate_store(mandate_store);
        info!("Execution proxying enabled (/v1/execute endpoint)");
    }

    // Initialize control-plane client if in cloud_connected mode
    if mode == "cloud_connected" {
        if let (Some(ref url), Some(ref tid), Some(ref pid)) =
            (&control_plane_url, &tenant_id, &project_id)
        {
            let cp_config = ControlPlaneConfig {
                base_url: url.clone(),
                tenant_id: tid.clone(),
                project_id: pid.clone(),
                api_key: api_key.clone(),
                timeout_s: file_config.control_plane.timeout_s,
                max_retries: file_config.control_plane.max_retries,
                backoff_initial_s: 0.2,
                fail_open,
                sync_enabled,
                sync_wait_timeout_s,
                sync_poll_interval_ms: 200,
                sync_project_id: project_id.clone(),
                sync_environment: sync_environment.clone(),
                replay_signing_secret: None,
            };

            match ControlPlaneClient::new(cp_config) {
                Ok(client) => {
                    let client = Arc::new(client);
                    let revocation_cache = Arc::new(RevocationCache::new());

                    info!("Control-plane client initialized: {}", url);

                    // Start sync loop if enabled
                    if sync_enabled {
                        let sync_client = client.clone();
                        let sync_cache = revocation_cache.clone();
                        let sync_policy_engine = state.policy_engine.clone();

                        tokio::spawn(async move {
                            sync_loop(sync_client, sync_cache, sync_policy_engine).await;
                        });

                        info!("Control-plane sync enabled");
                    }
                }
                Err(e) => {
                    warn!("Failed to initialize control-plane client: {}", e);
                    if !fail_open {
                        return Err(anyhow::anyhow!(
                            "Control-plane initialization failed and fail_open is disabled"
                        ));
                    }
                }
            }
        } else {
            warn!(
                "Cloud-connected mode requires --control-plane-url, --tenant-id, and --project-id"
            );
            if !fail_open {
                return Err(anyhow::anyhow!(
                    "Missing required control-plane configuration"
                ));
            }
        }
    }

    // Parse address
    let addr: SocketAddr = format!("{}:{}", host, port).parse()?;

    // Check if we're in dashboard mode
    let is_dashboard_mode = matches!(&cli.command, Some(Commands::Dashboard { .. }));
    let refresh_ms: u64 = std::env::var("PREDICATE_TUI_REFRESH_MS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(100);

    // Create router (state is cloned, but inner Arc fields are shared)
    let app = create_router(state.clone());

    // Start server
    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!("Listening on http://{}", addr);

    // Print Web UI URL if enabled
    if let Some(ref token) = web_ui_token {
        // Use println! to ensure it's visible even with TUI
        println!(
            "\n  Web UI enabled: http://{}:{}/ui/?token={}\n",
            host, port, token
        );
        info!("Web UI enabled at /ui/ (token-protected)");
    }

    if is_dashboard_mode {
        // Dashboard mode: run HTTP server + TUI together
        info!("Starting dashboard mode (refresh: {}ms)", refresh_ms);

        // Run server in background task
        let server =
            axum::serve(listener, app).with_graceful_shutdown(shutdown_signal(shutdown_tx));

        // Run both concurrently - TUI exit or server shutdown will end the session
        tokio::select! {
            result = server => {
                if let Err(e) = result {
                    tracing::error!("Server error: {}", e);
                }
            }
            result = ui::run_dashboard(state, refresh_ms) => {
                if let Err(e) = result {
                    tracing::error!("TUI error: {}", e);
                }
            }
        }
    } else {
        // Normal mode: just run the HTTP server
        axum::serve(listener, app)
            .with_graceful_shutdown(shutdown_signal(shutdown_tx))
            .await?;
    }

    info!("Shutdown complete");
    Ok(())
}

/// Wait for shutdown signal (Ctrl+C or SIGTERM)
/// Notifies SSE streams via the watch channel when shutdown is triggered.
async fn shutdown_signal(shutdown_tx: watch::Sender<bool>) {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("Failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            info!("Received Ctrl+C, initiating graceful shutdown...");
        }
        _ = terminate => {
            info!("Received SIGTERM, initiating graceful shutdown...");
        }
    }

    // Signal SSE streams to terminate
    let _ = shutdown_tx.send(true);
}

/// Background sync loop for control-plane updates
async fn sync_loop(
    client: Arc<ControlPlaneClient>,
    revocation_cache: Arc<RevocationCache>,
    policy_engine: Arc<PolicyEngine>,
) {
    let mut current_token: Option<String> = None;

    loop {
        match client
            .poll_authority_updates(current_token.as_deref(), None, None, None, None)
            .await
        {
            Ok(snapshot) => {
                if snapshot.changed {
                    info!(
                        "Received control-plane update: policy_revision={:?}",
                        snapshot.policy_revision
                    );

                    // Update revocation cache
                    revocation_cache
                        .update_from_snapshot(&snapshot.revocations)
                        .await;

                    // Update policy if present
                    if let Some(ref policy_doc) = snapshot.policy_document {
                        if let Some(rules) = policy_doc.get("rules").and_then(|r| r.as_array()) {
                            let parsed_rules: Vec<models::PolicyRule> = rules
                                .iter()
                                .filter_map(|r| serde_json::from_value(r.clone()).ok())
                                .collect();
                            let count = parsed_rules.len();
                            policy_engine.replace_rules(parsed_rules);
                            info!("Updated policy with {} rules from control-plane", count);
                        }
                    }

                    current_token = Some(snapshot.sync_token);
                }
            }
            Err(e) => {
                warn!("Control-plane sync error: {}", e);
                // Back off on error
                tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
            }
        }
    }
}
