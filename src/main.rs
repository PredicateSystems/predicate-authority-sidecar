//! Predicate Authority Sidecar Daemon (Rust)
//!
//! A high-performance authorization sidecar that enforces policy rules
//! for agent actions.

use clap::{Parser, Subcommand};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::signal;
use tracing::{info, warn, Level};
use tracing_subscriber::FmtSubscriber;

use predicate_authorityd::config::Config;
use predicate_authorityd::control_plane::{
    ControlPlaneClient, ControlPlaneConfig, RevocationCache,
};
use predicate_authorityd::http::{create_router, AppState};
use predicate_authorityd::identity::LocalIdentityRegistry;
use predicate_authorityd::models;
use predicate_authorityd::policy::PolicyEngine;

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

    /// Path to policy JSON file
    #[arg(long, env = "PREDICATE_POLICY_FILE")]
    policy_file: Option<String>,

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
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Start the daemon (default)
    Run,

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

    // Initialize policy engine
    let policy_engine = PolicyEngine::new();

    // Load policy file if specified
    if let Some(ref policy_path) = policy_file {
        info!("Loading policy from: {}", policy_path);
        match std::fs::read_to_string(policy_path) {
            Ok(content) => match serde_json::from_str::<serde_json::Value>(&content) {
                Ok(json) => {
                    if let Some(rules) = json.get("rules").and_then(|r| r.as_array()) {
                        let parsed_rules: Vec<models::PolicyRule> = rules
                            .iter()
                            .filter_map(|r| serde_json::from_value(r.clone()).ok())
                            .collect();
                        let count = parsed_rules.len();
                        policy_engine.replace_rules(parsed_rules);
                        info!("Loaded {} policy rules", count);
                    }
                }
                Err(e) => {
                    warn!("Failed to parse policy file: {}", e);
                }
            },
            Err(e) => {
                warn!("Failed to read policy file: {}", e);
            }
        }
    }

    // Create application state
    let mut state = AppState::new(policy_engine, &mode);

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

    // Create router
    let app = create_router(state);

    // Parse address
    let addr: SocketAddr = format!("{}:{}", host, port).parse()?;
    info!("Listening on http://{}", addr);

    // Start server with graceful shutdown
    let listener = tokio::net::TcpListener::bind(addr).await?;

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    info!("Shutdown complete");
    Ok(())
}

/// Wait for shutdown signal (Ctrl+C or SIGTERM)
async fn shutdown_signal() {
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
