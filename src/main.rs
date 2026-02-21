//! Predicate Authority Sidecar Daemon (Rust)
//!
//! A high-performance authorization sidecar that enforces policy rules
//! for agent actions.

mod bridge;
mod control_plane;
mod http;
mod identity;
mod mandate;
mod models;
mod policy;
mod proof;

use clap::Parser;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{info, warn, Level};
use tracing_subscriber::FmtSubscriber;

use crate::control_plane::{ControlPlaneClient, ControlPlaneConfig, RevocationCache};
use crate::http::AppState;
use crate::identity::LocalIdentityRegistry;
use crate::policy::PolicyEngine;

/// Predicate Authority Sidecar Daemon
#[derive(Parser, Debug)]
#[command(name = "predicate-authorityd")]
#[command(about = "Predicate Authority sidecar daemon for agent authorization")]
#[command(version)]
struct Args {
    /// Host to bind to
    #[arg(long, default_value = "127.0.0.1", env = "PREDICATE_HOST")]
    host: String,

    /// Port to bind to
    #[arg(long, default_value_t = 8787, env = "PREDICATE_PORT")]
    port: u16,

    /// Operating mode: local_only or cloud_connected
    #[arg(long, default_value = "local_only", env = "PREDICATE_MODE")]
    mode: String,

    /// Path to policy JSON file
    #[arg(long, env = "PREDICATE_POLICY_FILE")]
    policy_file: Option<String>,

    /// Path to local identity registry JSON file
    #[arg(long, env = "PREDICATE_IDENTITY_FILE")]
    identity_file: Option<String>,

    /// Log level: trace, debug, info, warn, error
    #[arg(long, default_value = "info", env = "PREDICATE_LOG_LEVEL")]
    log_level: String,

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

    /// Auth token for control-plane
    #[arg(long, env = "PREDICATE_AUTH_TOKEN")]
    auth_token: Option<String>,

    /// Enable control-plane sync
    #[arg(long, env = "PREDICATE_SYNC_ENABLED")]
    sync_enabled: bool,

    /// Sync wait timeout in seconds
    #[arg(long, default_value_t = 15.0, env = "PREDICATE_SYNC_WAIT_TIMEOUT_S")]
    sync_wait_timeout_s: f64,

    /// Environment for sync (e.g., production, staging)
    #[arg(long, env = "PREDICATE_SYNC_ENVIRONMENT")]
    sync_environment: Option<String>,

    /// Fail open if control-plane is unreachable
    #[arg(long, default_value_t = true, env = "PREDICATE_FAIL_OPEN")]
    fail_open: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // Initialize logging
    let level = match args.log_level.as_str() {
        "trace" => Level::TRACE,
        "debug" => Level::DEBUG,
        "info" => Level::INFO,
        "warn" => Level::WARN,
        "error" => Level::ERROR,
        _ => Level::INFO,
    };

    FmtSubscriber::builder()
        .with_max_level(level)
        .with_target(true)
        .with_thread_ids(false)
        .compact()
        .init();

    info!("Starting predicate-authorityd (Rust)");
    info!("Mode: {}", args.mode);

    // Initialize policy engine
    let policy_engine = PolicyEngine::new();

    // Load policy file if specified
    if let Some(ref policy_path) = args.policy_file {
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
    let mut state = AppState::new(policy_engine, &args.mode);

    // Initialize local identity registry if path specified or in local_only mode
    let identity_path = args.identity_file.clone().unwrap_or_else(|| {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        format!("{}/.predicate/local-identity-registry.json", home)
    });

    let registry = LocalIdentityRegistry::new(&PathBuf::from(&identity_path), None, None);
    state = state.with_identity_registry(registry);
    info!("Local identity registry: {}", identity_path);

    // Initialize control-plane client if in cloud_connected mode
    if args.mode == "cloud_connected" {
        if let (Some(ref url), Some(ref tenant_id), Some(ref project_id)) =
            (&args.control_plane_url, &args.tenant_id, &args.project_id)
        {
            let config = ControlPlaneConfig {
                base_url: url.clone(),
                tenant_id: tenant_id.clone(),
                project_id: project_id.clone(),
                auth_token: args.auth_token.clone(),
                timeout_s: 2.0,
                max_retries: 2,
                backoff_initial_s: 0.2,
                fail_open: args.fail_open,
                sync_enabled: args.sync_enabled,
                sync_wait_timeout_s: args.sync_wait_timeout_s,
                sync_poll_interval_ms: 200,
                sync_project_id: args.project_id.clone(),
                sync_environment: args.sync_environment.clone(),
                replay_signing_secret: None,
            };

            match ControlPlaneClient::new(config) {
                Ok(client) => {
                    let client = Arc::new(client);
                    let revocation_cache = Arc::new(RevocationCache::new());

                    info!("Control-plane client initialized: {}", url);

                    // Start sync loop if enabled
                    if args.sync_enabled {
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
                    if !args.fail_open {
                        return Err(anyhow::anyhow!(
                            "Control-plane initialization failed and fail_open is disabled"
                        ));
                    }
                }
            }
        } else {
            warn!("Cloud-connected mode requires --control-plane-url, --tenant-id, and --project-id");
            if !args.fail_open {
                return Err(anyhow::anyhow!(
                    "Missing required control-plane configuration"
                ));
            }
        }
    }

    // Create router
    let app = http::create_router(state);

    // Parse address
    let addr: SocketAddr = format!("{}:{}", args.host, args.port).parse()?;
    info!("Listening on http://{}", addr);

    // Start server
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
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
