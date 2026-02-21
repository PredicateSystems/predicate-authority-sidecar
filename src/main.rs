//! Predicate Authority Sidecar Daemon (Rust)
//!
//! A high-performance authorization sidecar that enforces policy rules
//! for agent actions.

mod http;
mod mandate;
mod models;
mod policy;
mod proof;

use clap::Parser;
use std::net::SocketAddr;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

use crate::http::AppState;
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

    /// Log level: trace, debug, info, warn, error
    #[arg(long, default_value = "info", env = "PREDICATE_LOG_LEVEL")]
    log_level: String,
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

    let subscriber = FmtSubscriber::builder()
        .with_max_level(level)
        .with_target(true)
        .with_thread_ids(false)
        .compact()
        .init();

    info!("Starting predicate-authorityd (Rust)");
    info!("Mode: {}", args.mode);

    // Initialize policy engine
    let mut policy_engine = PolicyEngine::new();

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
                    tracing::warn!("Failed to parse policy file: {}", e);
                }
            },
            Err(e) => {
                tracing::warn!("Failed to read policy file: {}", e);
            }
        }
    }

    // Create application state
    let state = AppState::new(policy_engine, &args.mode);

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
