//! Web UI module for browser-based monitoring.
//!
//! Provides an embedded React-based Web UI for:
//! - Real-time authorization event streaming (SSE)
//! - Policy file viewing
//! - Token-based authentication

pub mod auth;
pub mod policy;
pub mod sse;
pub mod static_files;

use axum::{middleware, routing::get, Router};

use crate::http::AppState;

/// Creates the Web UI router with authentication.
///
/// This router serves:
/// - `/ui/*` - Static files (embedded React app)
/// - `/ui/api/events` - SSE event stream
/// - `/ui/api/policy/raw` - Policy file contents
///
/// All routes are protected by token authentication.
pub fn create_webui_router(state: AppState) -> Router<AppState> {
    let token = state
        .web_ui_token
        .clone()
        .expect("Web UI router requires token");

    let auth_state = auth::WebUiAuthState { token };

    // API routes for Web UI
    let api_routes = Router::new()
        .route("/events", get(sse::events_handler))
        .route("/policy/raw", get(policy::policy_raw_handler));

    // Build the full Web UI router with auth
    // Static routes nested under /ui with fallback for SPA routing
    let static_routes = Router::new()
        .route("/", get(static_files::static_handler))
        .fallback(get(static_files::static_handler));

    Router::new()
        .nest("/ui/api", api_routes)
        .route("/ui/", get(static_files::static_handler)) // Handle /ui/ explicitly
        .nest("/ui", static_routes)
        .layer(middleware::from_fn_with_state(
            auth_state,
            auth::web_ui_auth_middleware,
        ))
}
