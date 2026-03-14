//! Web UI authentication middleware.
//!
//! Validates bearer tokens for Web UI access. Accepts token via:
//! - `Authorization: Bearer <token>` header (for REST calls)
//! - `?token=<token>` query parameter (required for SSE since EventSource doesn't support headers)

use axum::{
    extract::{Request, State},
    http::{header::AUTHORIZATION, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};

/// State for Web UI authentication middleware.
#[derive(Clone)]
pub struct WebUiAuthState {
    pub token: String,
}

/// Extract token from Authorization header or query parameter.
fn extract_token(request: &Request) -> Option<String> {
    // Try Authorization header first: "Bearer <token>"
    if let Some(auth_header) = request.headers().get(AUTHORIZATION) {
        if let Ok(auth_str) = auth_header.to_str() {
            if let Some(token) = auth_str.strip_prefix("Bearer ") {
                return Some(token.to_string());
            }
        }
    }

    // Fall back to query parameter: ?token=<token>
    if let Some(query) = request.uri().query() {
        for pair in query.split('&') {
            if let Some(token) = pair.strip_prefix("token=") {
                return Some(token.to_string());
            }
        }
    }

    None
}

/// Check if the path is a static asset that doesn't need authentication.
/// Static assets are loaded by the browser after the initial authenticated page load.
fn is_static_asset(path: &str) -> bool {
    // Allow static assets (JS, CSS, images, fonts) without token
    // These are referenced from the authenticated HTML page
    path.starts_with("/ui/assets/")
        || path.ends_with(".js")
        || path.ends_with(".css")
        || path.ends_with(".ico")
        || path.ends_with(".png")
        || path.ends_with(".jpg")
        || path.ends_with(".svg")
        || path.ends_with(".woff")
        || path.ends_with(".woff2")
}

/// Middleware that validates Web UI authentication token.
///
/// Returns 401 Unauthorized if:
/// - No token is provided
/// - Token doesn't match the expected value
///
/// Static assets (JS, CSS, images) are allowed without authentication
/// since they're loaded by the browser after the initial authenticated page load.
pub async fn web_ui_auth_middleware(
    State(auth_state): State<WebUiAuthState>,
    request: Request,
    next: Next,
) -> Response {
    let path = request.uri().path();

    // Allow static assets without authentication
    if is_static_asset(path) {
        return next.run(request).await;
    }

    match extract_token(&request) {
        Some(token) if token == auth_state.token => {
            // Token valid, proceed
            next.run(request).await
        }
        Some(_) => {
            // Wrong token
            (
                StatusCode::UNAUTHORIZED,
                "Invalid token. Check terminal for correct access URL.",
            )
                .into_response()
        }
        None => {
            // No token provided
            (
                StatusCode::UNAUTHORIZED,
                "Authorization required. Access the Web UI via the URL printed in terminal.",
            )
                .into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;

    #[test]
    fn test_extract_token_from_header() {
        let request = Request::builder()
            .uri("/test")
            .header(AUTHORIZATION, "Bearer my-secret-token")
            .body(Body::empty())
            .unwrap();

        assert_eq!(extract_token(&request), Some("my-secret-token".to_string()));
    }

    #[test]
    fn test_extract_token_from_query() {
        let request = Request::builder()
            .uri("/test?token=query-token&other=value")
            .body(Body::empty())
            .unwrap();

        assert_eq!(extract_token(&request), Some("query-token".to_string()));
    }

    #[test]
    fn test_extract_token_header_preferred() {
        let request = Request::builder()
            .uri("/test?token=query-token")
            .header(AUTHORIZATION, "Bearer header-token")
            .body(Body::empty())
            .unwrap();

        // Header takes precedence
        assert_eq!(extract_token(&request), Some("header-token".to_string()));
    }

    #[test]
    fn test_extract_token_none() {
        let request = Request::builder()
            .uri("/test?other=value")
            .body(Body::empty())
            .unwrap();

        assert_eq!(extract_token(&request), None);
    }
}
