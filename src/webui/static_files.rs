//! Static file serving for embedded Web UI assets.
//!
//! Uses `rust-embed` to embed the React build output into the binary.
//! Supports SPA routing by falling back to index.html for unknown paths.

use axum::{
    body::Body,
    http::{header, Response, StatusCode, Uri},
    response::IntoResponse,
};
use rust_embed::Embed;

/// Embedded Web UI assets from the React build.
#[derive(Embed)]
#[folder = "webui/dist/"]
pub struct Assets;

/// Serve a static file from embedded assets.
///
/// If the file exists, serve it with the appropriate content type.
/// If not found, fall back to index.html for SPA client-side routing.
pub async fn static_handler(uri: Uri) -> impl IntoResponse {
    let raw_path = uri.path();

    // When nested under /ui, the path may or may not include /ui/
    // Strip it if present, otherwise use as-is
    let path = raw_path
        .trim_start_matches("/ui/")
        .trim_start_matches("/ui")
        .trim_start_matches('/');

    // Handle root path
    let path = if path.is_empty() { "index.html" } else { path };

    tracing::debug!("Static file request: raw={}, resolved={}", raw_path, path);
    serve_file(path).await
}

/// Serve a specific file or fall back to index.html.
async fn serve_file(path: &str) -> Response<Body> {
    // Try to get the requested file
    if let Some(content) = Assets::get(path) {
        let mime = mime_guess::from_path(path).first_or_octet_stream();

        Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, mime.as_ref())
            .header(header::CACHE_CONTROL, cache_control_for(path))
            .body(Body::from(content.data.into_owned()))
            .unwrap()
    } else {
        // SPA fallback: serve index.html for client-side routing
        serve_index_html()
    }
}

/// Serve index.html for SPA routing fallback.
fn serve_index_html() -> Response<Body> {
    match Assets::get("index.html") {
        Some(content) => Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
            .header(header::CACHE_CONTROL, "no-cache")
            .body(Body::from(content.data.into_owned()))
            .unwrap(),
        None => {
            // No index.html means Web UI assets aren't built yet
            Response::builder()
                .status(StatusCode::NOT_FOUND)
                .header(header::CONTENT_TYPE, "text/plain")
                .body(Body::from(
                    "Web UI not available. Build the React app first: cd webui && npm run build",
                ))
                .unwrap()
        }
    }
}

/// Determine cache control header based on file type.
///
/// - HTML files: no-cache (always revalidate)
/// - Hashed assets (js, css with hash): immutable, long cache
/// - Other assets: short cache
fn cache_control_for(path: &str) -> &'static str {
    if path.ends_with(".html") {
        "no-cache"
    } else if path.contains(".") && (path.contains("-") || path.contains("_")) {
        // Likely a hashed asset like "index-abc123.js"
        "public, max-age=31536000, immutable"
    } else {
        "public, max-age=3600"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_control_html() {
        assert_eq!(cache_control_for("index.html"), "no-cache");
    }

    #[test]
    fn test_cache_control_hashed_asset() {
        assert_eq!(
            cache_control_for("assets/index-abc123.js"),
            "public, max-age=31536000, immutable"
        );
    }

    #[test]
    fn test_cache_control_other() {
        assert_eq!(cache_control_for("favicon.ico"), "public, max-age=3600");
    }
}
