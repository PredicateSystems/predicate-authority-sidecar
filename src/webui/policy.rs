//! Policy file API handler for Web UI.
//!
//! Provides an endpoint to read the raw policy file contents.

use axum::{
    extract::State,
    http::{header, StatusCode},
    response::{IntoResponse, Response},
};
use std::fs;

use crate::http::AppState;

/// Handler for `GET /ui/api/policy/raw`.
///
/// Returns the raw contents of the policy file as text/plain.
/// Returns 404 if no policy file is configured or the file doesn't exist.
pub async fn policy_raw_handler(State(state): State<AppState>) -> Response {
    match &state.policy_file_path {
        Some(path) => {
            match fs::read_to_string(path) {
                Ok(content) => {
                    // Determine content type based on file extension
                    let content_type = if path
                        .extension()
                        .is_some_and(|ext| ext == "yaml" || ext == "yml")
                    {
                        "text/yaml; charset=utf-8"
                    } else {
                        "text/plain; charset=utf-8"
                    };

                    (
                        StatusCode::OK,
                        [(header::CONTENT_TYPE, content_type)],
                        content,
                    )
                        .into_response()
                }
                Err(e) => {
                    let message = format!("Failed to read policy file: {}", e);
                    (StatusCode::NOT_FOUND, message).into_response()
                }
            }
        }
        None => (
            StatusCode::NOT_FOUND,
            "No policy file configured. Start the sidecar with --policy-file.",
        )
            .into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_policy_content_type_yaml() {
        let path = std::path::PathBuf::from("/test/policy.yaml");
        let is_yaml = path
            .extension()
            .is_some_and(|ext| ext == "yaml" || ext == "yml");
        assert!(is_yaml);
    }

    #[test]
    fn test_policy_content_type_yml() {
        let path = std::path::PathBuf::from("/test/policy.yml");
        let is_yaml = path
            .extension()
            .is_some_and(|ext| ext == "yaml" || ext == "yml");
        assert!(is_yaml);
    }

    #[test]
    fn test_policy_content_type_json() {
        let path = std::path::PathBuf::from("/test/policy.json");
        let is_yaml = path
            .extension()
            .is_some_and(|ext| ext == "yaml" || ext == "yml");
        assert!(!is_yaml);
    }

    #[tokio::test]
    async fn test_read_policy_file() {
        // Create a temporary policy file
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(temp_file, "rules:").unwrap();
        writeln!(temp_file, "  - effect: ALLOW").unwrap();
        writeln!(temp_file, "    action: '*'").unwrap();
        writeln!(temp_file, "    resource: '*'").unwrap();

        let content = fs::read_to_string(temp_file.path()).unwrap();
        assert!(content.contains("rules:"));
        assert!(content.contains("effect: ALLOW"));
    }
}
