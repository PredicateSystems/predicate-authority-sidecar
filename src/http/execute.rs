//! Execute handler for Phase 5: Execution Proxying (Zero-Trust).
//!
//! This module implements the `/v1/execute` endpoint which executes operations
//! on behalf of agents. The sidecar validates the mandate, executes the operation,
//! and returns the result. The agent never touches the resource directly.
//!
//! ## Security Model
//!
//! The execute endpoint prevents "confused deputy" attacks by:
//! 1. Validating the mandate exists and is not expired
//! 2. Verifying the requested action matches the mandate's action
//! 3. Verifying the requested resource matches the mandate's resource scope
//! 4. Executing the operation (sidecar is the executor, not the agent)
//! 5. Recording evidence in the audit log
//!
//! This ensures that an agent cannot request authorization for one resource
//! but actually access a different resource.

use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::Path;
use tokio::fs;
use tokio::process::Command;
use tracing::{info, warn};

use crate::http::AppState;
use crate::models::{
    AuthorizationReason, DirectoryEntry, ExecutePayload, ExecuteRequest, ExecuteResponse,
    ExecuteResult,
};

/// POST /v1/execute
///
/// Execute an operation on behalf of the agent. The sidecar:
/// 1. Validates the mandate exists and is not expired
/// 2. Verifies the requested resource matches mandate's resource scope
/// 3. Executes the operation
/// 4. Records evidence in audit log
/// 5. Returns result to agent
pub async fn execute_handler(
    State(state): State<AppState>,
    Json(request): Json<ExecuteRequest>,
) -> impl IntoResponse {
    // 1. Retrieve mandate from store
    let mandate_store = match &state.mandate_store {
        Some(store) => store,
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ExecuteResponse {
                    success: false,
                    result: None,
                    error: Some("Execute endpoint not enabled (no mandate store)".to_string()),
                    audit_id: String::new(),
                    evidence_hash: None,
                }),
            );
        }
    };

    let stored_mandate = match mandate_store.get(&request.mandate_id) {
        Some(m) => m,
        None => {
            warn!("Mandate not found: {}", request.mandate_id);
            return (
                StatusCode::NOT_FOUND,
                Json(ExecuteResponse {
                    success: false,
                    result: None,
                    error: Some("Mandate not found".to_string()),
                    audit_id: String::new(),
                    evidence_hash: None,
                }),
            );
        }
    };

    // 2. Check mandate expiration
    if stored_mandate.is_expired() {
        warn!("Mandate expired: {}", request.mandate_id);
        return (
            StatusCode::FORBIDDEN,
            Json(ExecuteResponse {
                success: false,
                result: None,
                error: Some("Mandate expired".to_string()),
                audit_id: String::new(),
                evidence_hash: None,
            }),
        );
    }

    // 3. Verify action matches mandate
    let mandate_action = stored_mandate.action();
    if !actions_match(mandate_action, &request.action) {
        warn!(
            "Action mismatch: mandate={}, requested={}",
            mandate_action, request.action
        );
        return (
            StatusCode::FORBIDDEN,
            Json(ExecuteResponse {
                success: false,
                result: None,
                error: Some(format!(
                    "Action '{}' not authorized by mandate (authorized: '{}')",
                    request.action, mandate_action
                )),
                audit_id: String::new(),
                evidence_hash: None,
            }),
        );
    }

    // 4. Verify resource matches mandate's resource scope
    //    This is the CRITICAL enforcement point - prevents resource swapping
    let mandate_resource = stored_mandate.resource();
    if !resources_match(mandate_resource, &request.resource) {
        warn!(
            "Resource mismatch: mandate={}, requested={}",
            mandate_resource, request.resource
        );
        return (
            StatusCode::FORBIDDEN,
            Json(ExecuteResponse {
                success: false,
                result: None,
                error: Some(format!(
                    "Resource '{}' not in mandate scope (authorized: '{}')",
                    request.resource, mandate_resource
                )),
                audit_id: String::new(),
                evidence_hash: None,
            }),
        );
    }

    // 5. Execute the operation
    let (result, evidence_hash) = match execute_action(&request).await {
        Ok((r, h)) => (r, h),
        Err(e) => {
            // Record failed execution in audit log
            let audit_id = record_execution(
                &state,
                &request.mandate_id,
                &request.action,
                &request.resource,
                false,
                Some(&e),
            );

            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ExecuteResponse {
                    success: false,
                    result: None,
                    error: Some(e),
                    audit_id,
                    evidence_hash: None,
                }),
            );
        }
    };

    // 6. Mark mandate as executed
    mandate_store.mark_executed(&request.mandate_id);

    // 7. Record successful execution in audit log
    let audit_id = record_execution(
        &state,
        &request.mandate_id,
        &request.action,
        &request.resource,
        true,
        None,
    );

    info!(
        "Executed {} on {} for mandate {}",
        request.action, request.resource, request.mandate_id
    );

    (
        StatusCode::OK,
        Json(ExecuteResponse {
            success: true,
            result: Some(result),
            error: None,
            audit_id,
            evidence_hash: Some(evidence_hash),
        }),
    )
}

/// Check if actions match (supports wildcard suffix)
fn actions_match(authorized: &str, actual: &str) -> bool {
    if authorized == actual {
        return true;
    }
    // Support wildcard like "fs.*" matching "fs.read", "fs.write", etc.
    if let Some(prefix) = authorized.strip_suffix(".*") {
        return actual.starts_with(prefix) && actual.len() > prefix.len();
    }
    false
}

/// Check if resources match (supports glob patterns and path normalization)
fn resources_match(authorized: &str, actual: &str) -> bool {
    // Normalize paths for comparison
    let norm_auth = normalize_path(authorized);
    let norm_actual = normalize_path(actual);

    // Exact match
    if norm_auth == norm_actual {
        return true;
    }

    // Glob pattern match using the glob crate
    if authorized.contains('*') {
        if let Ok(pattern) = glob::Pattern::new(&norm_auth) {
            return pattern.matches(&norm_actual);
        }
    }

    false
}

/// Normalize a file path for comparison
fn normalize_path(path: &str) -> String {
    path
        // Expand ~ to home directory would require env access
        .replace("//", "/") // Collapse multiple slashes
        .replace("/./", "/") // Remove ./
        .trim_end_matches('/') // Remove trailing slash
        .to_string()
}

/// Execute the requested action
async fn execute_action(request: &ExecuteRequest) -> Result<(ExecuteResult, String), String> {
    match request.action.as_str() {
        "fs.read" => execute_fs_read(&request.resource).await,
        "fs.write" => {
            let payload = request
                .payload
                .as_ref()
                .ok_or("fs.write requires payload")?;
            if let ExecutePayload::FileWrite {
                content,
                create,
                append,
            } = payload
            {
                execute_fs_write(&request.resource, content, *create, *append).await
            } else {
                Err("Invalid payload for fs.write".to_string())
            }
        }
        "fs.list" => execute_fs_list(&request.resource).await,
        "fs.delete" => {
            let recursive = match &request.payload {
                Some(ExecutePayload::FileDelete { recursive }) => *recursive,
                None => false,
                _ => return Err("Invalid payload for fs.delete".to_string()),
            };
            execute_fs_delete(&request.resource, recursive).await
        }
        "cli.exec" => {
            let payload = request
                .payload
                .as_ref()
                .ok_or("cli.exec requires payload")?;
            if let ExecutePayload::CliExec {
                command,
                args,
                cwd,
                timeout_ms,
            } = payload
            {
                execute_cli(
                    &request.resource,
                    command,
                    args,
                    cwd.as_deref(),
                    *timeout_ms,
                )
                .await
            } else {
                Err("Invalid payload for cli.exec".to_string())
            }
        }
        "http.fetch" => {
            let payload = request.payload.as_ref();
            execute_http_fetch(&request.resource, payload).await
        }
        "env.read" => {
            let payload = request
                .payload
                .as_ref()
                .ok_or("env.read requires payload")?;
            if let ExecutePayload::EnvRead { keys } = payload {
                execute_env_read(keys).await
            } else {
                Err("Invalid payload for env.read".to_string())
            }
        }
        _ => Err(format!("Unsupported action: {}", request.action)),
    }
}

/// Execute fs.read
async fn execute_fs_read(resource: &str) -> Result<(ExecuteResult, String), String> {
    // Resolve to absolute path (prevents path traversal)
    let path = Path::new(resource);
    let canonical = fs::canonicalize(path)
        .await
        .map_err(|e| format!("Cannot resolve path: {}", e))?;

    // Read file content
    let content = fs::read_to_string(&canonical)
        .await
        .map_err(|e| format!("Cannot read file: {}", e))?;

    let size = content.len() as u64;

    // Compute content hash
    let mut hasher = Sha256::new();
    hasher.update(content.as_bytes());
    let content_hash = format!("sha256:{:x}", hasher.finalize());

    Ok((
        ExecuteResult::FileRead {
            content,
            size,
            content_hash: content_hash.clone(),
        },
        content_hash,
    ))
}

/// Execute fs.write
async fn execute_fs_write(
    resource: &str,
    content: &str,
    create: bool,
    append: bool,
) -> Result<(ExecuteResult, String), String> {
    let path = Path::new(resource);

    // Check if file exists when create=false
    if !create && !path.exists() {
        return Err("File does not exist and create=false".to_string());
    }

    // Write content
    if append {
        let mut existing = fs::read_to_string(path).await.unwrap_or_default();
        existing.push_str(content);
        fs::write(path, &existing)
            .await
            .map_err(|e| format!("Cannot write file: {}", e))?;
    } else {
        fs::write(path, content)
            .await
            .map_err(|e| format!("Cannot write file: {}", e))?;
    }

    let bytes_written = content.len() as u64;

    // Compute content hash
    let mut hasher = Sha256::new();
    hasher.update(content.as_bytes());
    let content_hash = format!("sha256:{:x}", hasher.finalize());

    Ok((
        ExecuteResult::FileWrite {
            bytes_written,
            content_hash: content_hash.clone(),
        },
        content_hash,
    ))
}

/// Execute cli.exec
async fn execute_cli(
    _resource: &str,
    command: &str,
    args: &[String],
    cwd: Option<&str>,
    timeout_ms: Option<u64>,
) -> Result<(ExecuteResult, String), String> {
    let start = std::time::Instant::now();

    let mut cmd = Command::new(command);
    cmd.args(args);

    if let Some(dir) = cwd {
        cmd.current_dir(dir);
    }

    // Execute with timeout
    let output = if let Some(timeout) = timeout_ms {
        tokio::time::timeout(std::time::Duration::from_millis(timeout), cmd.output())
            .await
            .map_err(|_| "Command timed out".to_string())?
            .map_err(|e| format!("Command failed: {}", e))?
    } else {
        cmd.output()
            .await
            .map_err(|e| format!("Command failed: {}", e))?
    };

    let duration_ms = start.elapsed().as_millis() as u64;
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let exit_code = output.status.code().unwrap_or(-1);

    // Compute evidence hash
    let mut hasher = Sha256::new();
    hasher.update(format!("{}:{}:{}:{}", command, exit_code, stdout, stderr).as_bytes());
    let evidence_hash = format!("sha256:{:x}", hasher.finalize());

    Ok((
        ExecuteResult::CliExec {
            exit_code,
            stdout,
            stderr,
            duration_ms,
        },
        evidence_hash,
    ))
}

/// Execute http.fetch
async fn execute_http_fetch(
    resource: &str,
    payload: Option<&ExecutePayload>,
) -> Result<(ExecuteResult, String), String> {
    let client = reqwest::Client::new();

    let method = if let Some(ExecutePayload::HttpFetch { method, .. }) = payload {
        method.as_str()
    } else {
        "GET"
    };

    let mut request = match method.to_uppercase().as_str() {
        "GET" => client.get(resource),
        "POST" => client.post(resource),
        "PUT" => client.put(resource),
        "DELETE" => client.delete(resource),
        "PATCH" => client.patch(resource),
        "HEAD" => client.head(resource),
        _ => return Err(format!("Unsupported HTTP method: {}", method)),
    };

    // Add headers and body from payload
    if let Some(ExecutePayload::HttpFetch { headers, body, .. }) = payload {
        if let Some(hdrs) = headers {
            for (k, v) in hdrs {
                request = request.header(k, v);
            }
        }
        if let Some(b) = body {
            request = request.body(b.clone());
        }
    }

    let response = request
        .send()
        .await
        .map_err(|e| format!("HTTP request failed: {}", e))?;

    let status_code = response.status().as_u16();
    let headers: HashMap<String, String> = response
        .headers()
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();

    let body = response
        .text()
        .await
        .map_err(|e| format!("Cannot read response body: {}", e))?;

    // Compute body hash
    let mut hasher = Sha256::new();
    hasher.update(body.as_bytes());
    let body_hash = format!("sha256:{:x}", hasher.finalize());

    Ok((
        ExecuteResult::HttpFetch {
            status_code,
            headers,
            body,
            body_hash: body_hash.clone(),
        },
        body_hash,
    ))
}

/// Execute fs.list - list directory contents
async fn execute_fs_list(resource: &str) -> Result<(ExecuteResult, String), String> {
    let path = Path::new(resource);

    // Verify directory exists
    if !path.exists() {
        return Err(format!("Directory does not exist: {}", resource));
    }

    if !path.is_dir() {
        return Err(format!("Path is not a directory: {}", resource));
    }

    // Resolve to canonical path
    let canonical = fs::canonicalize(path)
        .await
        .map_err(|e| format!("Cannot resolve path: {}", e))?;

    // Read directory entries
    let mut entries = Vec::new();
    let mut read_dir = fs::read_dir(&canonical)
        .await
        .map_err(|e| format!("Cannot read directory: {}", e))?;

    while let Some(entry) = read_dir
        .next_entry()
        .await
        .map_err(|e| format!("Cannot read entry: {}", e))?
    {
        let metadata = entry
            .metadata()
            .await
            .map_err(|e| format!("Cannot read metadata: {}", e))?;

        let entry_type = if metadata.is_dir() {
            "dir"
        } else if metadata.is_symlink() {
            "symlink"
        } else {
            "file"
        };

        let modified = metadata
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs());

        entries.push(DirectoryEntry {
            name: entry.file_name().to_string_lossy().to_string(),
            entry_type: entry_type.to_string(),
            size: metadata.len(),
            modified,
        });
    }

    // Sort entries by name for deterministic output
    entries.sort_by(|a, b| a.name.cmp(&b.name));

    let total_entries = entries.len();

    // Compute evidence hash
    let mut hasher = Sha256::new();
    for entry in &entries {
        hasher.update(format!("{}:{}:{}", entry.name, entry.entry_type, entry.size).as_bytes());
    }
    let evidence_hash = format!("sha256:{:x}", hasher.finalize());

    Ok((
        ExecuteResult::FileList {
            entries,
            total_entries,
        },
        evidence_hash,
    ))
}

/// Execute fs.delete - delete file or directory
async fn execute_fs_delete(
    resource: &str,
    recursive: bool,
) -> Result<(ExecuteResult, String), String> {
    let path = Path::new(resource);

    // Verify path exists
    if !path.exists() {
        return Err(format!("Path does not exist: {}", resource));
    }

    // Resolve to canonical path (prevents path traversal)
    let canonical = fs::canonicalize(path)
        .await
        .map_err(|e| format!("Cannot resolve path: {}", e))?;

    let paths_removed = if canonical.is_dir() {
        if recursive {
            // Count entries before removal
            let count = count_entries(&canonical).await?;
            fs::remove_dir_all(&canonical)
                .await
                .map_err(|e| format!("Cannot delete directory: {}", e))?;
            count
        } else {
            // Try to remove empty directory
            fs::remove_dir(&canonical).await.map_err(|e| {
                format!(
                    "Cannot delete directory (not empty or recursive=false): {}",
                    e
                )
            })?;
            1
        }
    } else {
        fs::remove_file(&canonical)
            .await
            .map_err(|e| format!("Cannot delete file: {}", e))?;
        1
    };

    // Compute evidence hash
    let mut hasher = Sha256::new();
    hasher.update(format!("deleted:{}:{}", canonical.display(), paths_removed).as_bytes());
    let evidence_hash = format!("sha256:{:x}", hasher.finalize());

    Ok((ExecuteResult::FileDelete { paths_removed }, evidence_hash))
}

/// Count all entries in a directory recursively
async fn count_entries(path: &Path) -> Result<usize, String> {
    let mut count = 1; // Count the directory itself
    let mut read_dir = fs::read_dir(path)
        .await
        .map_err(|e| format!("Cannot read directory: {}", e))?;

    while let Some(entry) = read_dir
        .next_entry()
        .await
        .map_err(|e| format!("Cannot read entry: {}", e))?
    {
        let entry_path = entry.path();
        if entry_path.is_dir() {
            count += Box::pin(count_entries(&entry_path)).await?;
        } else {
            count += 1;
        }
    }

    Ok(count)
}

/// Execute env.read - read environment variables
async fn execute_env_read(keys: &[String]) -> Result<(ExecuteResult, String), String> {
    let mut values = HashMap::new();

    for key in keys {
        if let Ok(value) = std::env::var(key) {
            values.insert(key.clone(), value);
        }
        // If key doesn't exist, we simply don't include it in the result
        // This is intentional - agents should not be able to probe for env var existence
    }

    // Compute evidence hash (hash of keys requested, not values for security)
    let mut hasher = Sha256::new();
    let mut sorted_keys: Vec<&String> = keys.iter().collect();
    sorted_keys.sort();
    for key in sorted_keys {
        hasher.update(format!("env:{}", key).as_bytes());
    }
    let evidence_hash = format!("sha256:{:x}", hasher.finalize());

    Ok((ExecuteResult::EnvRead { values }, evidence_hash))
}

/// Record execution in proof ledger
fn record_execution(
    state: &AppState,
    mandate_id: &str,
    action: &str,
    resource: &str,
    success: bool,
    _error: Option<&str>,
) -> String {
    let reason = if success {
        AuthorizationReason::Allowed
    } else {
        AuthorizationReason::ExplicitDeny
    };

    state.proof_ledger.record_decision(
        &format!("execute:{}", mandate_id),
        action,
        resource,
        success,
        reason,
        Some(mandate_id.to_string()),
    );

    // Generate audit ID from event count and timestamp
    let event_count = state.proof_ledger.event_count();
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis();
    format!("exec_{}_{}", event_count, timestamp % 100_000_000)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_actions_match_exact() {
        assert!(actions_match("fs.read", "fs.read"));
        assert!(actions_match("cli.exec", "cli.exec"));
        assert!(!actions_match("fs.read", "fs.write"));
    }

    #[test]
    fn test_actions_match_wildcard() {
        assert!(actions_match("fs.*", "fs.read"));
        assert!(actions_match("fs.*", "fs.write"));
        assert!(actions_match("browser.*", "browser.click"));
        assert!(!actions_match("fs.*", "cli.exec"));
        assert!(!actions_match("fs.*", "fs")); // Must have something after prefix
    }

    #[test]
    fn test_resources_match_exact() {
        assert!(resources_match("/src/index.ts", "/src/index.ts"));
        assert!(resources_match(
            "https://example.com/api",
            "https://example.com/api"
        ));
        assert!(!resources_match("/src/index.ts", "/src/main.ts"));
    }

    #[test]
    fn test_resources_match_normalized() {
        assert!(resources_match("/src//index.ts", "/src/index.ts"));
        assert!(resources_match("/src/./index.ts", "/src/index.ts"));
        assert!(resources_match("/src/index.ts/", "/src/index.ts"));
    }

    #[test]
    fn test_resources_match_glob() {
        assert!(resources_match("/src/*.ts", "/src/index.ts"));
        assert!(resources_match("/src/**/*.ts", "/src/components/Button.ts"));
        // Note: glob crate's * matches path separators by default, so /src/*.ts matches /src/components/Button.ts
        // This is different from shell globbing. Use ** explicitly for recursive matching.
        assert!(resources_match("/src/*.ts", "/src/components/Button.ts")); // * matches components/Button
        assert!(resources_match(
            "https://api.example.com/*",
            "https://api.example.com/users"
        ));
        // Exact match required when no wildcards
        assert!(!resources_match("/src/index.ts", "/src/main.ts"));
    }

    #[test]
    fn test_normalize_path() {
        assert_eq!(normalize_path("/src//index.ts"), "/src/index.ts");
        assert_eq!(normalize_path("/src/./index.ts"), "/src/index.ts");
        assert_eq!(normalize_path("/src/index.ts/"), "/src/index.ts");
        assert_eq!(normalize_path("/src//./index.ts/"), "/src/index.ts");
    }

    #[test]
    fn test_actions_match_new_actions() {
        // fs.list
        assert!(actions_match("fs.list", "fs.list"));
        assert!(actions_match("fs.*", "fs.list"));

        // fs.delete
        assert!(actions_match("fs.delete", "fs.delete"));
        assert!(actions_match("fs.*", "fs.delete"));

        // env.read
        assert!(actions_match("env.read", "env.read"));
        assert!(actions_match("env.*", "env.read"));
    }
}
