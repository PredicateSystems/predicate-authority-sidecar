//! Execute types for Phase 5: Execution Proxying (Zero-Trust).
//!
//! These types support the `/v1/execute` endpoint which allows the sidecar to
//! execute operations on behalf of agents, preventing resource-swapping attacks.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// POST /v1/execute request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecuteRequest {
    /// Mandate ID from prior authorization
    pub mandate_id: String,

    /// Action to execute (must match mandate)
    pub action: String,

    /// Resource to operate on (must match mandate's resource scope)
    pub resource: String,

    /// Action-specific payload
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<ExecutePayload>,
}

/// Action-specific payloads
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ExecutePayload {
    /// fs.write payload
    FileWrite {
        content: String,
        #[serde(default)]
        create: bool,
        #[serde(default)]
        append: bool,
    },
    /// fs.delete payload
    FileDelete {
        #[serde(default)]
        recursive: bool,
    },
    /// cli.exec payload
    CliExec {
        command: String,
        #[serde(default)]
        args: Vec<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        cwd: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        timeout_ms: Option<u64>,
    },
    /// http.fetch payload
    HttpFetch {
        method: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        headers: Option<HashMap<String, String>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        body: Option<String>,
    },
    /// env.read payload
    EnvRead { keys: Vec<String> },
}

/// POST /v1/execute response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecuteResponse {
    /// Whether execution succeeded
    pub success: bool,

    /// Execution result (action-specific)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<ExecuteResult>,

    /// Error message if failed
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,

    /// Audit trail ID
    pub audit_id: String,

    /// Evidence hash (for verification)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence_hash: Option<String>,
}

/// Directory entry for fs.list result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectoryEntry {
    pub name: String,
    #[serde(rename = "type")]
    pub entry_type: String, // "file", "dir", "symlink"
    pub size: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modified: Option<u64>, // Unix timestamp
}

/// Action-specific results
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ExecuteResult {
    /// fs.read result
    FileRead {
        content: String,
        size: u64,
        content_hash: String,
    },
    /// fs.write result
    FileWrite {
        bytes_written: u64,
        content_hash: String,
    },
    /// fs.list result
    FileList {
        entries: Vec<DirectoryEntry>,
        total_entries: usize,
    },
    /// fs.delete result
    FileDelete { paths_removed: usize },
    /// cli.exec result
    CliExec {
        exit_code: i32,
        stdout: String,
        stderr: String,
        duration_ms: u64,
    },
    /// http.fetch result
    HttpFetch {
        status_code: u16,
        headers: HashMap<String, String>,
        body: String,
        body_hash: String,
    },
    /// env.read result
    EnvRead { values: HashMap<String, String> },
}

/// Execution error types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecuteErrorCode {
    MandateNotFound,
    MandateExpired,
    ActionMismatch,
    ResourceMismatch,
    ExecutionFailed,
    UnsupportedAction,
    InvalidPayload,
}

impl std::fmt::Display for ExecuteErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MandateNotFound => write!(f, "mandate_not_found"),
            Self::MandateExpired => write!(f, "mandate_expired"),
            Self::ActionMismatch => write!(f, "action_mismatch"),
            Self::ResourceMismatch => write!(f, "resource_mismatch"),
            Self::ExecutionFailed => write!(f, "execution_failed"),
            Self::UnsupportedAction => write!(f, "unsupported_action"),
            Self::InvalidPayload => write!(f, "invalid_payload"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_execute_request_serialization() {
        let request = ExecuteRequest {
            mandate_id: "m_abc123".to_string(),
            action: "fs.read".to_string(),
            resource: "/src/index.ts".to_string(),
            payload: None,
        };

        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("m_abc123"));
        assert!(json.contains("fs.read"));

        let parsed: ExecuteRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.mandate_id, "m_abc123");
    }

    #[test]
    fn test_execute_payload_file_write() {
        let payload = ExecutePayload::FileWrite {
            content: "hello world".to_string(),
            create: true,
            append: false,
        };

        let json = serde_json::to_string(&payload).unwrap();
        assert!(json.contains(r#""type":"file_write""#));
        assert!(json.contains("hello world"));

        let parsed: ExecutePayload = serde_json::from_str(&json).unwrap();
        if let ExecutePayload::FileWrite {
            content,
            create,
            append,
        } = parsed
        {
            assert_eq!(content, "hello world");
            assert!(create);
            assert!(!append);
        } else {
            panic!("Expected FileWrite payload");
        }
    }

    #[test]
    fn test_execute_payload_cli_exec() {
        let payload = ExecutePayload::CliExec {
            command: "ls".to_string(),
            args: vec!["-la".to_string()],
            cwd: Some("/tmp".to_string()),
            timeout_ms: Some(5000),
        };

        let json = serde_json::to_string(&payload).unwrap();
        assert!(json.contains(r#""type":"cli_exec""#));
        assert!(json.contains("ls"));

        let parsed: ExecutePayload = serde_json::from_str(&json).unwrap();
        if let ExecutePayload::CliExec {
            command,
            args,
            cwd,
            timeout_ms,
        } = parsed
        {
            assert_eq!(command, "ls");
            assert_eq!(args, vec!["-la"]);
            assert_eq!(cwd, Some("/tmp".to_string()));
            assert_eq!(timeout_ms, Some(5000));
        } else {
            panic!("Expected CliExec payload");
        }
    }

    #[test]
    fn test_execute_payload_http_fetch() {
        let mut headers = HashMap::new();
        headers.insert("Authorization".to_string(), "Bearer token".to_string());

        let payload = ExecutePayload::HttpFetch {
            method: "POST".to_string(),
            headers: Some(headers),
            body: Some("{\"key\": \"value\"}".to_string()),
        };

        let json = serde_json::to_string(&payload).unwrap();
        assert!(json.contains(r#""type":"http_fetch""#));
        assert!(json.contains("POST"));

        let parsed: ExecutePayload = serde_json::from_str(&json).unwrap();
        if let ExecutePayload::HttpFetch {
            method,
            headers,
            body,
        } = parsed
        {
            assert_eq!(method, "POST");
            assert!(headers.is_some());
            assert!(body.is_some());
        } else {
            panic!("Expected HttpFetch payload");
        }
    }

    #[test]
    fn test_execute_response_success() {
        let response = ExecuteResponse {
            success: true,
            result: Some(ExecuteResult::FileRead {
                content: "file content".to_string(),
                size: 12,
                content_hash: "sha256:abc123".to_string(),
            }),
            error: None,
            audit_id: "exec_123".to_string(),
            evidence_hash: Some("sha256:def456".to_string()),
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"success\":true"));
        assert!(json.contains("file_read"));
        assert!(!json.contains("error"));

        let parsed: ExecuteResponse = serde_json::from_str(&json).unwrap();
        assert!(parsed.success);
        assert!(parsed.result.is_some());
    }

    #[test]
    fn test_execute_response_failure() {
        let response = ExecuteResponse {
            success: false,
            result: None,
            error: Some("Mandate not found".to_string()),
            audit_id: "exec_456".to_string(),
            evidence_hash: None,
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"success\":false"));
        assert!(json.contains("Mandate not found"));

        let parsed: ExecuteResponse = serde_json::from_str(&json).unwrap();
        assert!(!parsed.success);
        assert!(parsed.error.is_some());
    }

    #[test]
    fn test_execute_result_cli_exec() {
        let result = ExecuteResult::CliExec {
            exit_code: 0,
            stdout: "output".to_string(),
            stderr: "".to_string(),
            duration_ms: 150,
        };

        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains(r#""type":"cli_exec""#));
        assert!(json.contains("\"exit_code\":0"));

        let parsed: ExecuteResult = serde_json::from_str(&json).unwrap();
        if let ExecuteResult::CliExec {
            exit_code,
            stdout,
            stderr,
            duration_ms,
        } = parsed
        {
            assert_eq!(exit_code, 0);
            assert_eq!(stdout, "output");
            assert_eq!(stderr, "");
            assert_eq!(duration_ms, 150);
        } else {
            panic!("Expected CliExec result");
        }
    }

    #[test]
    fn test_execute_result_http_fetch() {
        let mut headers = HashMap::new();
        headers.insert("content-type".to_string(), "application/json".to_string());

        let result = ExecuteResult::HttpFetch {
            status_code: 200,
            headers,
            body: "{\"ok\": true}".to_string(),
            body_hash: "sha256:xyz789".to_string(),
        };

        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains(r#""type":"http_fetch""#));
        assert!(json.contains("\"status_code\":200"));

        let parsed: ExecuteResult = serde_json::from_str(&json).unwrap();
        if let ExecuteResult::HttpFetch {
            status_code,
            headers: _,
            body,
            body_hash,
        } = parsed
        {
            assert_eq!(status_code, 200);
            assert_eq!(body, "{\"ok\": true}");
            assert_eq!(body_hash, "sha256:xyz789");
        } else {
            panic!("Expected HttpFetch result");
        }
    }

    #[test]
    fn test_execute_error_code_display() {
        assert_eq!(
            ExecuteErrorCode::MandateNotFound.to_string(),
            "mandate_not_found"
        );
        assert_eq!(
            ExecuteErrorCode::MandateExpired.to_string(),
            "mandate_expired"
        );
        assert_eq!(
            ExecuteErrorCode::ActionMismatch.to_string(),
            "action_mismatch"
        );
        assert_eq!(
            ExecuteErrorCode::ResourceMismatch.to_string(),
            "resource_mismatch"
        );
        assert_eq!(
            ExecuteErrorCode::ExecutionFailed.to_string(),
            "execution_failed"
        );
        assert_eq!(
            ExecuteErrorCode::UnsupportedAction.to_string(),
            "unsupported_action"
        );
        assert_eq!(
            ExecuteErrorCode::InvalidPayload.to_string(),
            "invalid_payload"
        );
    }

    #[test]
    fn test_execute_payload_file_delete() {
        let payload = ExecutePayload::FileDelete { recursive: true };

        let json = serde_json::to_string(&payload).unwrap();
        assert!(json.contains(r#""type":"file_delete""#));
        assert!(json.contains("\"recursive\":true"));

        let parsed: ExecutePayload = serde_json::from_str(&json).unwrap();
        if let ExecutePayload::FileDelete { recursive } = parsed {
            assert!(recursive);
        } else {
            panic!("Expected FileDelete payload");
        }
    }

    #[test]
    fn test_execute_payload_env_read() {
        let payload = ExecutePayload::EnvRead {
            keys: vec!["API_KEY".to_string(), "SECRET".to_string()],
        };

        let json = serde_json::to_string(&payload).unwrap();
        assert!(json.contains(r#""type":"env_read""#));
        assert!(json.contains("API_KEY"));

        let parsed: ExecutePayload = serde_json::from_str(&json).unwrap();
        if let ExecutePayload::EnvRead { keys } = parsed {
            assert_eq!(keys.len(), 2);
            assert!(keys.contains(&"API_KEY".to_string()));
        } else {
            panic!("Expected EnvRead payload");
        }
    }

    #[test]
    fn test_execute_result_file_list() {
        let entries = vec![
            DirectoryEntry {
                name: "file.txt".to_string(),
                entry_type: "file".to_string(),
                size: 1024,
                modified: Some(1700000000),
            },
            DirectoryEntry {
                name: "subdir".to_string(),
                entry_type: "dir".to_string(),
                size: 0,
                modified: None,
            },
        ];
        let result = ExecuteResult::FileList {
            entries,
            total_entries: 2,
        };

        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains(r#""type":"file_list""#));
        assert!(json.contains("file.txt"));
        assert!(json.contains("subdir"));

        let parsed: ExecuteResult = serde_json::from_str(&json).unwrap();
        if let ExecuteResult::FileList {
            entries,
            total_entries,
        } = parsed
        {
            assert_eq!(total_entries, 2);
            assert_eq!(entries.len(), 2);
            assert_eq!(entries[0].name, "file.txt");
            assert_eq!(entries[0].entry_type, "file");
        } else {
            panic!("Expected FileList result");
        }
    }

    #[test]
    fn test_execute_result_file_delete() {
        let result = ExecuteResult::FileDelete { paths_removed: 3 };

        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains(r#""type":"file_delete""#));
        assert!(json.contains("\"paths_removed\":3"));

        let parsed: ExecuteResult = serde_json::from_str(&json).unwrap();
        if let ExecuteResult::FileDelete { paths_removed } = parsed {
            assert_eq!(paths_removed, 3);
        } else {
            panic!("Expected FileDelete result");
        }
    }

    #[test]
    fn test_execute_result_env_read() {
        let mut values = HashMap::new();
        values.insert("API_KEY".to_string(), "sk_test_123".to_string());
        values.insert("SECRET".to_string(), "hunter2".to_string());

        let result = ExecuteResult::EnvRead { values };

        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains(r#""type":"env_read""#));
        assert!(json.contains("API_KEY"));
        assert!(json.contains("sk_test_123"));

        let parsed: ExecuteResult = serde_json::from_str(&json).unwrap();
        if let ExecuteResult::EnvRead { values } = parsed {
            assert_eq!(values.len(), 2);
            assert_eq!(values.get("API_KEY"), Some(&"sk_test_123".to_string()));
        } else {
            panic!("Expected EnvRead result");
        }
    }
}
