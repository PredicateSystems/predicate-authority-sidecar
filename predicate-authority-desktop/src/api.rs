//! Blocking HTTP calls to the local sidecar.

use predicate_authorityd::models::PolicyRule;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct HealthResponse {
    pub status: String,
    pub mode: String,
    pub uptime_s: u64,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct StatusResponse {
    pub status: String,
    pub mode: String,
    pub identity_mode: String,
    pub uptime_s: u64,
    pub rule_count: usize,
    pub total_allowed: u64,
    pub total_denied: u64,
    pub event_count: usize,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct PolicyReloadResponse {
    pub success: bool,
    pub rule_count: usize,
    pub message: String,
}

fn client() -> Result<reqwest::blocking::Client, String> {
    reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .map_err(|e| e.to_string())
}

pub fn base_url(host: &str, port: &str) -> String {
    format!("http://{}:{}", host.trim(), port.trim())
}

pub fn fetch_health(host: &str, port: &str) -> Result<HealthResponse, String> {
    let url = format!("{}/health", base_url(host, port));
    let r = client()?.get(url).send().map_err(|e| e.to_string())?;
    if !r.status().is_success() {
        return Err(format!("GET /health -> {}", r.status()));
    }
    r.json().map_err(|e| e.to_string())
}

pub fn fetch_status(host: &str, port: &str) -> Result<StatusResponse, String> {
    let url = format!("{}/status", base_url(host, port));
    let r = client()?.get(url).send().map_err(|e| e.to_string())?;
    if !r.status().is_success() {
        return Err(format!("GET /status -> {}", r.status()));
    }
    r.json().map_err(|e| e.to_string())
}

pub fn policy_reload(
    host: &str,
    port: &str,
    rules: &[PolicyRule],
    bearer_secret: Option<&str>,
) -> Result<PolicyReloadResponse, String> {
    let url = format!("{}/policy/reload", base_url(host, port));
    let body = serde_json::json!({ "rules": rules });
    let client = client()?;
    let mut req = client.post(url).json(&body);
    if let Some(s) = bearer_secret {
        if !s.trim().is_empty() {
            req = req.header("Authorization", format!("Bearer {}", s.trim()));
        }
    }
    let r = req.send().map_err(|e| e.to_string())?;
    let status = r.status();
    let text = r.text().unwrap_or_default();
    if status == reqwest::StatusCode::UNAUTHORIZED {
        return Err(format!(
            "401 Unauthorized: policy reload requires a matching bearer secret ({text})"
        ));
    }
    if !status.is_success() {
        return Err(format!("POST /policy/reload -> {status}: {text}"));
    }
    serde_json::from_str(&text).map_err(|e| format!("invalid reload JSON: {e}: {text}"))
}
