//! Control-plane HTTP client for sidecar synchronization.
//!
//! Implements long-poll based sync with the central control-plane for:
//! - Policy updates
//! - Revocation lists
//! - Audit event forwarding
//! - Usage metering

use reqwest::Client;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

use crate::models::{PolicyRule, ProofEvent};

/// Control-plane client configuration
#[derive(Debug, Clone)]
pub struct ControlPlaneConfig {
    pub base_url: String,
    pub tenant_id: String,
    pub project_id: String,
    pub auth_token: Option<String>,
    pub timeout_s: f64,
    pub max_retries: u32,
    pub backoff_initial_s: f64,
    pub fail_open: bool,
    pub sync_enabled: bool,
    pub sync_wait_timeout_s: f64,
    pub sync_poll_interval_ms: u64,
    pub sync_project_id: Option<String>,
    pub sync_environment: Option<String>,
    pub replay_signing_secret: Option<String>,
}

impl Default for ControlPlaneConfig {
    fn default() -> Self {
        Self {
            base_url: "https://api.predicate.systems".to_string(),
            tenant_id: String::new(),
            project_id: String::new(),
            auth_token: None,
            timeout_s: 2.0,
            max_retries: 2,
            backoff_initial_s: 0.2,
            fail_open: true,
            sync_enabled: false,
            sync_wait_timeout_s: 15.0,
            sync_poll_interval_ms: 200,
            sync_project_id: None,
            sync_environment: None,
            replay_signing_secret: None,
        }
    }
}

/// Audit event envelope for control-plane
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEventEnvelope {
    pub event_id: String,
    pub tenant_id: String,
    pub principal_id: String,
    pub action: String,
    pub resource: String,
    pub allowed: bool,
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mandate_id: Option<String>,
    pub timestamp: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
}

impl AuditEventEnvelope {
    pub fn from_proof_event(event: &ProofEvent, tenant_id: &str, trace_id: Option<&str>) -> Self {
        let timestamp = chrono::DateTime::from_timestamp(event.emitted_at_epoch_s, 0)
            .map(|dt| dt.to_rfc3339())
            .unwrap_or_default();

        let event_id_seed = format!(
            "{}|{}|{}|{}|{}|{}",
            event.principal_id,
            event.action,
            event.resource,
            event.emitted_at_epoch_s,
            event.allowed,
            event.reason
        );
        let hash = Sha256::digest(event_id_seed.as_bytes());
        let event_id = format!("evt_{}", hex::encode(&hash[..8]));

        Self {
            event_id,
            tenant_id: tenant_id.to_string(),
            principal_id: event.principal_id.clone(),
            action: event.action.clone(),
            resource: event.resource.clone(),
            allowed: event.allowed,
            reason: event.reason.to_string(),
            mandate_id: event.mandate_id.clone(),
            timestamp,
            trace_id: trace_id.map(|s| s.to_string()),
        }
    }
}

/// Usage credit record for metering
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageCreditRecord {
    pub tenant_id: String,
    pub project_id: String,
    pub action_type: String,
    pub credits: i64,
    pub timestamp: String,
}

impl UsageCreditRecord {
    pub fn authority_check(tenant_id: &str, project_id: &str, credits: i64) -> Self {
        let timestamp = chrono::Utc::now().to_rfc3339();
        Self {
            tenant_id: tenant_id.to_string(),
            project_id: project_id.to_string(),
            action_type: "authority_check".to_string(),
            credits,
            timestamp,
        }
    }
}

/// Remote revocation record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteRevocation {
    pub revocation_id: String,
    #[serde(rename = "type")]
    pub revocation_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub principal_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub intent_hash: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default)]
    pub created_at: String,
}

/// Authority sync snapshot from control-plane
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuthoritySyncSnapshot {
    pub changed: bool,
    pub sync_token: String,
    pub tenant_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub environment: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_revision: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_document: Option<serde_json::Value>,
    #[serde(default)]
    pub revocations: Vec<RemoteRevocation>,
}

/// Control-plane client statistics
#[derive(Debug, Clone, Default)]
pub struct ControlPlaneStats {
    pub audit_push_success_count: u64,
    pub audit_push_failure_count: u64,
    pub usage_push_success_count: u64,
    pub usage_push_failure_count: u64,
    pub sync_success_count: u64,
    pub sync_failure_count: u64,
    pub last_push_error: Option<String>,
    pub last_sync_token: Option<String>,
}

/// Control-plane HTTP client
pub struct ControlPlaneClient {
    config: ControlPlaneConfig,
    client: Client,
    stats: Arc<RwLock<ControlPlaneStats>>,
}

impl ControlPlaneClient {
    pub fn new(config: ControlPlaneConfig) -> Result<Self, String> {
        if !config.base_url.starts_with("http://") && !config.base_url.starts_with("https://") {
            return Err("base_url must use http or https scheme".to_string());
        }

        let client = Client::builder()
            .timeout(Duration::from_secs_f64(config.timeout_s))
            .build()
            .map_err(|e| format!("Failed to create HTTP client: {}", e))?;

        Ok(Self {
            config,
            client,
            stats: Arc::new(RwLock::new(ControlPlaneStats::default())),
        })
    }

    /// Send audit events to control-plane
    pub async fn send_audit_events(&self, events: &[AuditEventEnvelope]) -> bool {
        let payload = serde_json::json!({ "events": events });
        let path = "/v1/audit/events:batch";

        match self.post_json(path, &payload).await {
            Ok(_) => {
                let mut stats = self.stats.write().await;
                stats.audit_push_success_count += 1;
                stats.last_push_error = None;
                true
            }
            Err(e) => {
                let mut stats = self.stats.write().await;
                stats.audit_push_failure_count += 1;
                stats.last_push_error = Some(e);
                self.config.fail_open
            }
        }
    }

    /// Send usage records to control-plane
    pub async fn send_usage_records(&self, records: &[UsageCreditRecord]) -> bool {
        let payload = serde_json::json!({ "records": records });
        let path = "/v1/metering/usage:batch";

        match self.post_json(path, &payload).await {
            Ok(_) => {
                let mut stats = self.stats.write().await;
                stats.usage_push_success_count += 1;
                stats.last_push_error = None;
                true
            }
            Err(e) => {
                let mut stats = self.stats.write().await;
                stats.usage_push_failure_count += 1;
                stats.last_push_error = Some(e);
                self.config.fail_open
            }
        }
    }

    /// Poll for authority updates (long-poll)
    pub async fn poll_authority_updates(
        &self,
        current_token: Option<&str>,
        wait_timeout_s: Option<f64>,
        poll_interval_ms: Option<u64>,
        project_id: Option<&str>,
        environment: Option<&str>,
    ) -> Result<AuthoritySyncSnapshot, String> {
        let wait_timeout = wait_timeout_s.unwrap_or(self.config.sync_wait_timeout_s);
        let poll_interval = poll_interval_ms.unwrap_or(self.config.sync_poll_interval_ms);

        let mut query_params = vec![
            ("tenant_id", self.config.tenant_id.clone()),
            ("wait_timeout_s", wait_timeout.to_string()),
            ("poll_interval_ms", poll_interval.to_string()),
        ];

        if let Some(token) = current_token {
            if !token.trim().is_empty() {
                query_params.push(("current_token", token.to_string()));
            }
        }

        if let Some(proj) = project_id.or(self.config.sync_project_id.as_deref()) {
            if !proj.trim().is_empty() {
                query_params.push(("project_id", proj.to_string()));
            }
        }

        if let Some(env) = environment.or(self.config.sync_environment.as_deref()) {
            if !env.trim().is_empty() {
                query_params.push(("environment", env.to_string()));
            }
        }

        let query_string: String = query_params
            .iter()
            .map(|(k, v)| format!("{}={}", k, urlencoding::encode(v)))
            .collect::<Vec<_>>()
            .join("&");

        let path = format!("/v1/sync/authority-updates?{}", query_string);

        // Use longer timeout for long-poll
        let poll_timeout = Duration::from_secs_f64(wait_timeout + 5.0);

        match self.get_json_with_timeout(&path, poll_timeout).await {
            Ok(snapshot) => {
                let mut stats = self.stats.write().await;
                stats.sync_success_count += 1;
                stats.last_sync_token = Some(snapshot.sync_token.clone());
                Ok(snapshot)
            }
            Err(e) => {
                let mut stats = self.stats.write().await;
                stats.sync_failure_count += 1;
                stats.last_push_error = Some(e.clone());

                if self.config.fail_open {
                    Ok(AuthoritySyncSnapshot::default())
                } else {
                    Err(e)
                }
            }
        }
    }

    /// Get client statistics
    pub async fn stats(&self) -> ControlPlaneStats {
        self.stats.read().await.clone()
    }

    // --- Internal methods ---

    async fn post_json(&self, path: &str, payload: &serde_json::Value) -> Result<(), String> {
        let url = format!("{}{}", self.config.base_url.trim_end_matches('/'), path);
        let replay_headers = self.build_replay_headers(path);

        let mut attempts = self.config.max_retries + 1;
        let mut last_error = String::new();

        while attempts > 0 {
            let mut request = self.client.post(&url).json(payload);

            if let Some(ref token) = self.config.auth_token {
                request = request.header("Authorization", format!("Bearer {}", token));
            }

            for (key, value) in &replay_headers {
                request = request.header(key.as_str(), value.as_str());
            }

            match request.send().await {
                Ok(response) => {
                    if response.status().is_success() {
                        return Ok(());
                    }
                    let status = response.status();
                    let body = response.text().await.unwrap_or_default();
                    last_error = format!("HTTP {}: {}", status, body);
                }
                Err(e) => {
                    last_error = format!("Request failed: {}", e);
                }
            }

            attempts -= 1;
            if attempts > 0 {
                let backoff = self.config.backoff_initial_s
                    * 2f64.powi((self.config.max_retries - attempts) as i32);
                tokio::time::sleep(Duration::from_secs_f64(backoff)).await;
            }
        }

        Err(last_error)
    }

    async fn get_json_with_timeout(
        &self,
        path: &str,
        timeout: Duration,
    ) -> Result<AuthoritySyncSnapshot, String> {
        let url = format!("{}{}", self.config.base_url.trim_end_matches('/'), path);

        let mut attempts = self.config.max_retries + 1;
        let mut last_error = String::new();

        while attempts > 0 {
            let mut request = self.client.get(&url).timeout(timeout);

            if let Some(ref token) = self.config.auth_token {
                request = request.header("Authorization", format!("Bearer {}", token));
            }

            match request.send().await {
                Ok(response) => {
                    if response.status().is_success() {
                        return response
                            .json::<AuthoritySyncSnapshot>()
                            .await
                            .map_err(|e| format!("Failed to parse response: {}", e));
                    }
                    let status = response.status();
                    let body = response.text().await.unwrap_or_default();
                    last_error = format!("HTTP {}: {}", status, body);
                }
                Err(e) => {
                    last_error = format!("Request failed: {}", e);
                }
            }

            attempts -= 1;
            if attempts > 0 {
                let backoff = self.config.backoff_initial_s
                    * 2f64.powi((self.config.max_retries - attempts) as i32);
                tokio::time::sleep(Duration::from_secs_f64(backoff)).await;
            }
        }

        Err(last_error)
    }

    fn build_replay_headers(&self, path: &str) -> HashMap<String, String> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .to_string();

        let nonce_seed = format!(
            "{}|{}|{}",
            self.config.tenant_id,
            path,
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let nonce_hash = Sha256::digest(nonce_seed.as_bytes());
        let nonce = hex::encode(&nonce_hash[..16]);

        let idempotency_seed = format!("{}|{}|{}", nonce, timestamp, path);
        let idempotency_hash = Sha256::digest(idempotency_seed.as_bytes());
        let idempotency_token = hex::encode(&idempotency_hash[..16]);

        let mut headers = HashMap::new();
        headers.insert("X-PA-Nonce".to_string(), nonce);
        headers.insert("X-PA-Timestamp".to_string(), timestamp.clone());
        headers.insert("X-PA-Idempotency-Token".to_string(), idempotency_token);

        if let Some(ref secret) = self.config.replay_signing_secret {
            use hmac::{Hmac, Mac};
            type HmacSha256 = Hmac<sha2::Sha256>;

            let message = format!(
                "{}:{}:POST:{}",
                headers.get("X-PA-Nonce").unwrap(),
                timestamp,
                path
            );
            let mut mac =
                HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC can take any size key");
            mac.update(message.as_bytes());
            let signature = hex::encode(mac.finalize().into_bytes());
            headers.insert("X-PA-Signature".to_string(), signature);
        }

        headers
    }
}

/// Revocation cache for fast lookups
pub struct RevocationCache {
    /// Principal ID -> revocation record
    by_principal: Arc<RwLock<HashMap<String, RemoteRevocation>>>,
    /// Intent hash -> revocation record
    by_intent: Arc<RwLock<HashMap<String, RemoteRevocation>>>,
    /// Tag -> list of revocation records
    by_tag: Arc<RwLock<HashMap<String, Vec<RemoteRevocation>>>>,
    /// Last update timestamp
    last_updated: Arc<RwLock<Option<i64>>>,
}

impl RevocationCache {
    pub fn new() -> Self {
        Self {
            by_principal: Arc::new(RwLock::new(HashMap::new())),
            by_intent: Arc::new(RwLock::new(HashMap::new())),
            by_tag: Arc::new(RwLock::new(HashMap::new())),
            last_updated: Arc::new(RwLock::new(None)),
        }
    }

    /// Update cache from sync snapshot
    pub async fn update_from_snapshot(&self, revocations: &[RemoteRevocation]) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let mut by_principal = self.by_principal.write().await;
        let mut by_intent = self.by_intent.write().await;
        let mut by_tag = self.by_tag.write().await;

        // Clear existing entries
        by_principal.clear();
        by_intent.clear();
        by_tag.clear();

        for revocation in revocations {
            if let Some(ref principal_id) = revocation.principal_id {
                by_principal.insert(principal_id.clone(), revocation.clone());
            }

            if let Some(ref intent_hash) = revocation.intent_hash {
                by_intent.insert(intent_hash.clone(), revocation.clone());
            }

            for tag in &revocation.tags {
                by_tag
                    .entry(tag.clone())
                    .or_insert_with(Vec::new)
                    .push(revocation.clone());
            }
        }

        *self.last_updated.write().await = Some(now);

        info!(
            "Revocation cache updated: {} principals, {} intents, {} tags",
            by_principal.len(),
            by_intent.len(),
            by_tag.len()
        );
    }

    /// Check if a principal is revoked
    pub async fn is_principal_revoked(&self, principal_id: &str) -> Option<RemoteRevocation> {
        self.by_principal.read().await.get(principal_id).cloned()
    }

    /// Check if an intent is revoked
    pub async fn is_intent_revoked(&self, intent_hash: &str) -> Option<RemoteRevocation> {
        self.by_intent.read().await.get(intent_hash).cloned()
    }

    /// Check if any of the given tags are revoked
    pub async fn are_tags_revoked(&self, tags: &[String]) -> Vec<RemoteRevocation> {
        let by_tag = self.by_tag.read().await;
        let mut result = Vec::new();

        for tag in tags {
            if let Some(revocations) = by_tag.get(tag) {
                result.extend(revocations.iter().cloned());
            }
        }

        result
    }

    /// Get cache statistics
    pub async fn stats(&self) -> (usize, usize, usize, Option<i64>) {
        let by_principal = self.by_principal.read().await;
        let by_intent = self.by_intent.read().await;
        let by_tag = self.by_tag.read().await;
        let last_updated = *self.last_updated.read().await;

        (
            by_principal.len(),
            by_intent.len(),
            by_tag.len(),
            last_updated,
        )
    }
}

impl Default for RevocationCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::AuthorizationReason;

    #[test]
    fn test_audit_event_envelope_from_proof_event() {
        let event = ProofEvent {
            event_type: "authorization_allowed".to_string(),
            principal_id: "agent:test".to_string(),
            action: "browser.click".to_string(),
            resource: "https://example.com".to_string(),
            reason: AuthorizationReason::Allowed,
            allowed: true,
            mandate_id: Some("m_123".to_string()),
            emitted_at_epoch_s: 1700000000,
        };

        let envelope =
            AuditEventEnvelope::from_proof_event(&event, "tenant_abc", Some("trace_xyz"));

        assert!(envelope.event_id.starts_with("evt_"));
        assert_eq!(envelope.tenant_id, "tenant_abc");
        assert_eq!(envelope.principal_id, "agent:test");
        assert_eq!(envelope.action, "browser.click");
        assert!(envelope.allowed);
        assert_eq!(envelope.trace_id, Some("trace_xyz".to_string()));
    }

    #[test]
    fn test_usage_credit_record() {
        let record = UsageCreditRecord::authority_check("tenant_abc", "project_123", 1);

        assert_eq!(record.tenant_id, "tenant_abc");
        assert_eq!(record.project_id, "project_123");
        assert_eq!(record.action_type, "authority_check");
        assert_eq!(record.credits, 1);
        assert!(!record.timestamp.is_empty());
    }

    #[tokio::test]
    async fn test_revocation_cache() {
        let cache = RevocationCache::new();

        let revocations = vec![
            RemoteRevocation {
                revocation_id: "rev_1".to_string(),
                revocation_type: "principal".to_string(),
                principal_id: Some("agent:malicious".to_string()),
                intent_hash: None,
                tags: vec!["suspicious".to_string()],
                reason: Some("Compromised".to_string()),
                created_at: "2024-01-01T00:00:00Z".to_string(),
            },
            RemoteRevocation {
                revocation_id: "rev_2".to_string(),
                revocation_type: "intent".to_string(),
                principal_id: None,
                intent_hash: Some("hash_abc".to_string()),
                tags: vec!["blocked".to_string()],
                reason: Some("Dangerous action".to_string()),
                created_at: "2024-01-01T00:00:00Z".to_string(),
            },
        ];

        cache.update_from_snapshot(&revocations).await;

        // Check principal revocation
        let rev = cache.is_principal_revoked("agent:malicious").await;
        assert!(rev.is_some());
        assert_eq!(rev.unwrap().revocation_id, "rev_1");

        // Check non-revoked principal
        assert!(cache.is_principal_revoked("agent:good").await.is_none());

        // Check intent revocation
        let rev = cache.is_intent_revoked("hash_abc").await;
        assert!(rev.is_some());
        assert_eq!(rev.unwrap().revocation_id, "rev_2");

        // Check tag revocations
        let revs = cache.are_tags_revoked(&["suspicious".to_string()]).await;
        assert_eq!(revs.len(), 1);

        // Check stats
        let (principals, intents, tags, updated) = cache.stats().await;
        assert_eq!(principals, 1);
        assert_eq!(intents, 1);
        assert_eq!(tags, 2);
        assert!(updated.is_some());
    }

    #[test]
    fn test_control_plane_config_default() {
        let config = ControlPlaneConfig::default();
        assert_eq!(config.timeout_s, 2.0);
        assert_eq!(config.max_retries, 2);
        assert!(config.fail_open);
        assert!(!config.sync_enabled);
    }
}
