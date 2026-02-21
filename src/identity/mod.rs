//! Local identity registry with JSON file persistence.
//!
//! Manages task identities and audit queue for local sidecar operation.
//!
//! # Ephemeral Design Philosophy
//!
//! This module deliberately implements ephemeral logging to discourage reliance
//! on sidecar logs for enterprise audit requirements. Key design decisions:
//!
//! - **24-hour TTL**: Queue items auto-expire to prevent log accumulation
//! - **Payload redaction**: Sensitive fields redacted by default, directing users
//!   to control-plane for full audit trail
//! - **No cross-node aggregation**: Each sidecar maintains isolated local storage
//! - **File permissions**: 0o600 for files, 0o700 for directories (Unix)
//!
//! For durable, queryable audit storage, use the control-plane audit vault.

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

use crate::models::ProofEvent;

/// Default TTL for task identities (15 minutes)
const DEFAULT_IDENTITY_TTL_SECONDS: i64 = 900;

/// Default TTL for queue items (24 hours).
///
/// Ephemeral by design: local logs auto-expire to encourage control-plane adoption
/// for enterprise audit requirements.
const DEFAULT_QUEUE_ITEM_TTL_SECONDS: i64 = 24 * 60 * 60;

/// Task identity record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskIdentityRecord {
    pub identity_id: String,
    pub principal_id: String,
    pub task_id: String,
    pub issued_at_epoch_s: i64,
    pub expires_at_epoch_s: i64,
    #[serde(default)]
    pub revoked: bool,
    #[serde(default)]
    pub metadata: HashMap<String, String>,
}

/// Ledger queue item for audit events
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LedgerQueueItem {
    pub queue_item_id: String,
    pub enqueued_at_epoch_s: i64,
    pub payload: serde_json::Value,
    #[serde(default)]
    pub flushed: bool,
    #[serde(default)]
    pub flush_attempts: u32,
    #[serde(default)]
    pub last_error: Option<String>,
    #[serde(default)]
    pub flushed_at_epoch_s: Option<i64>,
    #[serde(default)]
    pub quarantined: bool,
    #[serde(default)]
    pub quarantine_reason: Option<String>,
    #[serde(default)]
    pub quarantined_at_epoch_s: Option<i64>,
}

/// Statistics for the local identity registry
#[derive(Debug, Clone, Serialize)]
pub struct LocalIdentityRegistryStats {
    pub total_identity_count: usize,
    pub active_identity_count: usize,
    pub pending_flush_queue_count: usize,
    pub flushed_queue_count: usize,
    pub failed_queue_count: usize,
    pub quarantined_queue_count: usize,
}

/// Registry storage structure
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct RegistryStore {
    #[serde(default)]
    identities: HashMap<String, TaskIdentityRecord>,
    #[serde(default)]
    flush_queue: HashMap<String, LedgerQueueItem>,
}

/// Local identity registry with file-based persistence
pub struct LocalIdentityRegistry {
    file_path: PathBuf,
    default_ttl_seconds: i64,
    queue_item_ttl_seconds: i64,
    store: Arc<RwLock<RegistryStore>>,
}

impl LocalIdentityRegistry {
    /// Create a new local identity registry
    pub fn new(
        file_path: &Path,
        default_ttl_seconds: Option<i64>,
        queue_item_ttl_seconds: Option<i64>,
    ) -> Self {
        let registry = Self {
            file_path: file_path.to_path_buf(),
            default_ttl_seconds: default_ttl_seconds.unwrap_or(DEFAULT_IDENTITY_TTL_SECONDS),
            queue_item_ttl_seconds: queue_item_ttl_seconds
                .unwrap_or(DEFAULT_QUEUE_ITEM_TTL_SECONDS),
            store: Arc::new(RwLock::new(RegistryStore::default())),
        };

        // Initialize storage
        registry.ensure_store_path();
        registry.load_from_disk();

        registry
    }

    /// Issue a new task identity
    pub fn issue_task_identity(
        &self,
        principal_id: &str,
        task_id: &str,
        ttl_seconds: Option<i64>,
        metadata: Option<HashMap<String, String>>,
    ) -> Result<TaskIdentityRecord, &'static str> {
        let ttl = ttl_seconds.unwrap_or(self.default_ttl_seconds);
        if ttl <= 0 {
            return Err("ttl_seconds must be > 0");
        }

        let now = Self::now_epoch();
        let identity_id = format!("lid_{}", &Uuid::new_v4().to_string().replace("-", "")[..16]);

        let record = TaskIdentityRecord {
            identity_id: identity_id.clone(),
            principal_id: principal_id.to_string(),
            task_id: task_id.to_string(),
            issued_at_epoch_s: now,
            expires_at_epoch_s: now + ttl,
            revoked: false,
            metadata: metadata.unwrap_or_default(),
        };

        {
            let mut store = self.store.write();
            store.identities.insert(identity_id, record.clone());
        }

        self.persist_to_disk();
        Ok(record)
    }

    /// Revoke an identity
    pub fn revoke_identity(&self, identity_id: &str) -> bool {
        let mut store = self.store.write();
        if let Some(record) = store.identities.get_mut(identity_id) {
            record.revoked = true;
            drop(store);
            self.persist_to_disk();
            true
        } else {
            false
        }
    }

    /// Check if an identity is active (not revoked and not expired)
    pub fn is_identity_active(&self, identity_id: &str) -> bool {
        let now = Self::now_epoch();
        let store = self.store.read();
        if let Some(record) = store.identities.get(identity_id) {
            !record.revoked && now < record.expires_at_epoch_s
        } else {
            false
        }
    }

    /// Get an identity by ID
    pub fn get_identity(&self, identity_id: &str) -> Option<TaskIdentityRecord> {
        let store = self.store.read();
        store.identities.get(identity_id).cloned()
    }

    /// List all identities
    pub fn list_identities(
        &self,
        include_revoked: bool,
        include_expired: bool,
    ) -> Vec<TaskIdentityRecord> {
        let now = Self::now_epoch();
        let store = self.store.read();
        store
            .identities
            .values()
            .filter(|r| {
                let is_expired = now >= r.expires_at_epoch_s;
                let include = (include_revoked || !r.revoked) && (include_expired || !is_expired);
                include
            })
            .cloned()
            .collect()
    }

    /// Expire identities that have passed their TTL
    pub fn expire_identities(&self) -> usize {
        let now = Self::now_epoch();
        let mut expired_count = 0;

        {
            let mut store = self.store.write();
            for record in store.identities.values_mut() {
                if !record.revoked && now >= record.expires_at_epoch_s {
                    record.revoked = true;
                    expired_count += 1;
                }
            }
        }

        if expired_count > 0 {
            self.persist_to_disk();
        }

        expired_count
    }

    /// Enqueue a proof event for flushing to control-plane
    pub fn enqueue_proof_event(&self, event: &ProofEvent) -> LedgerQueueItem {
        let now = Self::now_epoch();
        let queue_item_id = format!("q_{}", &Uuid::new_v4().to_string().replace("-", "")[..16]);

        let payload = serde_json::json!({
            "source": "predicate-authorityd",
            "event_type": event.event_type,
            "principal_id": event.principal_id,
            "action": event.action,
            "resource": event.resource,
            "reason": event.reason.to_string(),
            "allowed": event.allowed,
            "mandate_id": event.mandate_id,
            "emitted_at_epoch_s": event.emitted_at_epoch_s,
        });

        let item = LedgerQueueItem {
            queue_item_id: queue_item_id.clone(),
            enqueued_at_epoch_s: now,
            payload,
            flushed: false,
            flush_attempts: 0,
            last_error: None,
            flushed_at_epoch_s: None,
            quarantined: false,
            quarantine_reason: None,
            quarantined_at_epoch_s: None,
        };

        {
            let mut store = self.store.write();
            store.flush_queue.insert(queue_item_id, item.clone());
        }

        self.persist_to_disk();
        item
    }

    /// Mark a queue item as successfully flushed
    pub fn mark_flush_ack(&self, queue_item_id: &str) -> bool {
        let now = Self::now_epoch();
        let mut store = self.store.write();

        if let Some(item) = store.flush_queue.get_mut(queue_item_id) {
            item.flushed = true;
            item.flush_attempts += 1;
            item.last_error = None;
            item.flushed_at_epoch_s = Some(now);
            drop(store);
            self.persist_to_disk();
            true
        } else {
            false
        }
    }

    /// Mark a queue item flush as failed
    pub fn mark_flush_failed(&self, queue_item_id: &str, error: &str) -> bool {
        let mut store = self.store.write();

        if let Some(item) = store.flush_queue.get_mut(queue_item_id) {
            item.flush_attempts += 1;
            item.last_error = Some(error.to_string());
            drop(store);
            self.persist_to_disk();
            true
        } else {
            false
        }
    }

    /// Quarantine a queue item (move to dead-letter queue)
    pub fn quarantine_queue_item(&self, queue_item_id: &str, reason: &str) -> bool {
        let now = Self::now_epoch();
        let mut store = self.store.write();

        if let Some(item) = store.flush_queue.get_mut(queue_item_id) {
            item.quarantined = true;
            item.quarantine_reason = Some(reason.to_string());
            item.quarantined_at_epoch_s = Some(now);
            drop(store);
            self.persist_to_disk();
            true
        } else {
            false
        }
    }

    /// Requeue a quarantined item
    pub fn requeue_item(&self, queue_item_id: &str, reset_attempts: bool) -> bool {
        let mut store = self.store.write();

        if let Some(item) = store.flush_queue.get_mut(queue_item_id) {
            if !item.quarantined {
                return false;
            }

            item.quarantined = false;
            item.quarantine_reason = None;
            item.quarantined_at_epoch_s = None;
            item.flushed = false;
            item.flushed_at_epoch_s = None;
            item.last_error = None;

            if reset_attempts {
                item.flush_attempts = 0;
            }

            drop(store);
            self.persist_to_disk();
            true
        } else {
            false
        }
    }

    /// List queue items with optional payload redaction.
    ///
    /// By default, payloads are redacted to prevent local sidecar logs from
    /// serving as a queryable audit trail. Full payloads are only accessible
    /// via control-plane audit vault.
    pub fn list_flush_queue(
        &self,
        include_flushed: bool,
        include_quarantined: bool,
        limit: Option<usize>,
        redact_payloads: bool,
    ) -> Vec<LedgerQueueItem> {
        let store = self.store.read();
        let mut items: Vec<_> = store
            .flush_queue
            .values()
            .filter(|item| {
                let include = (!item.flushed || include_flushed)
                    && (!item.quarantined || include_quarantined);
                include
            })
            .cloned()
            .collect();

        // Sort by enqueued time
        items.sort_by_key(|i| i.enqueued_at_epoch_s);

        // Apply limit
        if let Some(lim) = limit {
            items.truncate(lim);
        }

        // Redact payloads if requested
        if redact_payloads {
            items = items
                .into_iter()
                .map(|i| Self::redact_queue_item(i))
                .collect();
        }

        items
    }

    /// List dead-letter queue items
    pub fn list_dead_letter_queue(
        &self,
        limit: Option<usize>,
        redact_payloads: bool,
    ) -> Vec<LedgerQueueItem> {
        let store = self.store.read();
        let mut items: Vec<_> = store
            .flush_queue
            .values()
            .filter(|item| item.quarantined)
            .cloned()
            .collect();

        // Sort by quarantined time
        items.sort_by_key(|i| i.quarantined_at_epoch_s.unwrap_or(0));

        // Apply limit
        if let Some(lim) = limit {
            items.truncate(lim);
        }

        // Redact payloads if requested
        if redact_payloads {
            items = items
                .into_iter()
                .map(|i| Self::redact_queue_item(i))
                .collect();
        }

        items
    }

    /// Remove queue items older than queue_item_ttl_seconds.
    ///
    /// Ephemeral logging: local audit events auto-expire to discourage
    /// reliance on sidecar logs for enterprise audit requirements.
    /// Control-plane provides durable, queryable audit storage.
    ///
    /// Returns the count of expired (deleted) queue items.
    pub fn expire_queue_items(&self) -> usize {
        let now = Self::now_epoch();
        let cutoff = now - self.queue_item_ttl_seconds;
        let mut expired_count = 0;

        {
            let mut store = self.store.write();
            store.flush_queue.retain(|_, item| {
                if item.enqueued_at_epoch_s < cutoff {
                    expired_count += 1;
                    false
                } else {
                    true
                }
            });
        }

        if expired_count > 0 {
            self.persist_to_disk();
        }

        expired_count
    }

    /// Get registry statistics
    pub fn stats(&self) -> LocalIdentityRegistryStats {
        let now = Self::now_epoch();
        let store = self.store.read();

        let total_identity_count = store.identities.len();
        let active_identity_count = store
            .identities
            .values()
            .filter(|r| !r.revoked && now < r.expires_at_epoch_s)
            .count();

        let pending_flush_queue_count = store
            .flush_queue
            .values()
            .filter(|i| !i.flushed && !i.quarantined)
            .count();

        let flushed_queue_count = store.flush_queue.values().filter(|i| i.flushed).count();

        let failed_queue_count = store
            .flush_queue
            .values()
            .filter(|i| i.last_error.is_some() && !i.flushed && !i.quarantined)
            .count();

        let quarantined_queue_count = store.flush_queue.values().filter(|i| i.quarantined).count();

        LocalIdentityRegistryStats {
            total_identity_count,
            active_identity_count,
            pending_flush_queue_count,
            flushed_queue_count,
            failed_queue_count,
            quarantined_queue_count,
        }
    }

    // --- Internal methods ---

    fn now_epoch() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    }

    fn ensure_store_path(&self) {
        if let Some(parent) = self.file_path.parent() {
            if !parent.exists() {
                fs::create_dir_all(parent).ok();
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).ok();
                }
            }
        }

        if !self.file_path.exists() {
            let store = RegistryStore::default();
            let json = serde_json::to_string_pretty(&store).unwrap();
            fs::write(&self.file_path, json).ok();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&self.file_path, fs::Permissions::from_mode(0o600)).ok();
            }
        }
    }

    fn load_from_disk(&self) {
        if let Ok(content) = fs::read_to_string(&self.file_path) {
            if let Ok(store) = serde_json::from_str::<RegistryStore>(&content) {
                *self.store.write() = store;
            }
        }
    }

    fn persist_to_disk(&self) {
        let store = self.store.read();
        let json = serde_json::to_string_pretty(&*store).unwrap();
        drop(store);

        // Atomic write using temp file + rename
        let tmp_path = self
            .file_path
            .with_extension(format!("{}.tmp", Uuid::new_v4()));

        if fs::write(&tmp_path, &json).is_ok() {
            if fs::rename(&tmp_path, &self.file_path).is_ok() {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    fs::set_permissions(&self.file_path, fs::Permissions::from_mode(0o600)).ok();
                }
            } else {
                // Cleanup temp file on rename failure
                fs::remove_file(&tmp_path).ok();
            }
        }
    }

    /// Redact sensitive payload fields from queue item.
    ///
    /// Preserves queue metadata (id, timestamps, status) but replaces
    /// audit-relevant payload fields to discourage local log aggregation.
    /// This matches the Python sidecar's `_redact_queue_item` behavior.
    fn redact_queue_item(item: LedgerQueueItem) -> LedgerQueueItem {
        const REDACT_MARKER: &str = "[REDACTED - use control-plane for full audit]";

        let mut redacted_payload = serde_json::Map::new();

        if let Some(payload) = item.payload.as_object() {
            // Preserve only non-sensitive metadata (matches Python behavior)
            if let Some(source) = payload.get("source") {
                redacted_payload.insert("source".to_string(), source.clone());
            }
            if let Some(event_type) = payload.get("event_type") {
                redacted_payload.insert("event_type".to_string(), event_type.clone());
            }
            if let Some(emitted_at) = payload.get("emitted_at_epoch_s") {
                redacted_payload.insert("emitted_at_epoch_s".to_string(), emitted_at.clone());
            }

            // Redact audit-sensitive fields
            for field in &["principal_id", "action", "resource", "reason", "mandate_id"] {
                if payload.contains_key(*field) {
                    redacted_payload.insert(field.to_string(), serde_json::json!(REDACT_MARKER));
                }
            }

            // Preserve allowed/denied decision indicator only (matches Python)
            if let Some(allowed) = payload.get("allowed") {
                redacted_payload.insert("allowed".to_string(), allowed.clone());
            }
        }

        LedgerQueueItem {
            queue_item_id: item.queue_item_id,
            enqueued_at_epoch_s: item.enqueued_at_epoch_s,
            payload: serde_json::Value::Object(redacted_payload),
            flushed: item.flushed,
            flush_attempts: item.flush_attempts,
            last_error: item.last_error,
            flushed_at_epoch_s: item.flushed_at_epoch_s,
            quarantined: item.quarantined,
            quarantine_reason: item.quarantine_reason,
            quarantined_at_epoch_s: item.quarantined_at_epoch_s,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::AuthorizationReason;
    use tempfile::TempDir;

    fn test_registry() -> (LocalIdentityRegistry, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test-registry.json");
        let registry = LocalIdentityRegistry::new(&file_path, Some(60), Some(3600));
        (registry, temp_dir)
    }

    #[test]
    fn test_issue_and_get_identity() {
        let (registry, _temp) = test_registry();

        let record = registry
            .issue_task_identity("agent:test", "task-123", None, None)
            .unwrap();

        assert!(record.identity_id.starts_with("lid_"));
        assert_eq!(record.principal_id, "agent:test");
        assert_eq!(record.task_id, "task-123");
        assert!(!record.revoked);

        let retrieved = registry.get_identity(&record.identity_id).unwrap();
        assert_eq!(retrieved.identity_id, record.identity_id);

        assert!(registry.is_identity_active(&record.identity_id));
    }

    #[test]
    fn test_revoke_identity() {
        let (registry, _temp) = test_registry();

        let record = registry
            .issue_task_identity("agent:test", "task-456", None, None)
            .unwrap();

        assert!(registry.is_identity_active(&record.identity_id));

        assert!(registry.revoke_identity(&record.identity_id));
        assert!(!registry.is_identity_active(&record.identity_id));

        let retrieved = registry.get_identity(&record.identity_id).unwrap();
        assert!(retrieved.revoked);
    }

    #[test]
    fn test_expire_identities() {
        let (registry, _temp) = test_registry();

        // Issue with 1 second TTL
        let record = registry
            .issue_task_identity("agent:test", "task-expire", Some(1), None)
            .unwrap();

        assert!(registry.is_identity_active(&record.identity_id));

        // Wait for expiration
        std::thread::sleep(std::time::Duration::from_secs(2));

        assert!(!registry.is_identity_active(&record.identity_id));

        let expired_count = registry.expire_identities();
        assert_eq!(expired_count, 1);
    }

    #[test]
    fn test_enqueue_and_list_queue() {
        let (registry, _temp) = test_registry();

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

        let item = registry.enqueue_proof_event(&event);
        assert!(item.queue_item_id.starts_with("q_"));
        assert!(!item.flushed);
        assert!(!item.quarantined);

        let pending = registry.list_flush_queue(false, false, None, false);
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].queue_item_id, item.queue_item_id);
    }

    #[test]
    fn test_flush_ack() {
        let (registry, _temp) = test_registry();

        let event = ProofEvent {
            event_type: "authorization_allowed".to_string(),
            principal_id: "agent:test".to_string(),
            action: "test.action".to_string(),
            resource: "test://resource".to_string(),
            reason: AuthorizationReason::Allowed,
            allowed: true,
            mandate_id: None,
            emitted_at_epoch_s: 1700000000,
        };

        let item = registry.enqueue_proof_event(&event);
        assert!(registry.mark_flush_ack(&item.queue_item_id));

        let pending = registry.list_flush_queue(false, false, None, false);
        assert_eq!(pending.len(), 0);

        let flushed = registry.list_flush_queue(true, false, None, false);
        assert_eq!(flushed.len(), 1);
        assert!(flushed[0].flushed);
    }

    #[test]
    fn test_dead_letter_queue() {
        let (registry, _temp) = test_registry();

        let event = ProofEvent {
            event_type: "authorization_denied".to_string(),
            principal_id: "agent:test".to_string(),
            action: "admin.delete".to_string(),
            resource: "/users/123".to_string(),
            reason: AuthorizationReason::ExplicitDeny,
            allowed: false,
            mandate_id: None,
            emitted_at_epoch_s: 1700000000,
        };

        let item = registry.enqueue_proof_event(&event);

        // Simulate failures and quarantine
        registry.mark_flush_failed(&item.queue_item_id, "connection error");
        registry.quarantine_queue_item(&item.queue_item_id, "max_attempts_exceeded");

        let dead_letter = registry.list_dead_letter_queue(None, false);
        assert_eq!(dead_letter.len(), 1);
        assert!(dead_letter[0].quarantined);

        // Requeue
        assert!(registry.requeue_item(&item.queue_item_id, true));

        let dead_letter = registry.list_dead_letter_queue(None, false);
        assert_eq!(dead_letter.len(), 0);

        let pending = registry.list_flush_queue(false, false, None, false);
        assert_eq!(pending.len(), 1);
    }

    #[test]
    fn test_stats() {
        let (registry, _temp) = test_registry();

        // Add identity
        registry
            .issue_task_identity("agent:test", "task-1", None, None)
            .unwrap();

        // Add queue item
        let event = ProofEvent {
            event_type: "test".to_string(),
            principal_id: "agent:test".to_string(),
            action: "test".to_string(),
            resource: "test".to_string(),
            reason: AuthorizationReason::Allowed,
            allowed: true,
            mandate_id: None,
            emitted_at_epoch_s: 1700000000,
        };
        registry.enqueue_proof_event(&event);

        let stats = registry.stats();
        assert_eq!(stats.total_identity_count, 1);
        assert_eq!(stats.active_identity_count, 1);
        assert_eq!(stats.pending_flush_queue_count, 1);
    }

    #[test]
    fn test_redaction() {
        let (registry, _temp) = test_registry();

        let event = ProofEvent {
            event_type: "authorization_allowed".to_string(),
            principal_id: "agent:sensitive".to_string(),
            action: "sensitive.action".to_string(),
            resource: "secret://data".to_string(),
            reason: AuthorizationReason::Allowed,
            allowed: true,
            mandate_id: Some("m_secret".to_string()),
            emitted_at_epoch_s: 1700000000,
        };

        registry.enqueue_proof_event(&event);

        // Get redacted queue
        let redacted = registry.list_flush_queue(false, false, None, true);
        assert_eq!(redacted.len(), 1);

        let payload = redacted[0].payload.as_object().unwrap();

        // Verify sensitive fields are redacted
        assert!(payload["principal_id"]
            .as_str()
            .unwrap()
            .contains("REDACTED"));
        assert!(payload["action"].as_str().unwrap().contains("REDACTED"));
        assert!(payload["resource"].as_str().unwrap().contains("REDACTED"));
        assert!(payload["reason"].as_str().unwrap().contains("REDACTED"));
        assert!(payload["mandate_id"].as_str().unwrap().contains("REDACTED"));

        // Verify non-sensitive metadata is preserved (matches Python behavior)
        assert_eq!(payload["source"].as_str().unwrap(), "predicate-authorityd");
        assert_eq!(
            payload["event_type"].as_str().unwrap(),
            "authorization_allowed"
        );
        assert_eq!(payload["emitted_at_epoch_s"].as_i64().unwrap(), 1700000000);
        assert_eq!(payload["allowed"].as_bool().unwrap(), true);
    }
}
