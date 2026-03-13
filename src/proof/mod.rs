//! In-memory proof ledger for audit logging.
//!
//! Records all authorization decisions for later audit and governance.
//! Implements a Merkle hash chain for tamper-evident audit trails.
//!

#![allow(dead_code)]

use parking_lot::RwLock;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;

use crate::models::{AuthorizationReason, ProofEvent};

/// Compute the genesis hash: SHA-256("predicate:genesis")
/// This is the initial chain hash before any events are recorded.
fn compute_genesis_hash() -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"predicate:genesis");
    hex::encode(hasher.finalize())
}

/// Compute a chain hash: SHA-256(prev_hash || ":" || canonical_event_json)
/// This creates a tamper-evident link between consecutive events.
fn compute_chain_hash(prev_hash: &str, event_json: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(prev_hash.as_bytes());
    hasher.update(b":");
    hasher.update(event_json.as_bytes());
    hex::encode(hasher.finalize())
}

/// Generate a unique event ID using UUID v4
fn generate_event_id() -> String {
    format!(
        "evt_{}",
        &uuid::Uuid::new_v4().to_string().replace('-', "")[..16]
    )
}

/// Statistics about authorization decisions
#[derive(Debug, Clone, Default)]
pub struct DecisionStats {
    pub total_allowed: u64,
    pub total_denied: u64,
    pub denied_by_reason: HashMap<String, u64>,
    /// Sum of all latencies in microseconds (for avg calculation)
    pub total_latency_us: u64,
    /// Count of requests with latency data
    pub latency_count: u64,
    /// Minimum latency seen (microseconds)
    pub min_latency_us: Option<u64>,
    /// Maximum latency seen (microseconds)
    pub max_latency_us: Option<u64>,
    /// Number of times headers were injected (env var based)
    pub headers_injected: u64,
    /// Number of times headers were injected from files
    pub headers_injected_from_file: u64,
    /// Number of times env vars were injected (env var based)
    pub env_vars_injected: u64,
    /// Number of times env vars were injected from files
    pub env_vars_injected_from_file: u64,
}

impl DecisionStats {
    /// Calculate average latency in microseconds
    pub fn avg_latency_us(&self) -> Option<u64> {
        if self.latency_count > 0 {
            Some(self.total_latency_us / self.latency_count)
        } else {
            None
        }
    }
}

/// Chain head information for verification
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ChainHead {
    /// The current chain head hash
    pub chain_hash: String,
    /// Total number of events in the chain
    pub event_count: u64,
    /// Event ID of the most recent event (None if chain is empty)
    pub last_event_id: Option<String>,
    /// Timestamp of the most recent event (epoch seconds)
    pub last_event_timestamp: Option<i64>,
    /// The genesis hash used to initialize this chain
    pub genesis_hash: String,
}

/// In-memory proof ledger with Merkle hash chain
pub struct InMemoryProofLedger {
    events: Arc<RwLock<Vec<ProofEvent>>>,
    stats: Arc<RwLock<DecisionStats>>,
    /// Current chain head hash - updated on each record
    chain_head: Arc<RwLock<String>>,
    /// Genesis hash for this ledger instance
    genesis_hash: String,
    /// Total events ever recorded (not affected by capacity cleanup)
    total_events: Arc<RwLock<u64>>,
    max_events: usize,
}

impl InMemoryProofLedger {
    /// Create a new ledger with default capacity (10000 events)
    pub fn new() -> Self {
        Self::with_capacity(10_000)
    }

    /// Create a ledger with specified max event capacity
    pub fn with_capacity(max_events: usize) -> Self {
        let genesis_hash = compute_genesis_hash();
        Self {
            events: Arc::new(RwLock::new(Vec::with_capacity(max_events.min(1000)))),
            stats: Arc::new(RwLock::new(DecisionStats::default())),
            chain_head: Arc::new(RwLock::new(genesis_hash.clone())),
            genesis_hash,
            total_events: Arc::new(RwLock::new(0)),
            max_events,
        }
    }

    /// Record an authorization event with hash chain computation
    pub fn record(&self, mut event: ProofEvent) {
        // Generate event ID if not present
        if event.event_id.is_none() {
            event.event_id = Some(generate_event_id());
        }

        // Compute chain hash
        let chain_hash = {
            let prev_hash = self.chain_head.read().clone();

            // Create a temporary event without chain_hash for canonical serialization
            let canonical_event = ProofEvent {
                event_type: event.event_type.clone(),
                principal_id: event.principal_id.clone(),
                action: event.action.clone(),
                resource: event.resource.clone(),
                reason: event.reason.clone(),
                allowed: event.allowed,
                mandate_id: event.mandate_id.clone(),
                emitted_at_epoch_s: event.emitted_at_epoch_s,
                latency_us: event.latency_us,
                event_id: event.event_id.clone(),
                chain_hash: None, // Excluded from hash computation
            };

            // Serialize to canonical JSON (sorted keys)
            let event_json =
                serde_json::to_string(&canonical_event).unwrap_or_else(|_| "{}".to_string());

            compute_chain_hash(&prev_hash, &event_json)
        };

        // Set the chain hash on the event
        event.chain_hash = Some(chain_hash.clone());

        // Update chain head
        *self.chain_head.write() = chain_hash;

        // Update stats
        {
            let mut stats = self.stats.write();
            if event.allowed {
                stats.total_allowed += 1;
            } else {
                stats.total_denied += 1;
                let reason_key = event.reason.to_string();
                *stats.denied_by_reason.entry(reason_key).or_insert(0) += 1;
            }

            // Track latency stats
            if let Some(latency) = event.latency_us {
                stats.total_latency_us += latency;
                stats.latency_count += 1;
                stats.min_latency_us =
                    Some(stats.min_latency_us.map_or(latency, |min| min.min(latency)));
                stats.max_latency_us =
                    Some(stats.max_latency_us.map_or(latency, |max| max.max(latency)));
            }
        }

        // Increment total events counter
        *self.total_events.write() += 1;

        // Store event (with capacity limit)
        {
            let mut events = self.events.write();
            if events.len() >= self.max_events {
                // Remove oldest 10% when full
                let remove_count = self.max_events / 10;
                events.drain(0..remove_count);
            }
            events.push(event);
        }
    }

    /// Create and record an event from authorization parameters
    pub fn record_decision(
        &self,
        principal_id: &str,
        action: &str,
        resource: &str,
        allowed: bool,
        reason: AuthorizationReason,
        mandate_id: Option<String>,
    ) {
        self.record_decision_with_latency(
            principal_id,
            action,
            resource,
            allowed,
            reason,
            mandate_id,
            None,
        );
    }

    /// Create and record an event with latency tracking
    #[allow(clippy::too_many_arguments)]
    pub fn record_decision_with_latency(
        &self,
        principal_id: &str,
        action: &str,
        resource: &str,
        allowed: bool,
        reason: AuthorizationReason,
        mandate_id: Option<String>,
        latency_us: Option<u64>,
    ) {
        let event = ProofEvent {
            event_type: if allowed {
                "authorization_allowed".to_string()
            } else {
                "authorization_denied".to_string()
            },
            principal_id: principal_id.to_string(),
            action: action.to_string(),
            resource: resource.to_string(),
            reason,
            allowed,
            mandate_id,
            emitted_at_epoch_s: chrono::Utc::now().timestamp(),
            latency_us,
            event_id: None,   // Will be generated in record()
            chain_hash: None, // Will be computed in record()
        };
        self.record(event);
    }

    /// Get current statistics
    pub fn stats(&self) -> DecisionStats {
        self.stats.read().clone()
    }

    /// Record secret injection events for metrics tracking
    ///
    /// # Arguments
    /// * `headers_from_env` - Number of headers injected from env vars
    /// * `headers_from_file` - Number of headers injected from files
    /// * `env_vars_from_env` - Number of env vars injected from env vars
    /// * `env_vars_from_file` - Number of env vars injected from files
    pub fn record_injection(
        &self,
        headers_from_env: usize,
        headers_from_file: usize,
        env_vars_from_env: usize,
        env_vars_from_file: usize,
    ) {
        let mut stats = self.stats.write();
        stats.headers_injected += headers_from_env as u64;
        stats.headers_injected_from_file += headers_from_file as u64;
        stats.env_vars_injected += env_vars_from_env as u64;
        stats.env_vars_injected_from_file += env_vars_from_file as u64;
    }

    /// Get total event count (events currently in memory)
    pub fn event_count(&self) -> usize {
        self.events.read().len()
    }

    /// Get the chain head information for verification
    pub fn chain_head(&self) -> ChainHead {
        let events = self.events.read();
        let last_event = events.last();

        ChainHead {
            chain_hash: self.chain_head.read().clone(),
            event_count: *self.total_events.read(),
            last_event_id: last_event.and_then(|e| e.event_id.clone()),
            last_event_timestamp: last_event.map(|e| e.emitted_at_epoch_s),
            genesis_hash: self.genesis_hash.clone(),
        }
    }

    /// Get recent events (newest first)
    pub fn recent_events(&self, limit: usize) -> Vec<ProofEvent> {
        let events = self.events.read();
        events.iter().rev().take(limit).cloned().collect()
    }

    /// Verify the integrity of the hash chain for events in memory.
    /// Returns true if the chain is valid, false if tampering is detected.
    pub fn verify_chain(&self) -> bool {
        let events = self.events.read();
        if events.is_empty() {
            return true;
        }

        let mut prev_hash = self.genesis_hash.clone();

        for event in events.iter() {
            // Recreate canonical event without chain_hash
            let canonical_event = ProofEvent {
                event_type: event.event_type.clone(),
                principal_id: event.principal_id.clone(),
                action: event.action.clone(),
                resource: event.resource.clone(),
                reason: event.reason.clone(),
                allowed: event.allowed,
                mandate_id: event.mandate_id.clone(),
                emitted_at_epoch_s: event.emitted_at_epoch_s,
                latency_us: event.latency_us,
                event_id: event.event_id.clone(),
                chain_hash: None,
            };

            let event_json =
                serde_json::to_string(&canonical_event).unwrap_or_else(|_| "{}".to_string());

            let expected_hash = compute_chain_hash(&prev_hash, &event_json);

            if let Some(ref actual_hash) = event.chain_hash {
                if actual_hash != &expected_hash {
                    return false; // Tampering detected
                }
                prev_hash = actual_hash.clone();
            } else {
                return false; // Missing chain hash
            }
        }

        true
    }

    /// Clear all events (useful for testing)
    pub fn clear(&self) {
        self.events.write().clear();
        *self.stats.write() = DecisionStats::default();
        *self.chain_head.write() = self.genesis_hash.clone();
        *self.total_events.write() = 0;
    }
}

impl Default for InMemoryProofLedger {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_genesis_hash_deterministic() {
        let hash1 = compute_genesis_hash();
        let hash2 = compute_genesis_hash();
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 64); // SHA-256 produces 64 hex chars
    }

    #[test]
    fn test_chain_hash_deterministic() {
        let hash1 = compute_chain_hash("prev", "event");
        let hash2 = compute_chain_hash("prev", "event");
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_chain_hash_changes_with_input() {
        let hash1 = compute_chain_hash("prev1", "event");
        let hash2 = compute_chain_hash("prev2", "event");
        assert_ne!(hash1, hash2);

        let hash3 = compute_chain_hash("prev", "event1");
        let hash4 = compute_chain_hash("prev", "event2");
        assert_ne!(hash3, hash4);
    }

    #[test]
    fn test_record_allowed_event() {
        let ledger = InMemoryProofLedger::new();

        ledger.record_decision(
            "agent:web",
            "browser.click",
            "https://example.com",
            true,
            AuthorizationReason::Allowed,
            Some("m_123".to_string()),
        );

        let stats = ledger.stats();
        assert_eq!(stats.total_allowed, 1);
        assert_eq!(stats.total_denied, 0);
        assert_eq!(ledger.event_count(), 1);

        // Verify chain hash was set
        let events = ledger.recent_events(1);
        assert!(events[0].chain_hash.is_some());
        assert!(events[0].event_id.is_some());
    }

    #[test]
    fn test_record_denied_event() {
        let ledger = InMemoryProofLedger::new();

        ledger.record_decision(
            "agent:web",
            "admin.delete",
            "/users/123",
            false,
            AuthorizationReason::ExplicitDeny,
            None,
        );

        let stats = ledger.stats();
        assert_eq!(stats.total_allowed, 0);
        assert_eq!(stats.total_denied, 1);
        assert_eq!(stats.denied_by_reason.get("explicit_deny"), Some(&1));
    }

    #[test]
    fn test_chain_head_updates() {
        let ledger = InMemoryProofLedger::new();

        let initial_head = ledger.chain_head();
        assert_eq!(initial_head.event_count, 0);
        assert_eq!(initial_head.chain_hash, ledger.genesis_hash);

        ledger.record_decision(
            "agent:1",
            "action",
            "resource",
            true,
            AuthorizationReason::Allowed,
            None,
        );

        let head1 = ledger.chain_head();
        assert_eq!(head1.event_count, 1);
        assert_ne!(head1.chain_hash, initial_head.chain_hash);

        ledger.record_decision(
            "agent:2",
            "action",
            "resource",
            true,
            AuthorizationReason::Allowed,
            None,
        );

        let head2 = ledger.chain_head();
        assert_eq!(head2.event_count, 2);
        assert_ne!(head2.chain_hash, head1.chain_hash);
    }

    #[test]
    fn test_verify_chain_empty() {
        let ledger = InMemoryProofLedger::new();
        assert!(ledger.verify_chain());
    }

    #[test]
    fn test_verify_chain_valid() {
        let ledger = InMemoryProofLedger::new();

        for i in 0..5 {
            ledger.record_decision(
                &format!("agent:{}", i),
                "test.action",
                "test://resource",
                true,
                AuthorizationReason::Allowed,
                None,
            );
        }

        assert!(ledger.verify_chain());
    }

    #[test]
    fn test_verify_chain_detects_tampering() {
        let ledger = InMemoryProofLedger::new();

        ledger.record_decision(
            "agent:1",
            "action",
            "resource",
            true,
            AuthorizationReason::Allowed,
            None,
        );
        ledger.record_decision(
            "agent:2",
            "action",
            "resource",
            true,
            AuthorizationReason::Allowed,
            None,
        );

        // Tamper with an event
        {
            let mut events = ledger.events.write();
            events[0].principal_id = "agent:tampered".to_string();
        }

        assert!(!ledger.verify_chain());
    }

    #[test]
    fn test_capacity_limit() {
        let ledger = InMemoryProofLedger::with_capacity(100);

        // Add 150 events (should trigger cleanup)
        for i in 0..150 {
            ledger.record_decision(
                &format!("agent:{}", i),
                "test.action",
                "test://resource",
                true,
                AuthorizationReason::Allowed,
                None,
            );
        }

        // Should be below max capacity
        assert!(ledger.event_count() <= 100);

        // Total events should still reflect all recorded
        assert_eq!(*ledger.total_events.read(), 150);
    }

    #[test]
    fn test_recent_events_order() {
        let ledger = InMemoryProofLedger::new();

        ledger.record_decision(
            "agent:1",
            "a",
            "r",
            true,
            AuthorizationReason::Allowed,
            None,
        );
        ledger.record_decision(
            "agent:2",
            "a",
            "r",
            true,
            AuthorizationReason::Allowed,
            None,
        );
        ledger.record_decision(
            "agent:3",
            "a",
            "r",
            true,
            AuthorizationReason::Allowed,
            None,
        );

        let recent = ledger.recent_events(2);
        assert_eq!(recent.len(), 2);
        assert_eq!(recent[0].principal_id, "agent:3"); // Most recent first
        assert_eq!(recent[1].principal_id, "agent:2");
    }

    #[test]
    fn test_clear_resets_chain() {
        let ledger = InMemoryProofLedger::new();

        ledger.record_decision(
            "agent:1",
            "action",
            "resource",
            true,
            AuthorizationReason::Allowed,
            None,
        );

        let head_before = ledger.chain_head();
        assert_ne!(head_before.chain_hash, ledger.genesis_hash);

        ledger.clear();

        let head_after = ledger.chain_head();
        assert_eq!(head_after.chain_hash, ledger.genesis_hash);
        assert_eq!(head_after.event_count, 0);
    }
}
