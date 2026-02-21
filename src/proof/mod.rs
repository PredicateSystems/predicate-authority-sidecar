//! In-memory proof ledger for audit logging.
//!
//! Records all authorization decisions for later audit and governance.

use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;

use crate::models::{AuthorizationReason, ProofEvent};

/// Statistics about authorization decisions
#[derive(Debug, Clone, Default)]
pub struct DecisionStats {
    pub total_allowed: u64,
    pub total_denied: u64,
    pub denied_by_reason: HashMap<String, u64>,
}

/// In-memory proof ledger
pub struct InMemoryProofLedger {
    events: Arc<RwLock<Vec<ProofEvent>>>,
    stats: Arc<RwLock<DecisionStats>>,
    max_events: usize,
}

impl InMemoryProofLedger {
    /// Create a new ledger with default capacity (10000 events)
    pub fn new() -> Self {
        Self::with_capacity(10_000)
    }

    /// Create a ledger with specified max event capacity
    pub fn with_capacity(max_events: usize) -> Self {
        Self {
            events: Arc::new(RwLock::new(Vec::with_capacity(max_events.min(1000)))),
            stats: Arc::new(RwLock::new(DecisionStats::default())),
            max_events,
        }
    }

    /// Record an authorization event
    pub fn record(&self, event: ProofEvent) {
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
        }

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
        };
        self.record(event);
    }

    /// Get current statistics
    pub fn stats(&self) -> DecisionStats {
        self.stats.read().clone()
    }

    /// Get total event count
    pub fn event_count(&self) -> usize {
        self.events.read().len()
    }

    /// Get recent events (newest first)
    pub fn recent_events(&self, limit: usize) -> Vec<ProofEvent> {
        let events = self.events.read();
        events.iter().rev().take(limit).cloned().collect()
    }

    /// Clear all events (useful for testing)
    pub fn clear(&self) {
        self.events.write().clear();
        *self.stats.write() = DecisionStats::default();
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
}
