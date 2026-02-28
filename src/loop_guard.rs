//! Loop Guard: Detection and prevention of infinite loops and retry storms.
//!
//! This module tracks repeated authorization failures to detect when an agent
//! may be stuck in a loop (repeatedly requesting the same action) or when a
//! retry storm is occurring (many rapid failures).
//!
//! # Features
//!
//! - **Repeated Failure Detection**: Tracks failures per (principal, action, resource) tuple
//! - **Configurable Thresholds**: Set max failures before circuit breaker opens
//! - **Time-based Reset**: Failure counts reset after a configurable window
//! - **LRU Eviction**: Old entries are evicted when capacity is exceeded
//!
//! # Usage
//!
//! ```rust,ignore
//! use predicate_authorityd::loop_guard::LoopGuard;
//! use std::time::Duration;
//!
//! let guard = LoopGuard::new(1000, 5, Duration::from_secs(60));
//!
//! // Record a failure
//! guard.record_failure("agent:test", "browser.click", "https://example.com");
//!
//! // Check if the circuit is open (too many failures)
//! if guard.is_blocked("agent:test", "browser.click", "https://example.com") {
//!     println!("Circuit breaker open - too many failures");
//! }
//! ```

use lru::LruCache;
use parking_lot::Mutex;
use std::num::NonZeroUsize;
use std::time::{Duration, Instant};

/// A single failure tracking entry
#[derive(Debug, Clone)]
struct FailureEntry {
    /// Number of failures recorded
    count: u32,
    /// Time of the first failure in this window
    first_failure: Instant,
    /// Time of the most recent failure
    last_failure: Instant,
}

impl FailureEntry {
    fn new() -> Self {
        let now = Instant::now();
        Self {
            count: 1,
            first_failure: now,
            last_failure: now,
        }
    }

    fn increment(&mut self) {
        self.count += 1;
        self.last_failure = Instant::now();
    }

    fn is_expired(&self, window: Duration) -> bool {
        self.first_failure.elapsed() > window
    }
}

/// Loop guard configuration
#[derive(Debug, Clone)]
pub struct LoopGuardConfig {
    /// Maximum number of entries to track (LRU cache capacity)
    pub max_entries: usize,
    /// Number of failures before circuit opens
    pub failure_threshold: u32,
    /// Time window for counting failures
    pub failure_window: Duration,
    /// How long to keep the circuit open after threshold is reached
    pub cooldown_period: Duration,
}

impl Default for LoopGuardConfig {
    fn default() -> Self {
        Self {
            max_entries: 10_000,
            failure_threshold: 5,
            failure_window: Duration::from_secs(60),
            cooldown_period: Duration::from_secs(300), // 5 minutes
        }
    }
}

/// Loop guard that tracks repeated failures and opens circuit breakers
pub struct LoopGuard {
    /// LRU cache of failure entries, keyed by (principal, action, resource) hash
    cache: Mutex<LruCache<String, FailureEntry>>,
    /// Configuration
    config: LoopGuardConfig,
}

impl LoopGuard {
    /// Create a new loop guard with default configuration
    pub fn new() -> Self {
        Self::with_config(LoopGuardConfig::default())
    }

    /// Create a new loop guard with custom configuration
    pub fn with_config(config: LoopGuardConfig) -> Self {
        let capacity =
            NonZeroUsize::new(config.max_entries).unwrap_or(NonZeroUsize::new(1000).unwrap());
        Self {
            cache: Mutex::new(LruCache::new(capacity)),
            config,
        }
    }

    /// Create a loop guard with specific parameters
    pub fn with_params(max_entries: usize, failure_threshold: u32, failure_window: Duration) -> Self {
        Self::with_config(LoopGuardConfig {
            max_entries,
            failure_threshold,
            failure_window,
            cooldown_period: failure_window * 5, // Default cooldown is 5x the window
        })
    }

    /// Record a failure for the given request
    pub fn record_failure(&self, principal: &str, action: &str, resource: &str) {
        let key = Self::make_key(principal, action, resource);
        let mut cache = self.cache.lock();

        if let Some(entry) = cache.get_mut(&key) {
            // Check if the entry has expired
            if entry.is_expired(self.config.failure_window) {
                // Reset the entry
                *entry = FailureEntry::new();
            } else {
                entry.increment();
            }
        } else {
            cache.put(key, FailureEntry::new());
        }
    }

    /// Check if the circuit is open (too many failures) for the given request
    pub fn is_blocked(&self, principal: &str, action: &str, resource: &str) -> bool {
        let key = Self::make_key(principal, action, resource);
        let mut cache = self.cache.lock();

        if let Some(entry) = cache.get_mut(&key) {
            // Check if expired - if so, the circuit is closed
            if entry.is_expired(self.config.failure_window) {
                return false;
            }

            // Check if threshold exceeded
            if entry.count >= self.config.failure_threshold {
                // Check if we're still in the cooldown period
                let cooldown_expired =
                    entry.last_failure.elapsed() > self.config.cooldown_period;
                return !cooldown_expired;
            }
        }

        false
    }

    /// Get the current failure count for a request (0 if not tracked)
    pub fn failure_count(&self, principal: &str, action: &str, resource: &str) -> u32 {
        let key = Self::make_key(principal, action, resource);
        let mut cache = self.cache.lock();

        if let Some(entry) = cache.get(&key) {
            if entry.is_expired(self.config.failure_window) {
                0
            } else {
                entry.count
            }
        } else {
            0
        }
    }

    /// Reset the failure count for a request (called on successful authorization)
    pub fn reset(&self, principal: &str, action: &str, resource: &str) {
        let key = Self::make_key(principal, action, resource);
        let mut cache = self.cache.lock();
        cache.pop(&key);
    }

    /// Get current cache size
    pub fn size(&self) -> usize {
        self.cache.lock().len()
    }

    /// Clear all entries
    pub fn clear(&self) {
        self.cache.lock().clear();
    }

    /// Get statistics about the loop guard
    pub fn stats(&self) -> LoopGuardStats {
        let cache = self.cache.lock();
        let mut blocked_count = 0;
        let mut total_failures = 0;

        for (_, entry) in cache.iter() {
            if !entry.is_expired(self.config.failure_window) {
                total_failures += entry.count;
                if entry.count >= self.config.failure_threshold {
                    blocked_count += 1;
                }
            }
        }

        LoopGuardStats {
            tracked_entries: cache.len(),
            blocked_entries: blocked_count,
            total_failures,
            capacity: self.config.max_entries,
        }
    }

    fn make_key(principal: &str, action: &str, resource: &str) -> String {
        format!("{}|{}|{}", principal, action, resource)
    }
}

impl Default for LoopGuard {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics about the loop guard
#[derive(Debug, Clone, serde::Serialize)]
pub struct LoopGuardStats {
    /// Number of entries currently being tracked
    pub tracked_entries: usize,
    /// Number of entries that are currently blocked
    pub blocked_entries: usize,
    /// Total failures recorded across all entries
    pub total_failures: u32,
    /// Maximum capacity of the cache
    pub capacity: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_and_check_failure() {
        let guard = LoopGuard::with_params(100, 3, Duration::from_secs(60));

        // First two failures should not block
        guard.record_failure("agent:test", "browser.click", "https://example.com");
        assert!(!guard.is_blocked("agent:test", "browser.click", "https://example.com"));
        assert_eq!(
            guard.failure_count("agent:test", "browser.click", "https://example.com"),
            1
        );

        guard.record_failure("agent:test", "browser.click", "https://example.com");
        assert!(!guard.is_blocked("agent:test", "browser.click", "https://example.com"));
        assert_eq!(
            guard.failure_count("agent:test", "browser.click", "https://example.com"),
            2
        );

        // Third failure should trigger block
        guard.record_failure("agent:test", "browser.click", "https://example.com");
        assert!(guard.is_blocked("agent:test", "browser.click", "https://example.com"));
        assert_eq!(
            guard.failure_count("agent:test", "browser.click", "https://example.com"),
            3
        );
    }

    #[test]
    fn test_different_requests_tracked_separately() {
        let guard = LoopGuard::with_params(100, 2, Duration::from_secs(60));

        // Max out one request
        guard.record_failure("agent:a", "action.a", "resource:a");
        guard.record_failure("agent:a", "action.a", "resource:a");
        assert!(guard.is_blocked("agent:a", "action.a", "resource:a"));

        // Different request should not be blocked
        assert!(!guard.is_blocked("agent:a", "action.b", "resource:a"));
        assert!(!guard.is_blocked("agent:b", "action.a", "resource:a"));
    }

    #[test]
    fn test_reset_clears_failures() {
        let guard = LoopGuard::with_params(100, 3, Duration::from_secs(60));

        guard.record_failure("agent:test", "action", "resource");
        guard.record_failure("agent:test", "action", "resource");
        assert_eq!(guard.failure_count("agent:test", "action", "resource"), 2);

        guard.reset("agent:test", "action", "resource");
        assert_eq!(guard.failure_count("agent:test", "action", "resource"), 0);
    }

    #[test]
    fn test_stats() {
        let guard = LoopGuard::with_params(100, 3, Duration::from_secs(60));

        guard.record_failure("agent:a", "action", "resource");
        guard.record_failure("agent:b", "action", "resource");
        guard.record_failure("agent:b", "action", "resource");
        guard.record_failure("agent:b", "action", "resource");

        let stats = guard.stats();
        assert_eq!(stats.tracked_entries, 2);
        assert_eq!(stats.blocked_entries, 1);
        assert_eq!(stats.total_failures, 4);
    }

    #[test]
    fn test_clear() {
        let guard = LoopGuard::new();

        guard.record_failure("agent:test", "action", "resource");
        assert_eq!(guard.size(), 1);

        guard.clear();
        assert_eq!(guard.size(), 0);
    }

    #[test]
    fn test_lru_eviction() {
        let guard = LoopGuard::with_params(2, 3, Duration::from_secs(60));

        guard.record_failure("agent:a", "action", "resource");
        guard.record_failure("agent:b", "action", "resource");
        assert_eq!(guard.size(), 2);

        // Adding a third entry should evict the oldest
        guard.record_failure("agent:c", "action", "resource");
        assert_eq!(guard.size(), 2);

        // The oldest entry (agent:a) should have been evicted
        assert_eq!(guard.failure_count("agent:a", "action", "resource"), 0);
        assert_eq!(guard.failure_count("agent:b", "action", "resource"), 1);
        assert_eq!(guard.failure_count("agent:c", "action", "resource"), 1);
    }

    #[test]
    fn test_expiration() {
        let guard = LoopGuard::with_params(100, 3, Duration::from_millis(50));

        guard.record_failure("agent:test", "action", "resource");
        guard.record_failure("agent:test", "action", "resource");
        assert_eq!(guard.failure_count("agent:test", "action", "resource"), 2);

        // Wait for expiration
        std::thread::sleep(Duration::from_millis(60));

        // Count should be reset due to expiration
        assert_eq!(guard.failure_count("agent:test", "action", "resource"), 0);
        assert!(!guard.is_blocked("agent:test", "action", "resource"));
    }

    #[test]
    fn test_default_config() {
        let config = LoopGuardConfig::default();
        assert_eq!(config.max_entries, 10_000);
        assert_eq!(config.failure_threshold, 5);
        assert_eq!(config.failure_window, Duration::from_secs(60));
        assert_eq!(config.cooldown_period, Duration::from_secs(300));
    }
}
