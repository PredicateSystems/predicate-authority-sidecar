//! Policy engine for evaluating authorization requests against rules.
//!
//! Uses glob-style pattern matching for principals, actions, and resources.
//!
//! # SSRF Protection
//!
//! The policy engine can optionally include SSRF protection, which acts as an
//! implicit deny rule for requests targeting internal network resources, cloud
//! metadata endpoints, and other sensitive targets.

#![allow(dead_code)]

pub mod subset;

pub use subset::{is_action_subset, is_resource_subset, is_scope_subset};

use glob::Pattern;
use parking_lot::RwLock;
use std::sync::Arc;

use crate::models::{
    AuthorizationDecision, AuthorizationReason, PolicyEffect, PolicyRule, SidecarAuthorizeRequest,
};
use crate::ssrf::SsrfProtection;

/// Result of matching a request against policy rules
#[derive(Debug, Clone)]
pub struct PolicyMatchResult {
    pub allowed: bool,
    pub reason: AuthorizationReason,
    pub matched_rule: Option<String>,
    pub missing_labels: Vec<String>,
}

/// Thread-safe policy engine
pub struct PolicyEngine {
    rules: Arc<RwLock<Vec<PolicyRule>>>,
    /// Whether the engine is running in audit/dry-run mode (log but don't block)
    audit_mode: Arc<RwLock<bool>>,
    /// SSRF protection (optional, enabled by default)
    ssrf_protection: Arc<RwLock<Option<SsrfProtection>>>,
}

impl PolicyEngine {
    /// Create a new policy engine with empty rules and SSRF protection enabled
    pub fn new() -> Self {
        Self {
            rules: Arc::new(RwLock::new(Vec::new())),
            audit_mode: Arc::new(RwLock::new(false)),
            ssrf_protection: Arc::new(RwLock::new(Some(SsrfProtection::default()))),
        }
    }

    /// Create a policy engine with initial rules and SSRF protection enabled
    pub fn with_rules(rules: Vec<PolicyRule>) -> Self {
        Self {
            rules: Arc::new(RwLock::new(rules)),
            audit_mode: Arc::new(RwLock::new(false)),
            ssrf_protection: Arc::new(RwLock::new(Some(SsrfProtection::default()))),
        }
    }

    /// Enable or disable SSRF protection
    pub fn set_ssrf_protection(&self, protection: Option<SsrfProtection>) {
        *self.ssrf_protection.write() = protection;
    }

    /// Check if SSRF protection is enabled
    pub fn has_ssrf_protection(&self) -> bool {
        self.ssrf_protection.read().is_some()
    }

    /// Enable or disable audit mode
    pub fn set_audit_mode(&self, enabled: bool) {
        *self.audit_mode.write() = enabled;
    }

    /// Check if audit mode is enabled
    pub fn is_audit_mode(&self) -> bool {
        *self.audit_mode.read()
    }

    /// Replace all rules (thread-safe)
    pub fn replace_rules(&self, rules: Vec<PolicyRule>) {
        let mut guard = self.rules.write();
        *guard = rules;
    }

    /// Get current rule count
    pub fn rule_count(&self) -> usize {
        self.rules.read().len()
    }

    /// Evaluate a request against the policy rules
    pub fn evaluate(&self, request: &SidecarAuthorizeRequest) -> PolicyMatchResult {
        self.evaluate_with_labels(request, &request.labels)
    }

    /// Evaluate with explicit verification labels
    pub fn evaluate_with_labels(
        &self,
        request: &SidecarAuthorizeRequest,
        passed_labels: &[String],
    ) -> PolicyMatchResult {
        // Check SSRF protection first (implicit deny)
        if let Some(ref ssrf) = *self.ssrf_protection.read() {
            if let Some(reason) = ssrf.check_resource(&request.resource) {
                return PolicyMatchResult {
                    allowed: false,
                    reason: AuthorizationReason::ExplicitDeny,
                    matched_rule: Some(format!("ssrf-protection: {}", reason)),
                    missing_labels: vec![],
                };
            }
        }

        let rules = self.rules.read();

        // First-match-wins evaluation: process rules in order, return on first match.
        // This allows policies to have specific ALLOW rules before a catch-all DENY.
        for rule in rules.iter() {
            if !self.matches_rule(rule, request) {
                continue;
            }

            match rule.effect {
                PolicyEffect::Deny => {
                    return PolicyMatchResult {
                        allowed: false,
                        reason: AuthorizationReason::ExplicitDeny,
                        matched_rule: Some(rule.name.clone()),
                        missing_labels: vec![],
                    };
                }
                PolicyEffect::Allow => {
                    // Check required verification labels
                    let missing: Vec<String> = rule
                        .required_labels
                        .iter()
                        .filter(|label| !passed_labels.contains(label))
                        .cloned()
                        .collect();

                    if !missing.is_empty() {
                        return PolicyMatchResult {
                            allowed: false,
                            reason: AuthorizationReason::MissingRequiredVerification,
                            matched_rule: Some(rule.name.clone()),
                            missing_labels: missing,
                        };
                    }

                    // All checks passed
                    return PolicyMatchResult {
                        allowed: true,
                        reason: AuthorizationReason::Allowed,
                        matched_rule: Some(rule.name.clone()),
                        missing_labels: vec![],
                    };
                }
            }
        }

        // No rule matched - implicit deny
        PolicyMatchResult {
            allowed: false,
            reason: AuthorizationReason::NoMatchingPolicy,
            matched_rule: None,
            missing_labels: vec![],
        }
    }

    /// Check if a rule matches the request
    fn matches_rule(&self, rule: &PolicyRule, request: &SidecarAuthorizeRequest) -> bool {
        let principal_matches = rule
            .principals
            .iter()
            .any(|p| matches_pattern(p, &request.principal));

        let action_matches = rule
            .actions
            .iter()
            .any(|a| matches_pattern(a, &request.action));

        let resource_matches = rule
            .resources
            .iter()
            .any(|r| matches_pattern(r, &request.resource));

        principal_matches && action_matches && resource_matches
    }
}

impl Default for PolicyEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Match a glob pattern against a value
fn matches_pattern(pattern: &str, value: &str) -> bool {
    // Handle wildcard shorthand
    if pattern == "*" {
        return true;
    }

    // Use glob pattern matching
    Pattern::new(pattern)
        .map(|p| p.matches(value))
        .unwrap_or(false)
}

/// Convert PolicyMatchResult to AuthorizationDecision
impl From<PolicyMatchResult> for AuthorizationDecision {
    fn from(result: PolicyMatchResult) -> Self {
        Self {
            allowed: result.allowed,
            reason: result.reason,
            mandate: None, // Mandate is added by the guard layer
            violated_rule: if !result.allowed {
                result.matched_rule
            } else {
                None
            },
            missing_labels: result.missing_labels,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_allow_rule() -> PolicyRule {
        PolicyRule {
            name: "allow-browser-actions".to_string(),
            effect: PolicyEffect::Allow,
            principals: vec!["agent:*".to_string()],
            actions: vec!["browser.*".to_string()],
            resources: vec!["https://*".to_string()],
            required_labels: vec![],
            max_delegation_depth: None,
        }
    }

    fn sample_deny_rule() -> PolicyRule {
        PolicyRule {
            name: "deny-admin-actions".to_string(),
            effect: PolicyEffect::Deny,
            principals: vec!["*".to_string()],
            actions: vec!["admin.*".to_string()],
            resources: vec!["*".to_string()],
            required_labels: vec![],
            max_delegation_depth: None,
        }
    }

    fn sample_request() -> SidecarAuthorizeRequest {
        SidecarAuthorizeRequest {
            principal: "agent:web-checkout".to_string(),
            action: "browser.click".to_string(),
            resource: "https://example.com/checkout".to_string(),
            intent_hash: None,
            context: serde_json::Value::Null,
            labels: vec![],
        }
    }

    #[test]
    fn test_no_rules_returns_no_matching_policy() {
        let engine = PolicyEngine::new();
        let result = engine.evaluate(&sample_request());

        assert!(!result.allowed);
        assert_eq!(result.reason, AuthorizationReason::NoMatchingPolicy);
    }

    #[test]
    fn test_allow_rule_matches() {
        let engine = PolicyEngine::with_rules(vec![sample_allow_rule()]);
        let result = engine.evaluate(&sample_request());

        assert!(result.allowed);
        assert_eq!(result.reason, AuthorizationReason::Allowed);
        assert_eq!(
            result.matched_rule,
            Some("allow-browser-actions".to_string())
        );
    }

    #[test]
    #[test]
    fn test_first_match_wins_deny() {
        // With first-match-wins, place DENY rules before ALLOW rules for deny-overrides behavior
        let engine = PolicyEngine::with_rules(vec![
            PolicyRule {
                name: "deny-checkout".to_string(),
                effect: PolicyEffect::Deny,
                principals: vec!["*".to_string()],
                actions: vec!["browser.*".to_string()],
                resources: vec!["*checkout*".to_string()],
                required_labels: vec![],
                max_delegation_depth: None,
            },
            sample_allow_rule(),
        ]);

        let result = engine.evaluate(&sample_request());

        assert!(!result.allowed);
        assert_eq!(result.reason, AuthorizationReason::ExplicitDeny);
    }

    #[test]
    fn test_first_match_wins_allow() {
        // When ALLOW rule comes first and matches, it takes precedence
        let engine = PolicyEngine::with_rules(vec![
            sample_allow_rule(),
            PolicyRule {
                name: "deny-all".to_string(),
                effect: PolicyEffect::Deny,
                principals: vec!["*".to_string()],
                actions: vec!["*".to_string()],
                resources: vec!["*".to_string()],
                required_labels: vec![],
                max_delegation_depth: None,
            },
        ]);

        let result = engine.evaluate(&sample_request());

        assert!(result.allowed);
        assert_eq!(result.reason, AuthorizationReason::Allowed);
    }

    #[test]
    fn test_missing_required_labels() {
        let rule = PolicyRule {
            name: "allow-with-mfa".to_string(),
            effect: PolicyEffect::Allow,
            principals: vec!["agent:*".to_string()],
            actions: vec!["browser.*".to_string()],
            resources: vec!["https://*".to_string()],
            required_labels: vec!["mfa_verified".to_string()],
            max_delegation_depth: None,
        };

        let engine = PolicyEngine::with_rules(vec![rule]);
        let result = engine.evaluate(&sample_request());

        assert!(!result.allowed);
        assert_eq!(
            result.reason,
            AuthorizationReason::MissingRequiredVerification
        );
        assert_eq!(result.missing_labels, vec!["mfa_verified".to_string()]);
    }

    #[test]
    fn test_labels_satisfy_requirements() {
        let rule = PolicyRule {
            name: "allow-with-mfa".to_string(),
            effect: PolicyEffect::Allow,
            principals: vec!["agent:*".to_string()],
            actions: vec!["browser.*".to_string()],
            resources: vec!["https://*".to_string()],
            required_labels: vec!["mfa_verified".to_string()],
            max_delegation_depth: None,
        };

        let engine = PolicyEngine::with_rules(vec![rule]);
        let mut request = sample_request();
        request.labels = vec!["mfa_verified".to_string()];

        let result = engine.evaluate(&request);

        assert!(result.allowed);
        assert_eq!(result.reason, AuthorizationReason::Allowed);
    }

    #[test]
    fn test_pattern_matching() {
        assert!(matches_pattern("*", "anything"));
        assert!(matches_pattern("agent:*", "agent:web"));
        assert!(matches_pattern("browser.*", "browser.click"));
        assert!(matches_pattern("https://*", "https://example.com"));
        assert!(!matches_pattern("agent:*", "user:alice"));
        assert!(!matches_pattern("browser.*", "filesystem.read"));
    }

    #[test]
    fn test_thread_safe_rule_replacement() {
        let engine = PolicyEngine::new();
        assert_eq!(engine.rule_count(), 0);

        engine.replace_rules(vec![sample_allow_rule()]);
        assert_eq!(engine.rule_count(), 1);

        engine.replace_rules(vec![sample_allow_rule(), sample_deny_rule()]);
        assert_eq!(engine.rule_count(), 2);
    }

    #[test]
    fn test_ssrf_protection_blocks_localhost() {
        let engine = PolicyEngine::with_rules(vec![PolicyRule {
            name: "allow-all".to_string(),
            effect: PolicyEffect::Allow,
            principals: vec!["*".to_string()],
            actions: vec!["*".to_string()],
            resources: vec!["*".to_string()],
            required_labels: vec![],
            max_delegation_depth: None,
        }]);

        let request = SidecarAuthorizeRequest {
            principal: "agent:test".to_string(),
            action: "http.fetch".to_string(),
            resource: "http://127.0.0.1/admin".to_string(),
            intent_hash: None,
            context: serde_json::Value::Null,
            labels: vec![],
        };

        let result = engine.evaluate(&request);
        assert!(!result.allowed);
        assert_eq!(result.reason, AuthorizationReason::ExplicitDeny);
        assert!(result.matched_rule.unwrap().contains("ssrf-protection"));
    }

    #[test]
    fn test_ssrf_protection_blocks_metadata() {
        let engine = PolicyEngine::with_rules(vec![PolicyRule {
            name: "allow-all".to_string(),
            effect: PolicyEffect::Allow,
            principals: vec!["*".to_string()],
            actions: vec!["*".to_string()],
            resources: vec!["*".to_string()],
            required_labels: vec![],
            max_delegation_depth: None,
        }]);

        let request = SidecarAuthorizeRequest {
            principal: "agent:test".to_string(),
            action: "http.fetch".to_string(),
            resource: "http://169.254.169.254/latest/meta-data/".to_string(),
            intent_hash: None,
            context: serde_json::Value::Null,
            labels: vec![],
        };

        let result = engine.evaluate(&request);
        assert!(!result.allowed);
        assert!(result.matched_rule.unwrap().contains("metadata"));
    }

    #[test]
    fn test_ssrf_protection_allows_public() {
        let engine = PolicyEngine::with_rules(vec![PolicyRule {
            name: "allow-all".to_string(),
            effect: PolicyEffect::Allow,
            principals: vec!["*".to_string()],
            actions: vec!["*".to_string()],
            resources: vec!["*".to_string()],
            required_labels: vec![],
            max_delegation_depth: None,
        }]);

        let request = SidecarAuthorizeRequest {
            principal: "agent:test".to_string(),
            action: "http.fetch".to_string(),
            resource: "https://api.example.com/data".to_string(),
            intent_hash: None,
            context: serde_json::Value::Null,
            labels: vec![],
        };

        let result = engine.evaluate(&request);
        assert!(result.allowed);
    }

    #[test]
    fn test_ssrf_protection_can_be_disabled() {
        let engine = PolicyEngine::with_rules(vec![PolicyRule {
            name: "allow-all".to_string(),
            effect: PolicyEffect::Allow,
            principals: vec!["*".to_string()],
            actions: vec!["*".to_string()],
            resources: vec!["*".to_string()],
            required_labels: vec![],
            max_delegation_depth: None,
        }]);

        // Disable SSRF protection
        engine.set_ssrf_protection(None);

        let request = SidecarAuthorizeRequest {
            principal: "agent:test".to_string(),
            action: "http.fetch".to_string(),
            resource: "http://127.0.0.1/admin".to_string(),
            intent_hash: None,
            context: serde_json::Value::Null,
            labels: vec![],
        };

        let result = engine.evaluate(&request);
        assert!(result.allowed); // Would be blocked if SSRF was enabled
    }
}

#[cfg(test)]
mod pattern_tests {
    use super::matches_pattern;

    #[test]
    fn test_agent_colon_star() {
        // This is the critical pattern from policy files
        assert!(
            matches_pattern("agent:*", "agent:test"),
            "agent:* should match agent:test"
        );
        assert!(
            matches_pattern("agent:*", "agent:secureclaw"),
            "agent:* should match agent:secureclaw"
        );
    }

    #[test]
    fn test_star_matches_all() {
        assert!(
            matches_pattern("*", "/src/index.ts"),
            "* should match /src/index.ts"
        );
        assert!(
            matches_pattern("*", "agent:test"),
            "* should match agent:test"
        );
        assert!(matches_pattern("*", "fs.read"), "* should match fs.read");
    }
}
