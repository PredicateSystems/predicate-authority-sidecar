//! Policy engine for evaluating authorization requests against rules.
//!
//! Uses glob-style pattern matching for principals, actions, and resources.
//!

#![allow(dead_code)]

use glob::Pattern;
use parking_lot::RwLock;
use std::sync::Arc;

use crate::models::{
    AuthorizationDecision, AuthorizationReason, PolicyEffect, PolicyRule, SidecarAuthorizeRequest,
};

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
}

impl PolicyEngine {
    /// Create a new policy engine with empty rules
    pub fn new() -> Self {
        Self {
            rules: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Create a policy engine with initial rules
    pub fn with_rules(rules: Vec<PolicyRule>) -> Self {
        Self {
            rules: Arc::new(RwLock::new(rules)),
        }
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
        let rules = self.rules.read();

        // Find all matching rules
        let matching_rules: Vec<&PolicyRule> = rules
            .iter()
            .filter(|rule| self.matches_rule(rule, request))
            .collect();

        if matching_rules.is_empty() {
            return PolicyMatchResult {
                allowed: false,
                reason: AuthorizationReason::NoMatchingPolicy,
                matched_rule: None,
                missing_labels: vec![],
            };
        }

        // Check for explicit DENY first (fail-fast)
        for rule in &matching_rules {
            if rule.effect == PolicyEffect::Deny {
                return PolicyMatchResult {
                    allowed: false,
                    reason: AuthorizationReason::ExplicitDeny,
                    matched_rule: Some(rule.name.clone()),
                    missing_labels: vec![],
                };
            }
        }

        // Check ALLOW rules
        for rule in &matching_rules {
            if rule.effect == PolicyEffect::Allow {
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

        // No ALLOW rule matched (shouldn't reach here if rules exist)
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
    fn test_deny_rule_takes_precedence() {
        let engine = PolicyEngine::with_rules(vec![
            sample_allow_rule(),
            PolicyRule {
                name: "deny-checkout".to_string(),
                effect: PolicyEffect::Deny,
                principals: vec!["*".to_string()],
                actions: vec!["browser.*".to_string()],
                resources: vec!["*checkout*".to_string()],
                required_labels: vec![],
                max_delegation_depth: None,
            },
        ]);

        let result = engine.evaluate(&sample_request());

        assert!(!result.allowed);
        assert_eq!(result.reason, AuthorizationReason::ExplicitDeny);
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
}
