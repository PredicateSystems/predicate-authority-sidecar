//! Core data models for Predicate Authority.
//!
//! These models mirror `predicate_contracts` from Python for wire compatibility.
//!

#![allow(dead_code)]

pub mod delegation;
pub mod execute;

pub use delegation::{DelegateError, DelegateErrorCode, DelegateRequest, DelegateResponse};
pub use execute::{
    DirectoryEntry, ExecuteErrorCode, ExecutePayload, ExecuteRequest, ExecuteResponse,
    ExecuteResult,
};

use serde::{Deserialize, Serialize};

/// Policy effect: allow or deny
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PolicyEffect {
    Allow,
    Deny,
}

/// Verification signal status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VerificationStatus {
    Passed,
    Failed,
    Skipped,
}

/// Authorization decision reason
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorizationReason {
    Allowed,
    NoMatchingPolicy,
    ExplicitDeny,
    MissingRequiredVerification,
    MaxDelegationDepthExceeded,
    InvalidMandate,
    RateLimitExceeded,
}

impl std::fmt::Display for AuthorizationReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Allowed => write!(f, "allowed"),
            Self::NoMatchingPolicy => write!(f, "no_matching_policy"),
            Self::ExplicitDeny => write!(f, "explicit_deny"),
            Self::MissingRequiredVerification => write!(f, "missing_required_verification"),
            Self::MaxDelegationDepthExceeded => write!(f, "max_delegation_depth_exceeded"),
            Self::InvalidMandate => write!(f, "invalid_mandate"),
            Self::RateLimitExceeded => write!(f, "rate_limit_exceeded"),
        }
    }
}

/// Principal reference
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrincipalRef {
    pub principal_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
}

impl PrincipalRef {
    pub fn new(principal_id: &str) -> Self {
        Self {
            principal_id: principal_id.to_string(),
            tenant_id: None,
            session_id: None,
        }
    }
}

/// A single scope (action + resource pair)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopeSpec {
    pub action: String,
    pub resource: String,
}

impl ScopeSpec {
    pub fn new(action: &str, resource: &str) -> Self {
        Self {
            action: action.to_string(),
            resource: resource.to_string(),
        }
    }
}

/// Action specification - supports single or multiple scopes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionSpec {
    /// Primary action (backward compatible, used when scopes is empty)
    pub action: String,
    /// Primary resource (backward compatible, used when scopes is empty)
    pub resource: String,
    /// Intent description or hash
    pub intent: String,
    /// Multiple scopes for multi-scope mandates (optional)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scopes: Vec<ScopeSpec>,
}

impl ActionSpec {
    /// Create a single-scope ActionSpec (backward compatible)
    pub fn single(action: &str, resource: &str, intent: &str) -> Self {
        Self {
            action: action.to_string(),
            resource: resource.to_string(),
            intent: intent.to_string(),
            scopes: Vec::new(),
        }
    }

    /// Create a multi-scope ActionSpec
    pub fn multi(scopes: Vec<ScopeSpec>, intent: &str) -> Self {
        let (primary_action, primary_resource) = if let Some(first) = scopes.first() {
            (first.action.clone(), first.resource.clone())
        } else {
            (String::new(), String::new())
        };
        Self {
            action: primary_action,
            resource: primary_resource,
            intent: intent.to_string(),
            scopes,
        }
    }

    /// Get all scopes (returns single scope if scopes vec is empty)
    pub fn all_scopes(&self) -> Vec<ScopeSpec> {
        if self.scopes.is_empty() {
            vec![ScopeSpec::new(&self.action, &self.resource)]
        } else {
            self.scopes.clone()
        }
    }

    /// Check if this is a multi-scope ActionSpec
    pub fn is_multi_scope(&self) -> bool {
        !self.scopes.is_empty()
    }
}

/// State evidence for authorization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateEvidence {
    pub source: String,
    pub state_hash: String,
    #[serde(default = "default_schema_version")]
    pub schema_version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence: Option<f64>,
}

impl StateEvidence {
    pub fn new(source: &str, state_hash: &str) -> Self {
        Self {
            source: source.to_string(),
            state_hash: state_hash.to_string(),
            schema_version: default_schema_version(),
            confidence: None,
        }
    }
}

fn default_schema_version() -> String {
    "v1".to_string()
}

/// Single verification signal
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationSignal {
    pub label: String,
    pub status: VerificationStatus,
    #[serde(default = "default_true")]
    pub required: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

fn default_true() -> bool {
    true
}

/// Collection of verification signals
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VerificationEvidence {
    #[serde(default = "default_schema_version")]
    pub schema_version: String,
    #[serde(default)]
    pub signals: Vec<VerificationSignal>,
    #[serde(default = "default_true")]
    pub verified: bool,
}

/// Full action request for authorization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionRequest {
    pub principal: PrincipalRef,
    pub action_spec: ActionSpec,
    pub state_evidence: StateEvidence,
    #[serde(default)]
    pub verification_evidence: VerificationEvidence,
}

/// Policy rule definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    pub name: String,
    pub effect: PolicyEffect,
    pub principals: Vec<String>,
    pub actions: Vec<String>,
    pub resources: Vec<String>,
    #[serde(default)]
    pub required_labels: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_delegation_depth: Option<u32>,
    /// Headers to inject for http.fetch actions.
    /// Values support environment variable substitution: `${VAR_NAME}` or `${VAR:-default}`
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inject_headers: Option<std::collections::HashMap<String, String>>,
    /// Environment variables to inject for cli.exec actions.
    /// Values support environment variable substitution: `${VAR_NAME}` or `${VAR:-default}`
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inject_env: Option<std::collections::HashMap<String, String>>,
}

/// Mandate claims (JWT payload)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MandateClaims {
    pub mandate_id: String,
    pub principal_id: String,
    /// Primary action (backward compatible)
    pub action: String,
    /// Primary resource (backward compatible)
    pub resource: String,
    /// Multiple scopes for multi-scope mandates
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scopes: Vec<ScopeSpec>,
    pub intent_hash: String,
    pub state_hash: String,
    pub issued_at_epoch_s: i64,
    pub expires_at_epoch_s: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delegated_by: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_mandate_id: Option<String>,
    #[serde(default)]
    pub delegation_depth: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delegation_chain_hash: Option<String>,
    // Standard JWT claims
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iat: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nbf: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
}

impl MandateClaims {
    /// Get all scopes (returns single scope if scopes vec is empty)
    pub fn all_scopes(&self) -> Vec<ScopeSpec> {
        if self.scopes.is_empty() {
            vec![ScopeSpec::new(&self.action, &self.resource)]
        } else {
            self.scopes.clone()
        }
    }

    /// Check if this is a multi-scope mandate
    pub fn is_multi_scope(&self) -> bool {
        !self.scopes.is_empty()
    }
}

/// Signed mandate (JWT token + claims)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedMandate {
    pub token: String,
    pub claims: MandateClaims,
    pub signature: String,
}

/// Authorization decision
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationDecision {
    pub allowed: bool,
    pub reason: AuthorizationReason,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mandate: Option<SignedMandate>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub violated_rule: Option<String>,
    #[serde(default)]
    pub missing_labels: Vec<String>,
}

/// Proof event for audit logging
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofEvent {
    pub event_type: String,
    pub principal_id: String,
    pub action: String,
    pub resource: String,
    pub reason: AuthorizationReason,
    pub allowed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mandate_id: Option<String>,
    pub emitted_at_epoch_s: i64,
    /// Authorization latency in microseconds
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latency_us: Option<u64>,
    /// Unique event identifier for this proof event
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_id: Option<String>,
    /// SHA-256 hash chain: H(prev_chain_hash || canonical_event_json)
    /// Creates a tamper-evident audit trail that can be verified by the control plane.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain_hash: Option<String>,
}

// --- Wire format for sidecar HTTP API ---

/// Scope authorization result (for multi-scope responses)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScopeAuthorizationResult {
    pub action: String,
    pub resource: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub matched_rule: Option<String>,
}

/// Sidecar authorize request (simplified wire format)
/// Supports both single-scope (action/resource) and multi-scope (scopes array)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SidecarAuthorizeRequest {
    pub principal: String,
    /// Single action (backward compatible, used when scopes is empty)
    #[serde(default)]
    pub action: String,
    /// Single resource (backward compatible, used when scopes is empty)
    #[serde(default)]
    pub resource: String,
    /// Multiple scopes for multi-scope authorization
    #[serde(default)]
    pub scopes: Vec<ScopeSpec>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub intent_hash: Option<String>,
    #[serde(default)]
    pub context: serde_json::Value,
    #[serde(default)]
    pub labels: Vec<String>,
}

impl SidecarAuthorizeRequest {
    /// Get all scopes from the request (single or multi)
    pub fn all_scopes(&self) -> Vec<ScopeSpec> {
        if !self.scopes.is_empty() {
            self.scopes.clone()
        } else if !self.action.is_empty() {
            vec![ScopeSpec::new(&self.action, &self.resource)]
        } else {
            Vec::new()
        }
    }

    /// Check if this is a multi-scope request
    pub fn is_multi_scope(&self) -> bool {
        !self.scopes.is_empty()
    }

    /// Validate the request has at least one scope
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.scopes.is_empty() && self.action.is_empty() {
            return Err("either 'action' or 'scopes' must be provided");
        }
        Ok(())
    }
}

/// Sidecar authorize response (matches TypeScript SDK expectations)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SidecarAuthorizeResponse {
    pub allowed: bool,
    pub reason: String,
    /// Always serialized (as null or string) for SDK compatibility
    pub mandate_id: Option<String>,
    /// The signed mandate JWT token (for chain delegation)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mandate_token: Option<String>,
    /// Always serialized (as null or string) for SDK compatibility
    pub violated_rule: Option<String>,
    #[serde(default)]
    pub missing_labels: Vec<String>,
    /// Scopes that were authorized (for multi-scope requests)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scopes_authorized: Vec<ScopeAuthorizationResult>,
}

impl From<AuthorizationDecision> for SidecarAuthorizeResponse {
    fn from(decision: AuthorizationDecision) -> Self {
        // Build scopes_authorized from mandate claims if available
        let scopes_authorized = decision
            .mandate
            .as_ref()
            .map(|m| {
                m.claims
                    .all_scopes()
                    .into_iter()
                    .map(|s| ScopeAuthorizationResult {
                        action: s.action,
                        resource: s.resource,
                        matched_rule: decision.violated_rule.clone(), // Reuse for now; will be improved
                    })
                    .collect()
            })
            .unwrap_or_default();

        Self {
            allowed: decision.allowed,
            reason: decision.reason.to_string(),
            mandate_id: decision
                .mandate
                .as_ref()
                .map(|m| m.claims.mandate_id.clone()),
            mandate_token: decision.mandate.map(|m| m.token),
            violated_rule: decision.violated_rule,
            missing_labels: decision.missing_labels,
            scopes_authorized,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_authorization_reason_serialization() {
        let reason = AuthorizationReason::NoMatchingPolicy;
        let json = serde_json::to_string(&reason).unwrap();
        assert_eq!(json, r#""no_matching_policy""#);
    }

    #[test]
    fn test_policy_effect_serialization() {
        let effect = PolicyEffect::Allow;
        let json = serde_json::to_string(&effect).unwrap();
        assert_eq!(json, r#""allow""#);
    }

    #[test]
    fn test_sidecar_request_deserialization() {
        let json = r#"{"principal": "agent:web", "action": "browser.click", "resource": "https://example.com"}"#;
        let req: SidecarAuthorizeRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.principal, "agent:web");
        assert_eq!(req.action, "browser.click");
        assert_eq!(req.resource, "https://example.com");
    }

    // --- Multi-scope tests ---

    #[test]
    fn test_scope_spec_creation() {
        let scope = ScopeSpec::new("browser.click", "https://example.com");
        assert_eq!(scope.action, "browser.click");
        assert_eq!(scope.resource, "https://example.com");
    }

    #[test]
    fn test_action_spec_single_scope() {
        let spec = ActionSpec::single("fs.read", "/src/file.ts", "read file");
        assert_eq!(spec.action, "fs.read");
        assert_eq!(spec.resource, "/src/file.ts");
        assert!(!spec.is_multi_scope());

        let scopes = spec.all_scopes();
        assert_eq!(scopes.len(), 1);
        assert_eq!(scopes[0].action, "fs.read");
    }

    #[test]
    fn test_action_spec_multi_scope() {
        let scopes = vec![
            ScopeSpec::new("browser.*", "https://example.com/*"),
            ScopeSpec::new("fs.*", "/workspace/**"),
        ];
        let spec = ActionSpec::multi(scopes, "orchestrate task");

        assert!(spec.is_multi_scope());
        assert_eq!(spec.action, "browser.*"); // Primary from first scope

        let all_scopes = spec.all_scopes();
        assert_eq!(all_scopes.len(), 2);
        assert_eq!(all_scopes[0].action, "browser.*");
        assert_eq!(all_scopes[1].action, "fs.*");
    }

    #[test]
    fn test_sidecar_request_single_scope() {
        let json = r#"{"principal": "agent:web", "action": "browser.click", "resource": "https://example.com"}"#;
        let req: SidecarAuthorizeRequest = serde_json::from_str(json).unwrap();

        assert!(!req.is_multi_scope());
        assert!(req.validate().is_ok());

        let scopes = req.all_scopes();
        assert_eq!(scopes.len(), 1);
        assert_eq!(scopes[0].action, "browser.click");
    }

    #[test]
    fn test_sidecar_request_multi_scope() {
        let json = r#"{
            "principal": "agent:orchestrator",
            "scopes": [
                {"action": "browser.*", "resource": "https://amazon.com/*"},
                {"action": "fs.*", "resource": "/workspace/**"}
            ],
            "intent_hash": "orchestrate:ecommerce:123"
        }"#;
        let req: SidecarAuthorizeRequest = serde_json::from_str(json).unwrap();

        assert!(req.is_multi_scope());
        assert!(req.validate().is_ok());

        let scopes = req.all_scopes();
        assert_eq!(scopes.len(), 2);
        assert_eq!(scopes[0].action, "browser.*");
        assert_eq!(scopes[1].action, "fs.*");
    }

    #[test]
    fn test_sidecar_request_validation_fails_empty() {
        let json = r#"{"principal": "agent:web"}"#;
        let req: SidecarAuthorizeRequest = serde_json::from_str(json).unwrap();

        assert!(req.validate().is_err());
    }

    #[test]
    fn test_mandate_claims_all_scopes_single() {
        let claims = MandateClaims {
            mandate_id: "m_123".to_string(),
            principal_id: "agent:test".to_string(),
            action: "browser.click".to_string(),
            resource: "https://example.com".to_string(),
            scopes: Vec::new(),
            intent_hash: "hash".to_string(),
            state_hash: "state".to_string(),
            issued_at_epoch_s: 0,
            expires_at_epoch_s: 0,
            delegated_by: None,
            parent_mandate_id: None,
            delegation_depth: 0,
            delegation_chain_hash: None,
            iss: None,
            aud: None,
            sub: None,
            iat: None,
            exp: None,
            nbf: None,
            jti: None,
        };

        assert!(!claims.is_multi_scope());
        let scopes = claims.all_scopes();
        assert_eq!(scopes.len(), 1);
        assert_eq!(scopes[0].action, "browser.click");
    }

    #[test]
    fn test_mandate_claims_all_scopes_multi() {
        let claims = MandateClaims {
            mandate_id: "m_123".to_string(),
            principal_id: "agent:orchestrator".to_string(),
            action: "browser.*".to_string(),
            resource: "https://*".to_string(),
            scopes: vec![
                ScopeSpec::new("browser.*", "https://*"),
                ScopeSpec::new("fs.*", "/workspace/**"),
            ],
            intent_hash: "hash".to_string(),
            state_hash: "state".to_string(),
            issued_at_epoch_s: 0,
            expires_at_epoch_s: 0,
            delegated_by: None,
            parent_mandate_id: None,
            delegation_depth: 0,
            delegation_chain_hash: None,
            iss: None,
            aud: None,
            sub: None,
            iat: None,
            exp: None,
            nbf: None,
            jti: None,
        };

        assert!(claims.is_multi_scope());
        let scopes = claims.all_scopes();
        assert_eq!(scopes.len(), 2);
    }
}
