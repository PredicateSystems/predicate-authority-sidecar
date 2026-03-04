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

/// Action specification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionSpec {
    pub action: String,
    pub resource: String,
    pub intent: String,
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
}

/// Mandate claims (JWT payload)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MandateClaims {
    pub mandate_id: String,
    pub principal_id: String,
    pub action: String,
    pub resource: String,
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

/// Sidecar authorize request (simplified wire format)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SidecarAuthorizeRequest {
    pub principal: String,
    pub action: String,
    pub resource: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub intent_hash: Option<String>,
    #[serde(default)]
    pub context: serde_json::Value,
    #[serde(default)]
    pub labels: Vec<String>,
}

/// Sidecar authorize response (matches TypeScript SDK expectations)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SidecarAuthorizeResponse {
    pub allowed: bool,
    pub reason: String,
    /// Always serialized (as null or string) for SDK compatibility
    pub mandate_id: Option<String>,
    /// Always serialized (as null or string) for SDK compatibility
    pub violated_rule: Option<String>,
    #[serde(default)]
    pub missing_labels: Vec<String>,
}

impl From<AuthorizationDecision> for SidecarAuthorizeResponse {
    fn from(decision: AuthorizationDecision) -> Self {
        Self {
            allowed: decision.allowed,
            reason: decision.reason.to_string(),
            mandate_id: decision.mandate.map(|m| m.claims.mandate_id),
            violated_rule: decision.violated_rule,
            missing_labels: decision.missing_labels,
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
}
