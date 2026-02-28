//! Delegation request and response models for chain delegation.
//!
//! These models support the `POST /v1/delegate` endpoint for creating
//! derived mandates with scope validation and depth limits.

use serde::{Deserialize, Serialize};

/// Request to delegate authority from a parent mandate to a child agent.
///
/// The parent agent presents its mandate token, and the sidecar issues
/// a derived mandate with the requested (narrower) scope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegateRequest {
    /// The parent's mandate JWT token
    pub parent_mandate_token: String,

    /// The target agent ID that will receive the derived mandate
    pub target_agent_id: String,

    /// The action scope requested for the child mandate
    /// Must be a subset of the parent's action scope
    pub requested_action: String,

    /// The resource scope requested for the child mandate
    /// Must be a subset of the parent's resource scope
    pub requested_resource: String,

    /// Hash of the intent/purpose for this delegation
    pub intent_hash: String,

    /// Optional TTL in seconds (will be capped to parent's remaining TTL)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl_seconds: Option<u64>,
}

/// Successful delegation response containing the derived mandate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegateResponse {
    /// The derived mandate JWT token
    pub mandate_token: String,

    /// The unique ID of the derived mandate
    pub mandate_id: String,

    /// Expiration timestamp (epoch seconds)
    pub expires_at: u64,

    /// The delegation depth of the derived mandate
    pub delegation_depth: u32,

    /// Hash of the delegation chain for verification
    pub delegation_chain_hash: String,
}

/// Error codes for delegation failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DelegateErrorCode {
    /// Parent token signature verification failed
    InvalidParentMandate,

    /// Parent mandate TTL has expired
    ParentMandateExpired,

    /// Parent mandate is in the revocation set
    ParentMandateRevoked,

    /// Requested scope exceeds parent's scope
    DelegationExceedsScope,

    /// Delegation chain would exceed maximum depth
    MaxDelegationDepthExceeded,

    /// Internal error during mandate signing
    SigningFailed,
}

impl std::fmt::Display for DelegateErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidParentMandate => write!(f, "INVALID_PARENT_MANDATE"),
            Self::ParentMandateExpired => write!(f, "PARENT_MANDATE_EXPIRED"),
            Self::ParentMandateRevoked => write!(f, "PARENT_MANDATE_REVOKED"),
            Self::DelegationExceedsScope => write!(f, "DELEGATION_EXCEEDS_SCOPE"),
            Self::MaxDelegationDepthExceeded => write!(f, "MAX_DELEGATION_DEPTH_EXCEEDED"),
            Self::SigningFailed => write!(f, "SIGNING_FAILED"),
        }
    }
}

/// Delegation error response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegateError {
    /// Error code
    pub code: DelegateErrorCode,

    /// Human-readable error message
    pub message: String,
}

impl DelegateError {
    pub fn new(code: DelegateErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    pub fn invalid_parent_mandate(detail: impl Into<String>) -> Self {
        Self::new(
            DelegateErrorCode::InvalidParentMandate,
            format!("Parent mandate validation failed: {}", detail.into()),
        )
    }

    pub fn parent_expired() -> Self {
        Self::new(
            DelegateErrorCode::ParentMandateExpired,
            "Parent mandate has expired",
        )
    }

    pub fn parent_revoked() -> Self {
        Self::new(
            DelegateErrorCode::ParentMandateRevoked,
            "Parent mandate has been revoked",
        )
    }

    pub fn scope_exceeded(
        parent_action: &str,
        parent_resource: &str,
        requested_action: &str,
        requested_resource: &str,
    ) -> Self {
        Self::new(
            DelegateErrorCode::DelegationExceedsScope,
            format!(
                "Requested scope ({}, {}) exceeds parent scope ({}, {})",
                requested_action, requested_resource, parent_action, parent_resource
            ),
        )
    }

    pub fn max_depth_exceeded(current_depth: u32, max_depth: u32) -> Self {
        Self::new(
            DelegateErrorCode::MaxDelegationDepthExceeded,
            format!(
                "Current delegation depth {} would exceed maximum depth {}",
                current_depth + 1,
                max_depth
            ),
        )
    }

    pub fn signing_failed(detail: impl Into<String>) -> Self {
        Self::new(
            DelegateErrorCode::SigningFailed,
            format!("Failed to sign derived mandate: {}", detail.into()),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_delegate_request_serialization() {
        let request = DelegateRequest {
            parent_mandate_token: "eyJhbGci...".to_string(),
            target_agent_id: "agent:worker".to_string(),
            requested_action: "browser.click".to_string(),
            requested_resource: "button#submit".to_string(),
            intent_hash: "abc123".to_string(),
            ttl_seconds: Some(300),
        };

        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("parent_mandate_token"));
        assert!(json.contains("target_agent_id"));

        let parsed: DelegateRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.target_agent_id, "agent:worker");
        assert_eq!(parsed.ttl_seconds, Some(300));
    }

    #[test]
    fn test_delegate_response_serialization() {
        let response = DelegateResponse {
            mandate_token: "eyJhbGci...".to_string(),
            mandate_id: "m_abc123".to_string(),
            expires_at: 1700000000,
            delegation_depth: 1,
            delegation_chain_hash: "hash123".to_string(),
        };

        let json = serde_json::to_string(&response).unwrap();
        let parsed: DelegateResponse = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.mandate_id, "m_abc123");
        assert_eq!(parsed.delegation_depth, 1);
    }

    #[test]
    fn test_delegate_error_codes() {
        let error = DelegateError::scope_exceeded("browser.*", "*", "fs.*", "*");
        assert_eq!(error.code, DelegateErrorCode::DelegationExceedsScope);
        assert!(error.message.contains("exceeds parent scope"));

        let error = DelegateError::max_depth_exceeded(2, 3);
        assert_eq!(error.code, DelegateErrorCode::MaxDelegationDepthExceeded);
        assert!(error.message.contains("depth 3"));
    }

    #[test]
    fn test_error_code_display() {
        assert_eq!(
            DelegateErrorCode::InvalidParentMandate.to_string(),
            "INVALID_PARENT_MANDATE"
        );
        assert_eq!(
            DelegateErrorCode::DelegationExceedsScope.to_string(),
            "DELEGATION_EXCEEDS_SCOPE"
        );
    }
}
