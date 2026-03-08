//! Delegation endpoint handler for chain delegation.
//!
//! Implements `POST /v1/delegate` for creating derived mandates with
//! scope validation, depth limits, and TTL capping.

use axum::{
    extract::{Json, State},
    http::StatusCode,
    response::IntoResponse,
};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{info, warn};

use crate::mandate::LocalMandateSigner;
use crate::models::{
    ActionRequest, ActionSpec, DelegateError, DelegateRequest, DelegateResponse, PrincipalRef,
    SignedMandate, StateEvidence, VerificationEvidence,
};
use crate::policy::subset::{is_scope_subset, is_scope_subset_of_any};

/// Unified delegate result that serializes directly without Ok/Err wrapper.
/// This enum uses untagged serialization so success returns DelegateResponse fields
/// directly and error returns DelegateError fields directly.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(untagged)]
pub enum DelegateResult {
    Success(DelegateResponse),
    Error(DelegateError),
}

/// Default maximum delegation depth if not specified in policy
const DEFAULT_MAX_DELEGATION_DEPTH: u32 = 5;

/// Delegation handler state
#[derive(Clone)]
pub struct DelegationState {
    /// Mandate signer for issuing derived mandates
    pub mandate_signer: Arc<LocalMandateSigner>,
    /// Maximum delegation depth (from policy)
    pub max_delegation_depth: u32,
    /// Set of revoked mandate IDs (for O(1) revocation checks)
    pub revoked_mandate_ids: Arc<parking_lot::RwLock<std::collections::HashSet<String>>>,
}

impl DelegationState {
    pub fn new(mandate_signer: LocalMandateSigner) -> Self {
        Self {
            mandate_signer: Arc::new(mandate_signer),
            max_delegation_depth: DEFAULT_MAX_DELEGATION_DEPTH,
            revoked_mandate_ids: Arc::new(parking_lot::RwLock::new(
                std::collections::HashSet::new(),
            )),
        }
    }

    pub fn with_max_depth(mut self, max_depth: u32) -> Self {
        self.max_delegation_depth = max_depth;
        self
    }

    /// Check if a mandate ID has been revoked
    pub fn is_mandate_revoked(&self, mandate_id: &str) -> bool {
        self.revoked_mandate_ids.read().contains(mandate_id)
    }

    /// Add a mandate ID to the revocation set
    pub fn revoke_mandate(&self, mandate_id: &str) {
        self.revoked_mandate_ids
            .write()
            .insert(mandate_id.to_string());
    }

    /// Update the revocation set with a batch of mandate IDs
    pub fn update_revoked_mandates(&self, mandate_ids: &[String]) {
        let mut set = self.revoked_mandate_ids.write();
        for id in mandate_ids {
            set.insert(id.clone());
        }
    }

    /// Clear the revocation set (for sync refresh)
    pub fn clear_revoked_mandates(&self) {
        self.revoked_mandate_ids.write().clear();
    }
}

/// Handle delegation request.
///
/// # Flow
/// 1. Validate parent mandate (signature, expiration)
/// 2. Check parent mandate not revoked
/// 3. Validate scope subset (requested ⊆ parent)
/// 4. Validate delegation depth limit
/// 5. Cap TTL to parent's remaining TTL
/// 6. Issue derived mandate
/// 7. Record audit event
pub async fn delegate_handler(
    State(state): State<DelegationState>,
    Json(request): Json<DelegateRequest>,
) -> impl IntoResponse {
    // 1. Validate parent mandate
    let parent_mandate = match state.mandate_signer.verify(&request.parent_mandate_token) {
        Some(mandate) => mandate,
        None => {
            warn!(
                target_agent = %request.target_agent_id,
                "Delegation failed: invalid parent mandate"
            );
            return (
                StatusCode::UNAUTHORIZED,
                Json(DelegateResult::Error(
                    DelegateError::invalid_parent_mandate("signature verification failed"),
                )),
            );
        }
    };

    let parent_claims = &parent_mandate.claims;

    // 2. Check if parent mandate is revoked
    if state.is_mandate_revoked(&parent_claims.mandate_id) {
        warn!(
            parent_mandate_id = %parent_claims.mandate_id,
            target_agent = %request.target_agent_id,
            "Delegation failed: parent mandate revoked"
        );
        return (
            StatusCode::FORBIDDEN,
            Json(DelegateResult::Error(DelegateError::parent_revoked())),
        );
    }

    // Check if parent has expired
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    if parent_claims.expires_at_epoch_s < now {
        warn!(
            parent_mandate_id = %parent_claims.mandate_id,
            expires_at = %parent_claims.expires_at_epoch_s,
            now = %now,
            "Delegation failed: parent mandate expired"
        );
        return (
            StatusCode::UNAUTHORIZED,
            Json(DelegateResult::Error(DelegateError::parent_expired())),
        );
    }

    // 3. Validate scope subset
    // For multi-scope parents, check if requested scope is subset of ANY parent scope (OR semantics)
    let parent_scopes = parent_claims.all_scopes();
    let scope_valid = if parent_claims.is_multi_scope() {
        // Multi-scope parent: child scope must match at least one parent scope
        is_scope_subset_of_any(
            &parent_scopes,
            &request.requested_action,
            &request.requested_resource,
        )
    } else {
        // Single-scope parent: use original validation
        is_scope_subset(
            &parent_claims.action,
            &parent_claims.resource,
            &request.requested_action,
            &request.requested_resource,
        )
    };

    if !scope_valid {
        warn!(
            parent_scopes = ?parent_scopes,
            requested_action = %request.requested_action,
            requested_resource = %request.requested_resource,
            "Delegation failed: scope exceeds parent"
        );
        // For error message, show all parent scopes if multi-scope
        let parent_action_display = if parent_claims.is_multi_scope() {
            format!(
                "[{}]",
                parent_scopes
                    .iter()
                    .map(|s| s.action.clone())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        } else {
            parent_claims.action.clone()
        };
        let parent_resource_display = if parent_claims.is_multi_scope() {
            format!(
                "[{}]",
                parent_scopes
                    .iter()
                    .map(|s| s.resource.clone())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        } else {
            parent_claims.resource.clone()
        };

        return (
            StatusCode::FORBIDDEN,
            Json(DelegateResult::Error(DelegateError::scope_exceeded(
                &parent_action_display,
                &parent_resource_display,
                &request.requested_action,
                &request.requested_resource,
            ))),
        );
    }

    // 4. Validate delegation depth
    let new_depth = parent_claims.delegation_depth + 1;
    if new_depth > state.max_delegation_depth {
        warn!(
            current_depth = %parent_claims.delegation_depth,
            max_depth = %state.max_delegation_depth,
            "Delegation failed: max depth exceeded"
        );
        return (
            StatusCode::FORBIDDEN,
            Json(DelegateResult::Error(DelegateError::max_depth_exceeded(
                parent_claims.delegation_depth,
                state.max_delegation_depth,
            ))),
        );
    }

    // 5. Cap TTL to parent's remaining TTL
    let parent_remaining_ttl = (parent_claims.expires_at_epoch_s - now).max(0) as u64;
    let requested_ttl = request.ttl_seconds.unwrap_or(parent_remaining_ttl);
    let capped_ttl = requested_ttl.min(parent_remaining_ttl);

    // 6. Issue derived mandate
    let action_request = ActionRequest {
        principal: PrincipalRef::new(&request.target_agent_id),
        action_spec: ActionSpec {
            action: request.requested_action.clone(),
            resource: request.requested_resource.clone(),
            intent: request.intent_hash.clone(),
            scopes: Vec::new(), // Derived mandates are single-scope
        },
        state_evidence: StateEvidence::new("delegation", &request.intent_hash),
        verification_evidence: VerificationEvidence {
            schema_version: "v1".to_string(),
            signals: vec![],
            verified: true,
        },
    };

    // Create a temporary signer with the capped TTL
    // Note: In production, you'd want to pass TTL to the issue method directly
    let derived_mandate = issue_derived_mandate(
        &state.mandate_signer,
        &action_request,
        &parent_mandate,
        capped_ttl,
    );

    info!(
        parent_mandate_id = %parent_claims.mandate_id,
        derived_mandate_id = %derived_mandate.claims.mandate_id,
        target_agent = %request.target_agent_id,
        delegation_depth = %derived_mandate.claims.delegation_depth,
        "Delegation successful"
    );

    let response = DelegateResponse {
        mandate_token: derived_mandate.token.clone(),
        mandate_id: derived_mandate.claims.mandate_id.clone(),
        expires_at: derived_mandate.claims.expires_at_epoch_s as u64,
        delegation_depth: derived_mandate.claims.delegation_depth,
        delegation_chain_hash: derived_mandate
            .claims
            .delegation_chain_hash
            .clone()
            .unwrap_or_default(),
    };

    (StatusCode::OK, Json(DelegateResult::Success(response)))
}

/// Issue a derived mandate with custom TTL.
///
/// This wraps the mandate signer's issue method but allows overriding the TTL.
fn issue_derived_mandate(
    signer: &LocalMandateSigner,
    request: &ActionRequest,
    parent_mandate: &SignedMandate,
    ttl_seconds: u64,
) -> SignedMandate {
    // Use the existing issue method which handles all delegation logic
    let mut mandate = signer.issue(request, Some(parent_mandate));

    // Adjust the expiration if needed (TTL capping)
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    let capped_expires = now + ttl_seconds as i64;
    if capped_expires < mandate.claims.expires_at_epoch_s {
        mandate.claims.expires_at_epoch_s = capped_expires;
        mandate.claims.exp = Some(capped_expires);
    }

    mandate
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mandate::SigningAlgorithm;
    use crate::models::DelegateErrorCode;

    fn test_signer() -> LocalMandateSigner {
        LocalMandateSigner::new(
            "test-delegation-secret",
            300,
            SigningAlgorithm::ES256,
            true,
            None,
            None,
        )
    }

    fn test_delegation_state() -> DelegationState {
        DelegationState::new(test_signer()).with_max_depth(3)
    }

    fn create_root_mandate(signer: &LocalMandateSigner) -> SignedMandate {
        let request = ActionRequest {
            principal: PrincipalRef::new("agent:root"),
            action_spec: ActionSpec {
                action: "browser.*".to_string(),
                resource: "https://*".to_string(),
                intent: "root task".to_string(),
                scopes: Vec::new(), // Single-scope mandate
            },
            state_evidence: StateEvidence::new("test", "state123"),
            verification_evidence: VerificationEvidence::default(),
        };
        signer.issue(&request, None)
    }

    #[test]
    fn test_delegation_state_creation() {
        let state = test_delegation_state();
        assert_eq!(state.max_delegation_depth, 3);
        assert!(!state.is_mandate_revoked("m_nonexistent"));
    }

    #[test]
    fn test_mandate_revocation() {
        let state = test_delegation_state();

        state.revoke_mandate("m_abc123");
        assert!(state.is_mandate_revoked("m_abc123"));
        assert!(!state.is_mandate_revoked("m_other"));

        state.update_revoked_mandates(&["m_def456".to_string(), "m_ghi789".to_string()]);
        assert!(state.is_mandate_revoked("m_def456"));
        assert!(state.is_mandate_revoked("m_ghi789"));

        state.clear_revoked_mandates();
        assert!(!state.is_mandate_revoked("m_abc123"));
    }

    #[test]
    fn test_issue_derived_mandate() {
        let signer = test_signer();
        let root = create_root_mandate(&signer);

        let child_request = ActionRequest {
            principal: PrincipalRef::new("agent:child"),
            action_spec: ActionSpec {
                action: "browser.click".to_string(),
                resource: "https://example.com".to_string(),
                intent: "click button".to_string(),
                scopes: Vec::new(),
            },
            state_evidence: StateEvidence::new("test", "child_state"),
            verification_evidence: VerificationEvidence::default(),
        };

        let derived = issue_derived_mandate(&signer, &child_request, &root, 60);

        assert_eq!(derived.claims.principal_id, "agent:child");
        assert_eq!(derived.claims.action, "browser.click");
        assert_eq!(derived.claims.delegation_depth, 1);
        assert_eq!(derived.claims.delegated_by, Some("agent:root".to_string()));
        assert_eq!(
            derived.claims.parent_mandate_id,
            Some(root.claims.mandate_id.clone())
        );
    }

    #[test]
    fn test_derived_mandate_ttl_capping() {
        let signer = test_signer();
        let root = create_root_mandate(&signer);

        let child_request = ActionRequest {
            principal: PrincipalRef::new("agent:child"),
            action_spec: ActionSpec {
                action: "browser.click".to_string(),
                resource: "https://example.com".to_string(),
                intent: "click".to_string(),
                scopes: Vec::new(),
            },
            state_evidence: StateEvidence::new("test", "state"),
            verification_evidence: VerificationEvidence::default(),
        };

        // Request very short TTL
        let derived_short = issue_derived_mandate(&signer, &child_request, &root, 10);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        // Should expire in roughly 10 seconds (with small margin for test execution)
        assert!(derived_short.claims.expires_at_epoch_s <= now + 15);
        assert!(derived_short.claims.expires_at_epoch_s >= now + 5);
    }

    #[test]
    fn test_delegation_chain_verification() {
        let signer = test_signer();
        let root = create_root_mandate(&signer);

        let child_request = ActionRequest {
            principal: PrincipalRef::new("agent:child"),
            action_spec: ActionSpec {
                action: "browser.click".to_string(),
                resource: "https://example.com".to_string(),
                intent: "click".to_string(),
                scopes: Vec::new(),
            },
            state_evidence: StateEvidence::new("test", "state"),
            verification_evidence: VerificationEvidence::default(),
        };

        let derived = issue_derived_mandate(&signer, &child_request, &root, 300);

        // Verify the chain
        assert!(signer.verify_delegation(&root, None));
        assert!(signer.verify_delegation(&derived, Some(&root)));
    }

    // --- Multi-scope delegation tests ---

    use crate::models::ScopeSpec;

    fn create_multi_scope_root_mandate(signer: &LocalMandateSigner) -> SignedMandate {
        let request = ActionRequest {
            principal: PrincipalRef::new("agent:orchestrator"),
            action_spec: ActionSpec {
                action: "browser.*".to_string(),
                resource: "https://*".to_string(),
                intent: "orchestrate task".to_string(),
                scopes: vec![
                    ScopeSpec::new("browser.*", "https://*"),
                    ScopeSpec::new("fs.*", "/workspace/**"),
                ],
            },
            state_evidence: StateEvidence::new("test", "state123"),
            verification_evidence: VerificationEvidence::default(),
        };
        signer.issue(&request, None)
    }

    #[test]
    fn test_multi_scope_mandate_issuance() {
        let signer = test_signer();
        let root = create_multi_scope_root_mandate(&signer);

        // Verify the mandate has multiple scopes
        assert!(root.claims.is_multi_scope());
        assert_eq!(root.claims.scopes.len(), 2);
        assert_eq!(root.claims.scopes[0].action, "browser.*");
        assert_eq!(root.claims.scopes[1].action, "fs.*");
    }

    #[test]
    fn test_multi_scope_delegation_browser_scope() {
        let signer = test_signer();
        let root = create_multi_scope_root_mandate(&signer);

        // Child requests browser scope - should succeed
        let child_request = ActionRequest {
            principal: PrincipalRef::new("agent:scraper"),
            action_spec: ActionSpec {
                action: "browser.navigate".to_string(),
                resource: "https://amazon.com/products".to_string(),
                intent: "scrape products".to_string(),
                scopes: Vec::new(),
            },
            state_evidence: StateEvidence::new("test", "child_state"),
            verification_evidence: VerificationEvidence::default(),
        };

        // Verify scope subset check passes
        let parent_scopes = root.claims.all_scopes();
        assert!(is_scope_subset_of_any(
            &parent_scopes,
            "browser.navigate",
            "https://amazon.com/products"
        ));

        let derived = issue_derived_mandate(&signer, &child_request, &root, 60);
        assert_eq!(derived.claims.principal_id, "agent:scraper");
        assert_eq!(derived.claims.action, "browser.navigate");
        assert_eq!(derived.claims.delegation_depth, 1);
    }

    #[test]
    fn test_multi_scope_delegation_fs_scope() {
        let signer = test_signer();
        let root = create_multi_scope_root_mandate(&signer);

        // Child requests fs scope - should succeed
        let child_request = ActionRequest {
            principal: PrincipalRef::new("agent:analyst"),
            action_spec: ActionSpec {
                action: "fs.write".to_string(),
                resource: "/workspace/data/analysis.json".to_string(),
                intent: "write analysis".to_string(),
                scopes: Vec::new(),
            },
            state_evidence: StateEvidence::new("test", "child_state"),
            verification_evidence: VerificationEvidence::default(),
        };

        // Verify scope subset check passes
        let parent_scopes = root.claims.all_scopes();
        assert!(is_scope_subset_of_any(
            &parent_scopes,
            "fs.write",
            "/workspace/data/analysis.json"
        ));

        let derived = issue_derived_mandate(&signer, &child_request, &root, 60);
        assert_eq!(derived.claims.principal_id, "agent:analyst");
        assert_eq!(derived.claims.action, "fs.write");
    }

    #[test]
    fn test_multi_scope_delegation_denied_for_unmatched_scope() {
        let signer = test_signer();
        let root = create_multi_scope_root_mandate(&signer);

        // Child requests network scope - should fail (not in parent's scopes)
        let parent_scopes = root.claims.all_scopes();
        assert!(!is_scope_subset_of_any(
            &parent_scopes,
            "network.connect",
            "tcp://internal:3306"
        ));
    }

    // --- DelegateResult serialization tests ---

    #[test]
    fn test_delegate_result_success_serialization() {
        // Test that DelegateResult::Success serializes without Ok wrapper
        let response = DelegateResponse {
            mandate_token: "eyJhbGci...".to_string(),
            mandate_id: "m_abc123".to_string(),
            expires_at: 1700000000,
            delegation_depth: 1,
            delegation_chain_hash: "hash123".to_string(),
        };

        let result = DelegateResult::Success(response);
        let json = serde_json::to_string(&result).unwrap();

        // Should NOT have "Ok" or "Success" wrapper
        assert!(!json.contains("\"Ok\""));
        assert!(!json.contains("\"Success\""));
        // Should have the response fields directly
        assert!(json.contains("\"mandate_token\""));
        assert!(json.contains("\"mandate_id\""));
        assert!(json.contains("\"m_abc123\""));

        // Verify it can be parsed as DelegateResponse
        let parsed: DelegateResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.mandate_id, "m_abc123");
    }

    #[test]
    fn test_delegate_result_error_serialization() {
        // Test that DelegateResult::Error serializes without Err wrapper
        let error = DelegateError::scope_exceeded("browser.*", "*", "fs.*", "*");
        let result = DelegateResult::Error(error);
        let json = serde_json::to_string(&result).unwrap();

        // Should NOT have "Err" or "Error" wrapper
        assert!(!json.contains("\"Err\""));
        assert!(!json.contains("\"Error\""));
        // Should have the error fields directly
        assert!(json.contains("\"code\""));
        assert!(json.contains("\"message\""));
        assert!(json.contains("DELEGATION_EXCEEDS_SCOPE"));

        // Verify it can be parsed as DelegateError
        let parsed: DelegateError = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.code, DelegateErrorCode::DelegationExceedsScope);
    }
}
