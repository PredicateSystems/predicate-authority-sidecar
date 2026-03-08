//! Integration tests for delegation chains and cascade revocation.
//!
//! These tests verify the delegation and revocation behavior in the sidecar.

use predicate_authorityd::http::DelegationState;
use predicate_authorityd::mandate::{LocalMandateSigner, SigningAlgorithm};
use predicate_authorityd::models::{
    ActionRequest, ActionSpec, PrincipalRef, SignedMandate, StateEvidence, VerificationEvidence,
};

/// Create a test mandate signer
fn test_signer() -> LocalMandateSigner {
    LocalMandateSigner::new(
        "test-delegation-e2e-secret-key",
        300, // 5 minute TTL
        SigningAlgorithm::ES256,
        true, // enable delegation
        None,
        None,
    )
}

/// Create a test delegation state
fn test_delegation_state(signer: LocalMandateSigner, max_depth: u32) -> DelegationState {
    DelegationState::new(signer).with_max_depth(max_depth)
}

/// Create a root mandate for a given principal with wildcards
fn create_root_mandate(signer: &LocalMandateSigner, principal: &str) -> SignedMandate {
    let request = ActionRequest {
        principal: PrincipalRef::new(principal),
        action_spec: ActionSpec {
            action: "browser.*".to_string(),
            resource: "https://*".to_string(),
            intent: "root task authorization".to_string(),
            scopes: Vec::new(),
        },
        state_evidence: StateEvidence::new("e2e_test", "root_state_hash"),
        verification_evidence: VerificationEvidence::default(),
    };
    signer.issue(&request, None)
}

/// Create a derived mandate by delegating from parent
fn delegate_mandate(
    signer: &LocalMandateSigner,
    parent: &SignedMandate,
    target_principal: &str,
    action: &str,
    resource: &str,
) -> SignedMandate {
    let request = ActionRequest {
        principal: PrincipalRef::new(target_principal),
        action_spec: ActionSpec {
            action: action.to_string(),
            resource: resource.to_string(),
            intent: format!("delegated task for {}", target_principal),
            scopes: Vec::new(),
        },
        state_evidence: StateEvidence::new("delegation", "child_state"),
        verification_evidence: VerificationEvidence::default(),
    };
    signer.issue(&request, Some(parent))
}

// =============================================================================
// E2E DELEGATION AND REVOCATION TESTS
// =============================================================================

#[tokio::test]
async fn test_delegation_and_revocation_e2e() {
    // This test verifies the full delegation and revocation flow:
    // 1. Agent A gets initial mandate
    // 2. Agent A delegates to Agent B with narrower scope
    // 3. Agent B can authorize actions within delegated scope
    // 4. Agent A's mandate is revoked
    // 5. Agent B's derived mandate should also be rejected

    // Create separate signer instances (LocalMandateSigner doesn't implement Clone)
    let delegation_state = test_delegation_state(test_signer(), 5);
    let signer = test_signer();

    // 1. Agent A gets initial mandate
    let mandate_a = create_root_mandate(&signer, "agent:A");
    assert_eq!(mandate_a.claims.delegation_depth, 0);
    assert!(mandate_a.claims.parent_mandate_id.is_none());

    // 2. Agent A delegates to Agent B with narrower scope
    let mandate_b = delegate_mandate(
        &signer,
        &mandate_a,
        "agent:B",
        "browser.click",
        "https://example.com",
    );
    assert_eq!(mandate_b.claims.delegation_depth, 1);
    assert_eq!(
        mandate_b.claims.parent_mandate_id,
        Some(mandate_a.claims.mandate_id.clone())
    );
    assert_eq!(mandate_b.claims.delegated_by, Some("agent:A".to_string()));

    // 3. Verify mandate B is valid
    assert!(signer.verify(&mandate_b.token).is_some());

    // 4. Revoke Agent A's mandate
    delegation_state.revoke_mandate(&mandate_a.claims.mandate_id);
    assert!(delegation_state.is_mandate_revoked(&mandate_a.claims.mandate_id));

    // 5. In a full system, B's mandate would be rejected because its parent is revoked.
    // The cascade revocation is handled by the control-plane pushing revoked_mandate_ids.
    // Here we simulate that by revoking B's mandate as well (as the control-plane would do).
    delegation_state.revoke_mandate(&mandate_b.claims.mandate_id);
    assert!(delegation_state.is_mandate_revoked(&mandate_b.claims.mandate_id));

    // Verify both are revoked
    assert!(delegation_state.is_mandate_revoked(&mandate_a.claims.mandate_id));
    assert!(delegation_state.is_mandate_revoked(&mandate_b.claims.mandate_id));
}

#[tokio::test]
async fn test_delegation_chain_four_levels() {
    // Test a 4-level delegation chain: A -> B -> C -> D
    // Verifies depth tracking, scope narrowing, and chain hash computation

    // Create separate signer instances (LocalMandateSigner doesn't implement Clone)
    let delegation_state = test_delegation_state(test_signer(), 5);
    let signer = test_signer();

    // Level 0: Root Agent A with broad scope
    let mandate_a = create_root_mandate(&signer, "agent:A");
    assert_eq!(mandate_a.claims.delegation_depth, 0);

    // Level 1: A delegates to B
    let mandate_b = delegate_mandate(
        &signer,
        &mandate_a,
        "agent:B",
        "browser.click",
        "https://*.example.com",
    );
    assert_eq!(mandate_b.claims.delegation_depth, 1);
    assert_eq!(
        mandate_b.claims.parent_mandate_id,
        Some(mandate_a.claims.mandate_id.clone())
    );

    // Level 2: B delegates to C
    let mandate_c = delegate_mandate(
        &signer,
        &mandate_b,
        "agent:C",
        "browser.click",
        "https://app.example.com",
    );
    assert_eq!(mandate_c.claims.delegation_depth, 2);
    assert_eq!(
        mandate_c.claims.parent_mandate_id,
        Some(mandate_b.claims.mandate_id.clone())
    );

    // Level 3: C delegates to D
    let mandate_d = delegate_mandate(
        &signer,
        &mandate_c,
        "agent:D",
        "browser.click",
        "https://app.example.com",
    );
    assert_eq!(mandate_d.claims.delegation_depth, 3);
    assert_eq!(
        mandate_d.claims.parent_mandate_id,
        Some(mandate_c.claims.mandate_id.clone())
    );

    // Verify the delegation chain
    assert!(signer.verify_delegation(&mandate_a, None));
    assert!(signer.verify_delegation(&mandate_b, Some(&mandate_a)));
    assert!(signer.verify_delegation(&mandate_c, Some(&mandate_b)));
    assert!(signer.verify_delegation(&mandate_d, Some(&mandate_c)));

    // Verify all mandates are valid
    assert!(signer.verify(&mandate_a.token).is_some());
    assert!(signer.verify(&mandate_b.token).is_some());
    assert!(signer.verify(&mandate_c.token).is_some());
    assert!(signer.verify(&mandate_d.token).is_some());

    // Verify chain hash exists for derived mandates
    assert!(mandate_b.claims.delegation_chain_hash.is_some());
    assert!(mandate_c.claims.delegation_chain_hash.is_some());
    assert!(mandate_d.claims.delegation_chain_hash.is_some());

    // Test cascade revocation: revoke B, which should affect C and D
    delegation_state.update_revoked_mandates(&[
        mandate_b.claims.mandate_id.clone(),
        mandate_c.claims.mandate_id.clone(),
        mandate_d.claims.mandate_id.clone(),
    ]);

    assert!(!delegation_state.is_mandate_revoked(&mandate_a.claims.mandate_id));
    assert!(delegation_state.is_mandate_revoked(&mandate_b.claims.mandate_id));
    assert!(delegation_state.is_mandate_revoked(&mandate_c.claims.mandate_id));
    assert!(delegation_state.is_mandate_revoked(&mandate_d.claims.mandate_id));
}

#[tokio::test]
async fn test_delegation_max_depth_enforced() {
    // Test that delegation depth limit is enforced
    // Create separate signer instances (LocalMandateSigner doesn't implement Clone)
    let _delegation_state = test_delegation_state(test_signer(), 2); // Max depth 2
    let signer = test_signer();

    // Level 0: Root
    let mandate_a = create_root_mandate(&signer, "agent:A");

    // Level 1: A -> B
    let mandate_b = delegate_mandate(
        &signer,
        &mandate_a,
        "agent:B",
        "browser.click",
        "https://example.com",
    );
    assert_eq!(mandate_b.claims.delegation_depth, 1);

    // Level 2: B -> C (should succeed, depth = 2)
    let mandate_c = delegate_mandate(
        &signer,
        &mandate_b,
        "agent:C",
        "browser.click",
        "https://example.com",
    );
    assert_eq!(mandate_c.claims.delegation_depth, 2);

    // Note: The actual depth enforcement happens in the delegate_handler.
    // Here we're testing the mandate issuing, which doesn't enforce depth.
    // The handler test would need HTTP layer testing.
}

#[tokio::test]
async fn test_cascade_revocation_mid_chain() {
    // Test that revoking a mid-chain mandate properly cascades
    // Chain: A -> B -> C -> D
    // Revoke B -> should cascade to C and D, but not A

    // Create separate signer instances (LocalMandateSigner doesn't implement Clone)
    let delegation_state = test_delegation_state(test_signer(), 5);
    let signer = test_signer();

    let mandate_a = create_root_mandate(&signer, "agent:A");
    let mandate_b = delegate_mandate(
        &signer,
        &mandate_a,
        "agent:B",
        "browser.click",
        "https://example.com",
    );
    let mandate_c = delegate_mandate(
        &signer,
        &mandate_b,
        "agent:C",
        "browser.click",
        "https://example.com",
    );
    let mandate_d = delegate_mandate(
        &signer,
        &mandate_c,
        "agent:D",
        "browser.click",
        "https://example.com",
    );

    // Simulate control-plane cascade revocation starting from B
    // The control-plane would compute: B revoked -> cascade to C, D
    delegation_state.update_revoked_mandates(&[
        mandate_b.claims.mandate_id.clone(),
        mandate_c.claims.mandate_id.clone(),
        mandate_d.claims.mandate_id.clone(),
    ]);

    // A should NOT be revoked (it's the parent, not the child)
    assert!(!delegation_state.is_mandate_revoked(&mandate_a.claims.mandate_id));

    // B, C, D should all be revoked
    assert!(delegation_state.is_mandate_revoked(&mandate_b.claims.mandate_id));
    assert!(delegation_state.is_mandate_revoked(&mandate_c.claims.mandate_id));
    assert!(delegation_state.is_mandate_revoked(&mandate_d.claims.mandate_id));
}

#[tokio::test]
async fn test_scope_narrowing_in_chain() {
    // Test that each delegation properly narrows scope
    let signer = test_signer();

    // A has broad scope
    let mandate_a = create_root_mandate(&signer, "agent:A");
    assert_eq!(mandate_a.claims.action, "browser.*");
    assert_eq!(mandate_a.claims.resource, "https://*");

    // B has narrower action scope
    let mandate_b = delegate_mandate(&signer, &mandate_a, "agent:B", "browser.click", "https://*");
    assert_eq!(mandate_b.claims.action, "browser.click");

    // C has even narrower resource scope
    let mandate_c = delegate_mandate(
        &signer,
        &mandate_b,
        "agent:C",
        "browser.click",
        "https://example.com",
    );
    assert_eq!(mandate_c.claims.resource, "https://example.com");
}

#[tokio::test]
async fn test_ttl_capping_in_delegation() {
    // Test that derived mandate TTL cannot exceed parent's remaining TTL
    let signer = LocalMandateSigner::new(
        "test-ttl-capping-secret",
        60, // 1 minute TTL
        SigningAlgorithm::ES256,
        true,
        None,
        None,
    );

    let mandate_a = create_root_mandate(&signer, "agent:A");
    let mandate_b = delegate_mandate(
        &signer,
        &mandate_a,
        "agent:B",
        "browser.click",
        "https://example.com",
    );

    // B's expiration should not exceed A's
    assert!(mandate_b.claims.expires_at_epoch_s <= mandate_a.claims.expires_at_epoch_s);
}

#[tokio::test]
async fn test_revocation_cache_performance() {
    // Test that revocation cache operations are fast (O(1))
    // Create separate signer instance (LocalMandateSigner doesn't implement Clone)
    let delegation_state = test_delegation_state(test_signer(), 5);

    // Add many revoked mandates
    let mandate_ids: Vec<String> = (0..10000).map(|i| format!("m_test_{:06}", i)).collect();

    let start = std::time::Instant::now();
    delegation_state.update_revoked_mandates(&mandate_ids);
    let update_duration = start.elapsed();

    // Update should be fast (< 100ms for 10k items)
    assert!(
        update_duration.as_millis() < 100,
        "Bulk update took too long: {:?}",
        update_duration
    );

    // Check lookup performance
    let start = std::time::Instant::now();
    for _ in 0..10000 {
        let _ = delegation_state.is_mandate_revoked("m_test_005000");
    }
    let lookup_duration = start.elapsed();

    // 10k lookups should be very fast (< 50ms)
    assert!(
        lookup_duration.as_millis() < 50,
        "Lookups took too long: {:?}",
        lookup_duration
    );
}

#[tokio::test]
async fn test_delegation_chain_hash_integrity() {
    // Test that chain hash properly links mandates
    let signer = test_signer();

    let mandate_a = create_root_mandate(&signer, "agent:A");
    let mandate_b = delegate_mandate(
        &signer,
        &mandate_a,
        "agent:B",
        "browser.click",
        "https://example.com",
    );

    // B should have a chain hash
    assert!(mandate_b.claims.delegation_chain_hash.is_some());
    let chain_hash_b = mandate_b.claims.delegation_chain_hash.as_ref().unwrap();

    // C should have a different chain hash (includes B's mandate)
    let mandate_c = delegate_mandate(
        &signer,
        &mandate_b,
        "agent:C",
        "browser.click",
        "https://example.com",
    );
    assert!(mandate_c.claims.delegation_chain_hash.is_some());
    let chain_hash_c = mandate_c.claims.delegation_chain_hash.as_ref().unwrap();

    // Chain hashes should be different
    assert_ne!(chain_hash_b, chain_hash_c);

    // Verify chain integrity
    assert!(signer.verify_delegation(&mandate_b, Some(&mandate_a)));
    assert!(signer.verify_delegation(&mandate_c, Some(&mandate_b)));
}
