//! Benchmarks for delegation chain operations.
//!
//! Target performance:
//! - POST /v1/delegate: < 10ms p99
//! - is_scope_subset(): < 1μs
//! - Revocation check: < 1μs

use criterion::{black_box, criterion_group, criterion_main, Criterion};

use predicate_authorityd::http::DelegationState;
use predicate_authorityd::mandate::{LocalMandateSigner, SigningAlgorithm};
use predicate_authorityd::models::{
    ActionRequest, ActionSpec, PrincipalRef, SignedMandate, StateEvidence, VerificationEvidence,
};
use predicate_authorityd::policy::subset::{is_action_subset, is_resource_subset, is_scope_subset};

/// Create a test mandate signer
fn test_signer() -> LocalMandateSigner {
    LocalMandateSigner::new(
        "bench-secret-key-for-testing",
        300,
        SigningAlgorithm::ES256,
        true,
        None,
        None,
    )
}

/// Create a test delegation state
fn test_delegation_state(signer: LocalMandateSigner) -> DelegationState {
    DelegationState::new(signer).with_max_depth(5)
}

/// Create a root mandate
fn create_root_mandate(signer: &LocalMandateSigner) -> SignedMandate {
    let request = ActionRequest {
        principal: PrincipalRef::new("agent:benchmark"),
        action_spec: ActionSpec {
            action: "browser.*".to_string(),
            resource: "https://*".to_string(),
            intent: "benchmark task".to_string(),
            scopes: vec![],
        },
        state_evidence: StateEvidence::new("bench", "state_hash"),
        verification_evidence: VerificationEvidence::default(),
    };
    signer.issue(&request, None)
}

/// Create a derived mandate
fn create_derived_mandate(signer: &LocalMandateSigner, parent: &SignedMandate) -> SignedMandate {
    let request = ActionRequest {
        principal: PrincipalRef::new("agent:child"),
        action_spec: ActionSpec {
            action: "browser.click".to_string(),
            resource: "https://example.com".to_string(),
            intent: "derived task".to_string(),
            scopes: vec![],
        },
        state_evidence: StateEvidence::new("bench", "child_hash"),
        verification_evidence: VerificationEvidence::default(),
    };
    signer.issue(&request, Some(parent))
}

// =============================================================================
// SCOPE SUBSET BENCHMARKS
// =============================================================================

fn bench_is_action_subset_exact_match(c: &mut Criterion) {
    c.bench_function("is_action_subset exact match", |b| {
        b.iter(|| is_action_subset(black_box("browser.click"), black_box("browser.click")))
    });
}

fn bench_is_action_subset_wildcard(c: &mut Criterion) {
    c.bench_function("is_action_subset wildcard parent", |b| {
        b.iter(|| is_action_subset(black_box("browser.*"), black_box("browser.click")))
    });
}

fn bench_is_action_subset_universal(c: &mut Criterion) {
    c.bench_function("is_action_subset universal wildcard", |b| {
        b.iter(|| is_action_subset(black_box("*"), black_box("browser.click")))
    });
}

fn bench_is_resource_subset_url(c: &mut Criterion) {
    c.bench_function("is_resource_subset URL pattern", |b| {
        b.iter(|| {
            is_resource_subset(
                black_box("https://*"),
                black_box("https://example.com/path"),
            )
        })
    });
}

fn bench_is_scope_subset_combined(c: &mut Criterion) {
    c.bench_function("is_scope_subset combined validation", |b| {
        b.iter(|| {
            is_scope_subset(
                black_box("browser.*"),
                black_box("https://*"),
                black_box("browser.click"),
                black_box("https://example.com"),
            )
        })
    });
}

// =============================================================================
// REVOCATION CHECK BENCHMARKS
// =============================================================================

fn bench_revocation_check_empty_cache(c: &mut Criterion) {
    let signer = test_signer();
    let delegation_state = test_delegation_state(signer);

    c.bench_function("revocation check empty cache", |b| {
        b.iter(|| delegation_state.is_mandate_revoked(black_box("m_nonexistent")))
    });
}

fn bench_revocation_check_small_cache(c: &mut Criterion) {
    let signer = test_signer();
    let delegation_state = test_delegation_state(signer);

    // Add 100 revoked mandates
    let ids: Vec<String> = (0..100).map(|i| format!("m_revoked_{}", i)).collect();
    delegation_state.update_revoked_mandates(&ids);

    c.bench_function("revocation check 100 items", |b| {
        b.iter(|| delegation_state.is_mandate_revoked(black_box("m_revoked_50")))
    });
}

fn bench_revocation_check_large_cache(c: &mut Criterion) {
    let signer = test_signer();
    let delegation_state = test_delegation_state(signer);

    // Add 10,000 revoked mandates
    let ids: Vec<String> = (0..10000).map(|i| format!("m_revoked_{}", i)).collect();
    delegation_state.update_revoked_mandates(&ids);

    c.bench_function("revocation check 10k items (hit)", |b| {
        b.iter(|| delegation_state.is_mandate_revoked(black_box("m_revoked_5000")))
    });
}

fn bench_revocation_check_large_cache_miss(c: &mut Criterion) {
    let signer = test_signer();
    let delegation_state = test_delegation_state(signer);

    // Add 10,000 revoked mandates
    let ids: Vec<String> = (0..10000).map(|i| format!("m_revoked_{}", i)).collect();
    delegation_state.update_revoked_mandates(&ids);

    c.bench_function("revocation check 10k items (miss)", |b| {
        b.iter(|| delegation_state.is_mandate_revoked(black_box("m_not_revoked")))
    });
}

fn bench_revocation_bulk_update(c: &mut Criterion) {
    let signer = test_signer();
    let delegation_state = test_delegation_state(signer);

    let ids: Vec<String> = (0..1000).map(|i| format!("m_batch_{}", i)).collect();

    c.bench_function("revocation bulk update 1k items", |b| {
        b.iter(|| {
            delegation_state.clear_revoked_mandates();
            delegation_state.update_revoked_mandates(black_box(&ids))
        })
    });
}

// =============================================================================
// MANDATE ISSUANCE BENCHMARKS
// =============================================================================

fn bench_issue_root_mandate(c: &mut Criterion) {
    let signer = test_signer();

    c.bench_function("issue root mandate", |b| {
        b.iter(|| create_root_mandate(black_box(&signer)))
    });
}

fn bench_issue_derived_mandate(c: &mut Criterion) {
    let signer = test_signer();
    let root = create_root_mandate(&signer);

    c.bench_function("issue derived mandate", |b| {
        b.iter(|| create_derived_mandate(black_box(&signer), black_box(&root)))
    });
}

fn bench_verify_mandate(c: &mut Criterion) {
    let signer = test_signer();
    let mandate = create_root_mandate(&signer);

    c.bench_function("verify mandate signature", |b| {
        b.iter(|| signer.verify(black_box(&mandate.token)))
    });
}

fn bench_verify_delegation_chain(c: &mut Criterion) {
    let signer = test_signer();
    let root = create_root_mandate(&signer);
    let child = create_derived_mandate(&signer, &root);

    c.bench_function("verify delegation chain", |b| {
        b.iter(|| signer.verify_delegation(black_box(&child), black_box(Some(&root))))
    });
}

// =============================================================================
// DELEGATION CHAIN BENCHMARKS
// =============================================================================

fn bench_three_level_chain_issuance(c: &mut Criterion) {
    let signer = test_signer();

    c.bench_function("issue 3-level chain", |b| {
        b.iter(|| {
            let root = create_root_mandate(&signer);
            let level1 = create_derived_mandate(&signer, &root);
            let _level2 = create_derived_mandate(&signer, &level1);
        })
    });
}

fn bench_chain_hash_computation(c: &mut Criterion) {
    let signer = test_signer();
    let root = create_root_mandate(&signer);

    c.bench_function("chain hash in derived mandate", |b| {
        b.iter(|| {
            let derived = create_derived_mandate(&signer, &root);
            black_box(derived.claims.delegation_chain_hash)
        })
    });
}

// =============================================================================
// CRITERION GROUPS
// =============================================================================

criterion_group!(
    scope_benches,
    bench_is_action_subset_exact_match,
    bench_is_action_subset_wildcard,
    bench_is_action_subset_universal,
    bench_is_resource_subset_url,
    bench_is_scope_subset_combined,
);

criterion_group!(
    revocation_benches,
    bench_revocation_check_empty_cache,
    bench_revocation_check_small_cache,
    bench_revocation_check_large_cache,
    bench_revocation_check_large_cache_miss,
    bench_revocation_bulk_update,
);

criterion_group!(
    mandate_benches,
    bench_issue_root_mandate,
    bench_issue_derived_mandate,
    bench_verify_mandate,
    bench_verify_delegation_chain,
);

criterion_group!(
    chain_benches,
    bench_three_level_chain_issuance,
    bench_chain_hash_computation,
);

criterion_main!(
    scope_benches,
    revocation_benches,
    mandate_benches,
    chain_benches
);
