//! Integration tests for predicate-authorityd.
//!
//! These tests verify the HTTP API behavior matches the Python sidecar contract.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::json;
use tower::util::ServiceExt;

// Re-import from the crate
use predicate_authorityd::bridge::{IdpBridgeProvider, LocalIdpBridgeConfig};
use predicate_authorityd::http::{create_router, AppState};
use predicate_authorityd::mandate::MandateStore;
use predicate_authorityd::models::PolicyRule;
use predicate_authorityd::policy::PolicyEngine;

fn test_state() -> AppState {
    AppState::new(PolicyEngine::new(), "local_only")
}

fn test_state_with_rules(rules: Vec<PolicyRule>) -> AppState {
    let engine = PolicyEngine::new();
    engine.replace_rules(rules);
    AppState::new(engine, "local_only")
}

fn test_state_with_local_idp(rules: Vec<PolicyRule>) -> AppState {
    let engine = PolicyEngine::new();
    engine.replace_rules(rules);

    let config = LocalIdpBridgeConfig {
        issuer: "http://localhost/predicate-local-idp".to_string(),
        audience: "api://predicate-authority".to_string(),
        signing_key: "test-signing-key".to_string(),
        token_ttl_seconds: 300,
    };

    let bridge = IdpBridgeProvider::new("local-idp", Some(config), None, None, None).unwrap();

    AppState::new(engine, "local_only").with_idp_bridge(bridge, "local-idp")
}

fn test_state_with_mandate_store(rules: Vec<PolicyRule>) -> AppState {
    let engine = PolicyEngine::new();
    engine.replace_rules(rules);
    AppState::new(engine, "local_only").with_mandate_store(MandateStore::new())
}

#[tokio::test]
async fn test_health_endpoint() {
    let app = create_router(test_state());

    let response = app
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_authorize_allow_rule() {
    let rules = vec![PolicyRule {
        name: "allow-browser".to_string(),
        effect: predicate_authorityd::models::PolicyEffect::Allow,
        principals: vec!["agent:*".to_string()],
        actions: vec!["browser.*".to_string()],
        resources: vec!["*".to_string()],
        max_delegation_depth: None,
        required_labels: vec![],
    }];

    let app = create_router(test_state_with_rules(rules));

    let body = json!({
        "principal": "agent:web",
        "action": "browser.click",
        "resource": "https://example.com"
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/authorize")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let resp: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

    assert_eq!(resp["allowed"], true);
    assert_eq!(resp["reason"], "allowed");
}

#[tokio::test]
async fn test_authorize_deny_rule() {
    let rules = vec![PolicyRule {
        name: "deny-admin".to_string(),
        effect: predicate_authorityd::models::PolicyEffect::Deny,
        principals: vec!["agent:*".to_string()],
        actions: vec!["admin.*".to_string()],
        resources: vec!["*".to_string()],
        max_delegation_depth: None,
        required_labels: vec![],
    }];

    let app = create_router(test_state_with_rules(rules));

    let body = json!({
        "principal": "agent:test",
        "action": "admin.delete",
        "resource": "/users/123"
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/authorize")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let resp: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

    assert_eq!(resp["allowed"], false);
    assert_eq!(resp["reason"], "explicit_deny");
}

#[tokio::test]
async fn test_authorize_no_matching_policy() {
    let app = create_router(test_state());

    let body = json!({
        "principal": "agent:test",
        "action": "unknown.action",
        "resource": "/resource"
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/authorize")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    // Default deny when no rules match
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_status_endpoint() {
    let app = create_router(test_state());

    let response = app
        .oneshot(
            Request::builder()
                .uri("/status")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let resp: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

    assert!(resp["status"].as_str().is_some());
    assert!(resp["mode"].as_str().is_some());
}

#[tokio::test]
async fn test_metrics_endpoint() {
    let app = create_router(test_state());

    let response = app
        .oneshot(
            Request::builder()
                .uri("/metrics")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body_str = String::from_utf8(body_bytes.to_vec()).unwrap();

    // Metrics endpoint returns Prometheus text format
    assert!(body_str.contains("predicate_authority_uptime_seconds"));
    assert!(body_str.contains("predicate_authority_decisions_total"));
}

#[tokio::test]
async fn test_policy_reload() {
    let app = create_router(test_state());

    let body = json!({
        "rules": [
            {
                "name": "new-rule",
                "effect": "allow",
                "principals": ["*"],
                "actions": ["*"],
                "resources": ["*"]
            }
        ]
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/policy/reload")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let resp: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

    assert_eq!(resp["success"], true);
    assert_eq!(resp["rule_count"], 1);
}

#[tokio::test]
async fn test_legacy_authorize_endpoint() {
    // Test that /authorize works as alias for /v1/authorize
    let rules = vec![PolicyRule {
        name: "allow-all".to_string(),
        effect: predicate_authorityd::models::PolicyEffect::Allow,
        principals: vec!["*".to_string()],
        actions: vec!["*".to_string()],
        resources: vec!["*".to_string()],
        max_delegation_depth: None,
        required_labels: vec![],
    }];

    let app = create_router(test_state_with_rules(rules));

    let body = json!({
        "principal": "agent:test",
        "action": "test.action",
        "resource": "/test"
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/authorize")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_authorize_with_labels() {
    let rules = vec![PolicyRule {
        name: "require-labels".to_string(),
        effect: predicate_authorityd::models::PolicyEffect::Allow,
        principals: vec!["agent:*".to_string()],
        actions: vec!["sensitive.*".to_string()],
        resources: vec!["*".to_string()],
        max_delegation_depth: None,
        required_labels: vec!["approved".to_string(), "verified".to_string()],
    }];

    let app = create_router(test_state_with_rules(rules));

    // Request without required labels
    let body = json!({
        "principal": "agent:test",
        "action": "sensitive.read",
        "resource": "/secret",
        "labels": ["approved"]  // Missing "verified"
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/authorize")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let resp: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

    assert_eq!(resp["allowed"], false);
    assert_eq!(resp["reason"], "missing_required_verification");
    assert!(resp["missing_labels"].as_array().is_some());
}

// --- Token validation tests ---

#[tokio::test]
async fn test_local_mode_no_token_required() {
    // Local mode should not require a bearer token
    let rules = vec![PolicyRule {
        name: "allow-all".to_string(),
        effect: predicate_authorityd::models::PolicyEffect::Allow,
        principals: vec!["*".to_string()],
        actions: vec!["*".to_string()],
        resources: vec!["*".to_string()],
        max_delegation_depth: None,
        required_labels: vec![],
    }];

    let app = create_router(test_state_with_rules(rules));

    let body = json!({
        "principal": "agent:test",
        "action": "test.action",
        "resource": "/test"
    });

    // No Authorization header
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/authorize")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_local_idp_mode_requires_token() {
    // local-idp mode should require a bearer token
    let rules = vec![PolicyRule {
        name: "allow-all".to_string(),
        effect: predicate_authorityd::models::PolicyEffect::Allow,
        principals: vec!["*".to_string()],
        actions: vec!["*".to_string()],
        resources: vec!["*".to_string()],
        max_delegation_depth: None,
        required_labels: vec![],
    }];

    let app = create_router(test_state_with_local_idp(rules));

    let body = json!({
        "principal": "agent:test",
        "action": "test.action",
        "resource": "/test"
    });

    // No Authorization header - should be rejected
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/authorize")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let resp: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

    assert_eq!(resp["allowed"], false);
    assert_eq!(resp["reason"], "MISSING_AUTHORIZATION");
}

#[tokio::test]
async fn test_local_idp_mode_invalid_token() {
    // local-idp mode should reject invalid tokens
    let rules = vec![PolicyRule {
        name: "allow-all".to_string(),
        effect: predicate_authorityd::models::PolicyEffect::Allow,
        principals: vec!["*".to_string()],
        actions: vec!["*".to_string()],
        resources: vec!["*".to_string()],
        max_delegation_depth: None,
        required_labels: vec![],
    }];

    let app = create_router(test_state_with_local_idp(rules));

    let body = json!({
        "principal": "agent:test",
        "action": "test.action",
        "resource": "/test"
    });

    // Invalid token - should be rejected
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/authorize")
                .header("content-type", "application/json")
                .header("authorization", "Bearer invalid.token.here")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let resp: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

    assert_eq!(resp["allowed"], false);
    assert!(resp["reason"]
        .as_str()
        .unwrap()
        .starts_with("INVALID_TOKEN"));
}

#[tokio::test]
async fn test_status_includes_identity_mode() {
    // Status endpoint should include identity_mode
    let rules = vec![];
    let app = create_router(test_state_with_local_idp(rules));

    let response = app
        .oneshot(
            Request::builder()
                .uri("/status")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let resp: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

    assert_eq!(resp["identity_mode"], "local-idp");
}

// --- Execute endpoint tests (Phase 5: Execution Proxying) ---

#[tokio::test]
async fn test_execute_endpoint_not_enabled_without_mandate_store() {
    // Execute endpoint should return 404 when mandate store is not configured
    let app = create_router(test_state());

    let body = json!({
        "mandate_id": "m_test123",
        "action": "fs.read",
        "resource": "/src/index.ts"
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/execute")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    // Should return 404 because route is not registered without mandate store
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_execute_mandate_not_found() {
    // Execute with non-existent mandate should return 404
    let rules = vec![PolicyRule {
        name: "allow-fs".to_string(),
        effect: predicate_authorityd::models::PolicyEffect::Allow,
        principals: vec!["*".to_string()],
        actions: vec!["fs.*".to_string()],
        resources: vec!["*".to_string()],
        max_delegation_depth: None,
        required_labels: vec![],
    }];

    let app = create_router(test_state_with_mandate_store(rules));

    let body = json!({
        "mandate_id": "m_nonexistent",
        "action": "fs.read",
        "resource": "/src/index.ts"
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/execute")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let resp: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

    assert_eq!(resp["success"], false);
    assert!(resp["error"]
        .as_str()
        .unwrap()
        .contains("Mandate not found"));
}

#[tokio::test]
async fn test_execute_with_stored_mandate() {
    use predicate_authorityd::mandate::MandateStore;
    use predicate_authorityd::models::{MandateClaims, SignedMandate};
    use std::time::{SystemTime, UNIX_EPOCH};

    let rules = vec![PolicyRule {
        name: "allow-fs".to_string(),
        effect: predicate_authorityd::models::PolicyEffect::Allow,
        principals: vec!["*".to_string()],
        actions: vec!["fs.*".to_string()],
        resources: vec!["*".to_string()],
        max_delegation_depth: None,
        required_labels: vec![],
    }];

    let engine = PolicyEngine::new();
    engine.replace_rules(rules);
    let mandate_store = MandateStore::new();

    // Create and store a test mandate
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    let mandate = SignedMandate {
        token: "test-token".to_string(),
        claims: MandateClaims {
            mandate_id: "m_test_execute".to_string(),
            principal_id: "agent:test".to_string(),
            action: "fs.read".to_string(),
            resource: "/tmp/test-execute.txt".to_string(),
            intent_hash: "hash123".to_string(),
            state_hash: "state123".to_string(),
            issued_at_epoch_s: now,
            expires_at_epoch_s: now + 300,
            delegated_by: None,
            parent_mandate_id: None,
            delegation_depth: 0,
            delegation_chain_hash: Some("chain123".to_string()),
            iss: Some("test".to_string()),
            aud: Some("test".to_string()),
            sub: Some("agent:test".to_string()),
            iat: None,
            exp: Some(now + 300),
            nbf: None,
            jti: Some("m_test_execute".to_string()),
        },
        signature: "test-signature".to_string(),
    };

    mandate_store.store(mandate);

    let state = AppState::new(engine, "local_only").with_mandate_store(mandate_store);
    let app = create_router(state);

    // Create test file first
    std::fs::write("/tmp/test-execute.txt", "Hello from execute test").unwrap();

    let body = json!({
        "mandate_id": "m_test_execute",
        "action": "fs.read",
        "resource": "/tmp/test-execute.txt"
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/execute")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let resp: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

    assert_eq!(resp["success"], true);
    assert!(resp["result"].is_object());
    assert!(resp["audit_id"].as_str().is_some());
    assert!(resp["evidence_hash"].as_str().is_some());

    // Verify result contains expected content
    let result = &resp["result"];
    assert_eq!(result["type"], "file_read");
    assert!(result["content"]
        .as_str()
        .unwrap()
        .contains("Hello from execute test"));

    // Cleanup
    std::fs::remove_file("/tmp/test-execute.txt").ok();
}

#[tokio::test]
async fn test_execute_action_mismatch() {
    use predicate_authorityd::mandate::MandateStore;
    use predicate_authorityd::models::{MandateClaims, SignedMandate};
    use std::time::{SystemTime, UNIX_EPOCH};

    let rules = vec![];
    let engine = PolicyEngine::new();
    engine.replace_rules(rules);
    let mandate_store = MandateStore::new();

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    // Mandate for fs.read
    let mandate = SignedMandate {
        token: "test-token".to_string(),
        claims: MandateClaims {
            mandate_id: "m_action_mismatch".to_string(),
            principal_id: "agent:test".to_string(),
            action: "fs.read".to_string(),
            resource: "/src/file.ts".to_string(),
            intent_hash: "hash123".to_string(),
            state_hash: "state123".to_string(),
            issued_at_epoch_s: now,
            expires_at_epoch_s: now + 300,
            delegated_by: None,
            parent_mandate_id: None,
            delegation_depth: 0,
            delegation_chain_hash: Some("chain123".to_string()),
            iss: Some("test".to_string()),
            aud: Some("test".to_string()),
            sub: Some("agent:test".to_string()),
            iat: None,
            exp: Some(now + 300),
            nbf: None,
            jti: Some("m_action_mismatch".to_string()),
        },
        signature: "test-signature".to_string(),
    };

    mandate_store.store(mandate);

    let state = AppState::new(engine, "local_only").with_mandate_store(mandate_store);
    let app = create_router(state);

    // Try to execute fs.write with a fs.read mandate
    let body = json!({
        "mandate_id": "m_action_mismatch",
        "action": "fs.write",  // Different from mandate's action
        "resource": "/src/file.ts",
        "payload": {
            "type": "file_write",
            "content": "malicious content",
            "create": true
        }
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/execute")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let resp: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

    assert_eq!(resp["success"], false);
    assert!(resp["error"]
        .as_str()
        .unwrap()
        .contains("not authorized by mandate"));
}

#[tokio::test]
async fn test_execute_resource_mismatch() {
    use predicate_authorityd::mandate::MandateStore;
    use predicate_authorityd::models::{MandateClaims, SignedMandate};
    use std::time::{SystemTime, UNIX_EPOCH};

    let rules = vec![];
    let engine = PolicyEngine::new();
    engine.replace_rules(rules);
    let mandate_store = MandateStore::new();

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    // Mandate for /src/index.ts
    let mandate = SignedMandate {
        token: "test-token".to_string(),
        claims: MandateClaims {
            mandate_id: "m_resource_mismatch".to_string(),
            principal_id: "agent:test".to_string(),
            action: "fs.read".to_string(),
            resource: "/src/index.ts".to_string(),
            intent_hash: "hash123".to_string(),
            state_hash: "state123".to_string(),
            issued_at_epoch_s: now,
            expires_at_epoch_s: now + 300,
            delegated_by: None,
            parent_mandate_id: None,
            delegation_depth: 0,
            delegation_chain_hash: Some("chain123".to_string()),
            iss: Some("test".to_string()),
            aud: Some("test".to_string()),
            sub: Some("agent:test".to_string()),
            iat: None,
            exp: Some(now + 300),
            nbf: None,
            jti: Some("m_resource_mismatch".to_string()),
        },
        signature: "test-signature".to_string(),
    };

    mandate_store.store(mandate);

    let state = AppState::new(engine, "local_only").with_mandate_store(mandate_store);
    let app = create_router(state);

    // Try to read /etc/passwd with a mandate for /src/index.ts
    // This is the classic "confused deputy" attack that Phase 5 prevents
    let body = json!({
        "mandate_id": "m_resource_mismatch",
        "action": "fs.read",
        "resource": "/etc/passwd"  // Different from mandate's resource!
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/execute")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let resp: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

    assert_eq!(resp["success"], false);
    assert!(resp["error"]
        .as_str()
        .unwrap()
        .contains("not in mandate scope"));
}

#[tokio::test]
async fn test_execute_expired_mandate() {
    use predicate_authorityd::mandate::MandateStore;
    use predicate_authorityd::models::{MandateClaims, SignedMandate};
    use std::time::{SystemTime, UNIX_EPOCH};

    let rules = vec![];
    let engine = PolicyEngine::new();
    engine.replace_rules(rules);
    let mandate_store = MandateStore::new();

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    // Create an already expired mandate
    let mandate = SignedMandate {
        token: "test-token".to_string(),
        claims: MandateClaims {
            mandate_id: "m_expired".to_string(),
            principal_id: "agent:test".to_string(),
            action: "fs.read".to_string(),
            resource: "/src/file.ts".to_string(),
            intent_hash: "hash123".to_string(),
            state_hash: "state123".to_string(),
            issued_at_epoch_s: now - 600,
            expires_at_epoch_s: now - 300, // Expired 5 minutes ago
            delegated_by: None,
            parent_mandate_id: None,
            delegation_depth: 0,
            delegation_chain_hash: Some("chain123".to_string()),
            iss: Some("test".to_string()),
            aud: Some("test".to_string()),
            sub: Some("agent:test".to_string()),
            iat: None,
            exp: Some(now - 300),
            nbf: None,
            jti: Some("m_expired".to_string()),
        },
        signature: "test-signature".to_string(),
    };

    mandate_store.store(mandate);

    let state = AppState::new(engine, "local_only").with_mandate_store(mandate_store);
    let app = create_router(state);

    let body = json!({
        "mandate_id": "m_expired",
        "action": "fs.read",
        "resource": "/src/file.ts"
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/execute")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let resp: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

    assert_eq!(resp["success"], false);
    assert!(resp["error"].as_str().unwrap().contains("Mandate expired"));
}
