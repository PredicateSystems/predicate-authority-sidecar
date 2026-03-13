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
        inject_headers: None,
        inject_headers_from_file: None,
        inject_env: None,
        inject_env_from_file: None,
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
        inject_headers: None,
        inject_headers_from_file: None,
        inject_env: None,
        inject_env_from_file: None,
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
    // Multi-scope now includes scope details in reason
    assert!(resp["reason"].as_str().unwrap().contains("explicit_deny"));
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
        inject_headers: None,
        inject_headers_from_file: None,
        inject_env: None,
        inject_env_from_file: None,
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
        inject_headers: None,
        inject_headers_from_file: None,
        inject_env: None,
        inject_env_from_file: None,
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
    // Multi-scope now includes scope details in reason
    assert!(resp["reason"]
        .as_str()
        .unwrap()
        .contains("missing_required_verification"));
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
        inject_headers: None,
        inject_headers_from_file: None,
        inject_env: None,
        inject_env_from_file: None,
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
        inject_headers: None,
        inject_headers_from_file: None,
        inject_env: None,
        inject_env_from_file: None,
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
        inject_headers: None,
        inject_headers_from_file: None,
        inject_env: None,
        inject_env_from_file: None,
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
        inject_headers: None,
        inject_headers_from_file: None,
        inject_env: None,
        inject_env_from_file: None,
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
        inject_headers: None,
        inject_headers_from_file: None,
        inject_env: None,
        inject_env_from_file: None,
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
            scopes: Vec::new(),
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
            scopes: Vec::new(),
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
            scopes: Vec::new(),
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
            scopes: Vec::new(),
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

// --- Secret Injection Tests (Phase 2) ---

#[tokio::test]
async fn test_secret_injection_cli_exec() {
    use predicate_authorityd::mandate::MandateStore;
    use predicate_authorityd::models::{MandateClaims, SignedMandate};
    use std::collections::HashMap;
    use std::time::{SystemTime, UNIX_EPOCH};

    // Set a test environment variable that will be injected
    std::env::set_var("TEST_SECRET_VALUE_CLI", "secret123");

    // Create policy rule with inject_env
    let mut inject_env = HashMap::new();
    inject_env.insert(
        "INJECTED_VAR".to_string(),
        "${TEST_SECRET_VALUE_CLI}".to_string(),
    );
    inject_env.insert(
        "INJECTED_WITH_DEFAULT".to_string(),
        "${NONEXISTENT_CLI_VAR:-fallback_value}".to_string(),
    );

    let rules = vec![PolicyRule {
        name: "cli-with-injection".to_string(),
        effect: predicate_authorityd::models::PolicyEffect::Allow,
        principals: vec!["*".to_string()],
        actions: vec!["cli.exec".to_string()],
        resources: vec!["*".to_string()],
        max_delegation_depth: None,
        inject_headers: None,
        inject_headers_from_file: None,
        inject_env: Some(inject_env),
        inject_env_from_file: None,
        required_labels: vec![],
    }];

    let engine = PolicyEngine::new();
    engine.replace_rules(rules);
    let mandate_store = MandateStore::new();

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    let mandate = SignedMandate {
        token: "test-token".to_string(),
        claims: MandateClaims {
            mandate_id: "m_cli_inject".to_string(),
            principal_id: "agent:test".to_string(),
            action: "cli.exec".to_string(),
            resource: "sh".to_string(),
            scopes: Vec::new(),
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
            jti: Some("m_cli_inject".to_string()),
        },
        signature: "test-signature".to_string(),
    };

    mandate_store.store(mandate);

    let state = AppState::new(engine, "local_only").with_mandate_store(mandate_store);
    let app = create_router(state);

    // Use sh -c to echo the injected environment variables
    let body = json!({
        "mandate_id": "m_cli_inject",
        "action": "cli.exec",
        "resource": "sh",
        "payload": {
            "type": "cli_exec",
            "command": "sh",
            "args": ["-c", "echo INJECTED_VAR=$INJECTED_VAR INJECTED_WITH_DEFAULT=$INJECTED_WITH_DEFAULT"]
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

    assert_eq!(response.status(), StatusCode::OK);

    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let resp: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

    assert_eq!(resp["success"], true);

    let stdout = resp["result"]["stdout"].as_str().unwrap();

    // Verify the injected values are present in output
    assert!(
        stdout.contains("secret123"),
        "Expected secret123 in stdout: {}",
        stdout
    );
    assert!(
        stdout.contains("fallback_value"),
        "Expected fallback_value in stdout: {}",
        stdout
    );

    // Cleanup
    std::env::remove_var("TEST_SECRET_VALUE_CLI");
}

#[tokio::test]
async fn test_secret_injection_default_value_syntax() {
    use predicate_authorityd::secrets::substitute_env_vars;

    // Test with existing variable
    std::env::set_var("EXISTING_VAR_TEST", "existing_value");

    // Existing variable without default - should use existing value
    let result = substitute_env_vars("prefix_${EXISTING_VAR_TEST}_suffix").unwrap();
    assert_eq!(result, "prefix_existing_value_suffix");

    // Existing variable with default - should use existing value, not default
    let result = substitute_env_vars("${EXISTING_VAR_TEST:-default}").unwrap();
    assert_eq!(result, "existing_value");

    // Non-existing variable with default - should use default
    let result = substitute_env_vars("${NONEXISTENT_VAR_12345:-my_default}").unwrap();
    assert_eq!(result, "my_default");

    // Non-existing variable without default - should ERROR (fail-closed behavior)
    let result = substitute_env_vars("${NONEXISTENT_VAR_12345}");
    assert!(result.is_err(), "Missing required var should return error");

    // Cleanup
    std::env::remove_var("EXISTING_VAR_TEST");
}

#[tokio::test]
async fn test_secret_not_exposed_in_authorize_response() {
    // Security test: Verify that inject_headers/inject_env values
    // are NOT exposed in the authorize response

    let mut inject_headers = std::collections::HashMap::new();
    inject_headers.insert(
        "Authorization".to_string(),
        "Bearer ${API_SECRET}".to_string(),
    );

    std::env::set_var("API_SECRET", "super_secret_token_12345");

    let rules = vec![PolicyRule {
        name: "api-with-secrets".to_string(),
        effect: predicate_authorityd::models::PolicyEffect::Allow,
        principals: vec!["agent:*".to_string()],
        actions: vec!["http.fetch".to_string()],
        resources: vec!["https://api.example.com/*".to_string()],
        max_delegation_depth: None,
        inject_headers: Some(inject_headers),
        inject_headers_from_file: None,
        inject_env: None,
        inject_env_from_file: None,
        required_labels: vec![],
    }];

    let app = create_router(test_state_with_rules(rules));

    let body = json!({
        "principal": "agent:web",
        "action": "http.fetch",
        "resource": "https://api.example.com/data"
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
    let body_str = String::from_utf8(body_bytes.to_vec()).unwrap();
    let resp: serde_json::Value = serde_json::from_str(&body_str).unwrap();

    // Verify authorization succeeded
    assert_eq!(resp["allowed"], true);

    // SECURITY: Verify the secret value is NOT in the response
    assert!(
        !body_str.contains("super_secret_token_12345"),
        "Secret value leaked in authorize response!"
    );
    assert!(
        !body_str.contains("API_SECRET"),
        "Secret variable name leaked in authorize response!"
    );

    // Cleanup
    std::env::remove_var("API_SECRET");
}

#[tokio::test]
async fn test_policy_with_inject_headers_parses_correctly() {
    // Test that policies with inject_headers can be loaded via /policy/reload

    let body = json!({
        "rules": [
            {
                "name": "github-api",
                "effect": "allow",
                "principals": ["agent:*"],
                "actions": ["http.fetch"],
                "resources": ["https://api.github.com/*"],
                "inject_headers": {
                    "Authorization": "Bearer ${GITHUB_TOKEN}",
                    "Accept": "application/vnd.github.v3+json"
                }
            },
            {
                "name": "aws-cli",
                "effect": "allow",
                "principals": ["agent:ops"],
                "actions": ["cli.exec"],
                "resources": ["aws *"],
                "inject_env": {
                    "AWS_ACCESS_KEY_ID": "${AWS_ACCESS_KEY_ID}",
                    "AWS_SECRET_ACCESS_KEY": "${AWS_SECRET_ACCESS_KEY}",
                    "AWS_DEFAULT_REGION": "${AWS_REGION:-us-east-1}"
                }
            }
        ]
    });

    let app = create_router(test_state());

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
    assert_eq!(resp["rule_count"], 2);
}

#[tokio::test]
async fn test_secret_validation_detects_missing_env_vars() {
    use std::collections::HashMap;

    // Set one variable but not others
    std::env::set_var("EXISTING_SECRET_VAR", "value");
    std::env::remove_var("MISSING_SECRET_VAR_1");
    std::env::remove_var("MISSING_SECRET_VAR_2");

    let mut inject_headers = HashMap::new();
    inject_headers.insert(
        "Authorization".to_string(),
        "Bearer ${MISSING_SECRET_VAR_1}".to_string(),
    );
    inject_headers.insert(
        "X-Existing".to_string(),
        "${EXISTING_SECRET_VAR}".to_string(),
    );

    let mut inject_env = HashMap::new();
    inject_env.insert(
        "MISSING_VAR".to_string(),
        "${MISSING_SECRET_VAR_2}".to_string(),
    );
    inject_env.insert(
        "WITH_DEFAULT".to_string(),
        "${ALSO_MISSING:-default}".to_string(),
    ); // Has default, so not missing

    let rules = vec![PolicyRule {
        name: "test-validation".to_string(),
        effect: predicate_authorityd::models::PolicyEffect::Allow,
        principals: vec!["*".to_string()],
        actions: vec!["*".to_string()],
        resources: vec!["*".to_string()],
        max_delegation_depth: None,
        inject_headers: Some(inject_headers),
        inject_headers_from_file: None,
        inject_env: Some(inject_env),
        inject_env_from_file: None,
        required_labels: vec![],
    }];

    let engine = PolicyEngine::new();
    engine.replace_rules(rules);

    // Check which env vars are missing
    let missing = engine.get_missing_secret_references();

    // Should have 2 missing: MISSING_SECRET_VAR_1, MISSING_SECRET_VAR_2
    // (ALSO_MISSING has a default so it's not considered missing)
    assert_eq!(
        missing.len(),
        2,
        "Expected 2 missing vars, got: {:?}",
        missing
    );

    let missing_vars: Vec<&str> = missing.iter().map(|(_, v)| v.as_str()).collect();
    assert!(
        missing_vars.contains(&"MISSING_SECRET_VAR_1"),
        "Should detect MISSING_SECRET_VAR_1"
    );
    assert!(
        missing_vars.contains(&"MISSING_SECRET_VAR_2"),
        "Should detect MISSING_SECRET_VAR_2"
    );

    // Cleanup
    std::env::remove_var("EXISTING_SECRET_VAR");
}

/// Test file-based secret injection for CLI exec
#[tokio::test]
async fn test_secret_injection_from_file() {
    use predicate_authorityd::mandate::MandateStore;
    use predicate_authorityd::models::{MandateClaims, SignedMandate};
    use std::collections::HashMap;
    use std::time::{SystemTime, UNIX_EPOCH};

    // Create temp files with secrets
    let secret_file_path = "/tmp/test_secret_injection.txt";
    std::fs::write(secret_file_path, "file_based_secret_value\n").unwrap();

    // Create policy with inject_env_from_file
    let mut inject_env_from_file = HashMap::new();
    inject_env_from_file.insert("FILE_SECRET".to_string(), secret_file_path.to_string());

    // Also test env var based injection alongside file-based
    let mut inject_env = HashMap::new();
    std::env::set_var("TEST_ENV_SECRET_FILE", "env_based_secret");
    inject_env.insert(
        "ENV_SECRET".to_string(),
        "${TEST_ENV_SECRET_FILE}".to_string(),
    );

    let rules = vec![PolicyRule {
        name: "cli-with-file-injection".to_string(),
        effect: predicate_authorityd::models::PolicyEffect::Allow,
        principals: vec!["*".to_string()],
        actions: vec!["cli.exec".to_string()],
        resources: vec!["*".to_string()],
        max_delegation_depth: None,
        inject_headers: None,
        inject_headers_from_file: None,
        inject_env: Some(inject_env),
        inject_env_from_file: Some(inject_env_from_file),
        required_labels: vec![],
    }];

    let engine = PolicyEngine::new();
    engine.replace_rules(rules);
    let mandate_store = MandateStore::new();

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    // Store a valid mandate
    let mandate = SignedMandate {
        token: "test-token".to_string(),
        claims: MandateClaims {
            mandate_id: "m_file_inject".to_string(),
            principal_id: "agent:test".to_string(),
            action: "cli.exec".to_string(),
            resource: "sh".to_string(),
            scopes: Vec::new(),
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
            jti: Some("m_file_inject".to_string()),
        },
        signature: "test-signature".to_string(),
    };
    mandate_store.store(mandate);

    let state = AppState::new(engine, "local_only").with_mandate_store(mandate_store);
    let app = create_router(state);

    // Execute command that echoes both env vars
    let body = json!({
        "mandate_id": "m_file_inject",
        "action": "cli.exec",
        "resource": "sh",
        "payload": {
            "type": "cli_exec",
            "command": "sh",
            "args": ["-c", "echo FILE_SECRET=$FILE_SECRET ENV_SECRET=$ENV_SECRET"]
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

    assert_eq!(response.status(), StatusCode::OK);

    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let resp: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

    assert_eq!(resp["success"], true);

    let stdout = resp["result"]["stdout"].as_str().unwrap();

    // Verify both injection methods worked
    assert!(
        stdout.contains("file_based_secret_value"),
        "Expected file_based_secret_value in stdout: {}",
        stdout
    );
    assert!(
        stdout.contains("env_based_secret"),
        "Expected env_based_secret in stdout: {}",
        stdout
    );

    // Cleanup
    std::env::remove_var("TEST_ENV_SECRET_FILE");
    std::fs::remove_file(secret_file_path).ok();
}

// --- Issue #26: Policy Reload Authentication Tests ---

#[tokio::test]
async fn test_policy_reload_with_auth_secret() {
    // Test that policy reload requires authentication when secret is configured
    let engine = PolicyEngine::new();
    let state = AppState::new(engine, "local_only")
        .with_policy_reload_secret(Some("test-secret-123".to_string()));
    let app = create_router(state);

    // Without auth header - should fail
    let body = json!({"rules": []});
    let response = app
        .clone()
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

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_policy_reload_with_valid_auth() {
    let engine = PolicyEngine::new();
    let state = AppState::new(engine, "local_only")
        .with_policy_reload_secret(Some("test-secret-123".to_string()));
    let app = create_router(state);

    // With valid auth header - should succeed
    let body = json!({"rules": []});
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/policy/reload")
                .header("content-type", "application/json")
                .header("authorization", "Bearer test-secret-123")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_policy_reload_disabled() {
    let engine = PolicyEngine::new();
    let state = AppState::new(engine, "local_only").with_policy_reload_disabled(true);
    let app = create_router(state);

    // Endpoint should return 404 when disabled
    let body = json!({"rules": []});
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

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

// --- Issue #27: SSRF Whitelist Tests ---

#[tokio::test]
async fn test_ssrf_whitelist_allows_private_ip() {
    use predicate_authorityd::ssrf::SsrfProtection;

    // Create engine with SSRF whitelist
    let engine = PolicyEngine::new();
    let rules = vec![PolicyRule {
        name: "allow-all".to_string(),
        effect: predicate_authorityd::models::PolicyEffect::Allow,
        principals: vec!["*".to_string()],
        actions: vec!["http.fetch".to_string()],
        resources: vec!["*".to_string()],
        max_delegation_depth: None,
        inject_headers: None,
        inject_headers_from_file: None,
        inject_env: None,
        inject_env_from_file: None,
        required_labels: vec![],
    }];
    engine.replace_rules(rules);

    // Configure SSRF whitelist for local Ollama-like service
    let ssrf = SsrfProtection::new().with_allowed_endpoints(vec!["172.30.192.1:11434".to_string()]);
    engine.set_ssrf_protection(Some(ssrf));

    let state = AppState::new(engine, "local_only");
    let app = create_router(state);

    // Request to whitelisted private IP should be allowed
    let body = json!({
        "principal": "agent:test",
        "action": "http.fetch",
        "resource": "http://172.30.192.1:11434/api/generate"
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

    assert_eq!(
        response.status(),
        StatusCode::OK,
        "Whitelisted private IP should be allowed"
    );
}

#[tokio::test]
async fn test_ssrf_blocks_non_whitelisted_private_ip() {
    use predicate_authorityd::ssrf::SsrfProtection;

    let engine = PolicyEngine::new();
    let rules = vec![PolicyRule {
        name: "allow-all".to_string(),
        effect: predicate_authorityd::models::PolicyEffect::Allow,
        principals: vec!["*".to_string()],
        actions: vec!["http.fetch".to_string()],
        resources: vec!["*".to_string()],
        max_delegation_depth: None,
        inject_headers: None,
        inject_headers_from_file: None,
        inject_env: None,
        inject_env_from_file: None,
        required_labels: vec![],
    }];
    engine.replace_rules(rules);

    // Only whitelist one specific port
    let ssrf = SsrfProtection::new().with_allowed_endpoints(vec!["172.30.192.1:11434".to_string()]);
    engine.set_ssrf_protection(Some(ssrf));

    let state = AppState::new(engine, "local_only");
    let app = create_router(state);

    // Request to different port should be blocked
    let body = json!({
        "principal": "agent:test",
        "action": "http.fetch",
        "resource": "http://172.30.192.1:8080/api"
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

    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "Non-whitelisted port should be blocked"
    );
}
