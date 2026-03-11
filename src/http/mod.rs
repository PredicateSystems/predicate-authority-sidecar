//! HTTP server and request handlers for the sidecar daemon.

pub mod delegate;
pub mod execute;

pub use delegate::{delegate_handler, DelegationState};
pub use execute::execute_handler;

use axum::{
    extract::{Json, Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tower_http::cors::{Any, CorsLayer};
use tracing::{debug, info, warn};

use crate::bridge::IdpBridgeProvider;
use crate::identity::{LedgerQueueItem, LocalIdentityRegistry, TaskIdentityRecord};
use crate::mandate::MandateStore;
use crate::models::{
    ActionSpec, AuthorizationDecision, PolicyRule, ScopeAuthorizationResult,
    SidecarAuthorizeRequest, SidecarAuthorizeResponse,
};
use crate::policy::PolicyEngine;
use crate::proof::InMemoryProofLedger;

/// Shared application state
#[derive(Clone)]
pub struct AppState {
    pub policy_engine: Arc<PolicyEngine>,
    pub proof_ledger: Arc<InMemoryProofLedger>,
    pub identity_registry: Option<Arc<LocalIdentityRegistry>>,
    pub idp_bridge: Option<Arc<IdpBridgeProvider>>,
    pub delegation_state: Option<DelegationState>,
    pub mandate_store: Option<Arc<MandateStore>>,
    pub start_time: std::time::Instant,
    pub mode: String,
    pub identity_mode: String,
}

impl AppState {
    pub fn new(policy_engine: PolicyEngine, mode: &str) -> Self {
        Self {
            policy_engine: Arc::new(policy_engine),
            proof_ledger: Arc::new(InMemoryProofLedger::new()),
            identity_registry: None,
            idp_bridge: None,
            delegation_state: None,
            mandate_store: None,
            start_time: std::time::Instant::now(),
            mode: mode.to_string(),
            identity_mode: "local".to_string(),
        }
    }

    pub fn with_identity_registry(mut self, registry: LocalIdentityRegistry) -> Self {
        self.identity_registry = Some(Arc::new(registry));
        self
    }

    pub fn with_idp_bridge(mut self, bridge: IdpBridgeProvider, identity_mode: &str) -> Self {
        self.idp_bridge = Some(Arc::new(bridge));
        self.identity_mode = identity_mode.to_string();
        self
    }

    pub fn with_delegation(mut self, delegation_state: DelegationState) -> Self {
        self.delegation_state = Some(delegation_state);
        self
    }

    pub fn with_mandate_store(mut self, mandate_store: MandateStore) -> Self {
        self.mandate_store = Some(Arc::new(mandate_store));
        self
    }
}

/// Create the HTTP router with all endpoints
pub fn create_router(state: AppState) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let mut router = Router::new()
        // Core authorization
        .route("/v1/authorize", post(authorize_handler))
        .route("/authorize", post(authorize_handler)); // Legacy alias

    // Add delegation endpoint if delegation state is configured
    if let Some(delegation_state) = state.delegation_state.clone() {
        router = router.route(
            "/v1/delegate",
            post(delegate_handler).with_state(delegation_state),
        );
    }

    // Add execute endpoint if mandate store is configured (Phase 5: Execution Proxying)
    if state.mandate_store.is_some() {
        router = router.route("/v1/execute", post(execute_handler));
    }

    router
        // Operations
        .route("/health", get(health_handler))
        .route("/status", get(status_handler))
        .route("/metrics", get(metrics_handler))
        // Policy management
        .route("/policy/reload", post(policy_reload_handler))
        // Identity management
        .route("/identity/task", post(identity_task_handler))
        .route("/identity/revoke", post(identity_revoke_handler))
        .route("/identity/list", get(identity_list_handler))
        // Ledger/queue management
        .route("/ledger/flush-queue", get(ledger_flush_queue_handler))
        .route("/ledger/flush-now", post(ledger_flush_now_handler))
        .route("/ledger/dead-letter", get(ledger_dead_letter_handler))
        .route("/ledger/requeue", post(ledger_requeue_handler))
        // Chain integrity endpoints (Merkle hash chain)
        .route("/ledger/chain-head", get(ledger_chain_head_handler))
        .route("/ledger/verify", get(ledger_verify_handler))
        .layer(cors)
        .with_state(state)
}

/// Create a standalone delegation router.
///
/// This can be merged into an existing router when delegation support is needed.
pub fn create_delegation_router(delegation_state: DelegationState) -> Router<()> {
    Router::new()
        .route("/v1/delegate", post(delegate_handler))
        .with_state(delegation_state)
}

// --- Authorization ---

/// Extract bearer token from Authorization header
fn extract_bearer_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|auth| {
            if auth.to_lowercase().starts_with("bearer ") {
                Some(auth[7..].trim().to_string())
            } else {
                None
            }
        })
}

async fn authorize_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<SidecarAuthorizeRequest>,
) -> impl IntoResponse {
    // Start timing
    let start = std::time::Instant::now();

    // Validate request has at least one scope
    if let Err(e) = request.validate() {
        let response = SidecarAuthorizeResponse {
            allowed: false,
            reason: format!("INVALID_REQUEST: {}", e),
            mandate_id: None,
            mandate_token: None,
            violated_rule: None,
            missing_labels: vec![],
            scopes_authorized: vec![],
        };
        return (StatusCode::BAD_REQUEST, Json(response));
    }

    // Validate bearer token if IdP bridge is configured and requires validation
    if let Some(ref bridge) = state.idp_bridge {
        if bridge.requires_token() {
            let token = match extract_bearer_token(&headers) {
                Some(t) => t,
                None => {
                    debug!(
                        "Authorization denied: missing bearer token for {} mode",
                        state.identity_mode
                    );
                    let response = SidecarAuthorizeResponse {
                        allowed: false,
                        reason: "MISSING_AUTHORIZATION".to_string(),
                        mandate_id: None,
                        mandate_token: None,
                        violated_rule: None,
                        missing_labels: vec![],
                        scopes_authorized: vec![],
                    };
                    return (StatusCode::UNAUTHORIZED, Json(response));
                }
            };

            // Validate the token
            match bridge.validate_token(&token).await {
                Ok(Some(identity)) => {
                    debug!(
                        "Token validated: subject={}, issuer={}, provider={:?}",
                        identity.subject, identity.issuer, identity.provider
                    );
                    // Token is valid - continue with policy evaluation
                    // Optionally: could override request.principal with identity.subject
                }
                Ok(None) => {
                    // Local mode - no token validation needed
                }
                Err(e) => {
                    warn!("Token validation failed: {}", e);
                    let response = SidecarAuthorizeResponse {
                        allowed: false,
                        reason: format!("INVALID_TOKEN: {}", e),
                        mandate_id: None,
                        mandate_token: None,
                        violated_rule: None,
                        missing_labels: vec![],
                        scopes_authorized: vec![],
                    };
                    return (StatusCode::UNAUTHORIZED, Json(response));
                }
            }
        }
    }

    // Get all scopes from request (single or multi)
    let request_scopes = request.all_scopes();
    let is_multi_scope = request.is_multi_scope();

    // For multi-scope requests, evaluate each scope against policy
    // All scopes must be allowed for the request to succeed
    let mut all_allowed = true;
    let mut first_denial_reason = None;
    let mut first_violated_rule = None;
    let mut all_missing_labels: Vec<String> = vec![];
    let mut scopes_authorized: Vec<ScopeAuthorizationResult> = vec![];

    for scope in &request_scopes {
        // Create a single-scope request for policy evaluation
        let single_request = SidecarAuthorizeRequest {
            principal: request.principal.clone(),
            action: scope.action.clone(),
            resource: scope.resource.clone(),
            scopes: vec![],
            intent_hash: request.intent_hash.clone(),
            context: request.context.clone(),
            labels: request.labels.clone(),
        };

        let result = state.policy_engine.evaluate(&single_request);

        if result.allowed {
            scopes_authorized.push(ScopeAuthorizationResult {
                action: scope.action.clone(),
                resource: scope.resource.clone(),
                matched_rule: result.matched_rule.clone(),
            });
        } else {
            all_allowed = false;
            if first_denial_reason.is_none() {
                first_denial_reason = Some(format!(
                    "{} (action: {}, resource: {})",
                    result.reason, scope.action, scope.resource
                ));
                first_violated_rule = result.matched_rule.clone();
            }
            all_missing_labels.extend(result.missing_labels.clone());
        }
    }

    // Calculate latency
    let latency_us = start.elapsed().as_micros() as u64;

    // For audit logging, use first scope as representative (or all scopes in multi-scope case)
    let (audit_action, audit_resource) = if is_multi_scope {
        (
            format!("multi-scope[{}]", request_scopes.len()),
            request_scopes
                .iter()
                .map(|s| s.action.clone())
                .collect::<Vec<_>>()
                .join(","),
        )
    } else {
        (request.action.clone(), request.resource.clone())
    };

    // Record to proof ledger with latency
    state.proof_ledger.record_decision_with_latency(
        &request.principal,
        &audit_action,
        &audit_resource,
        all_allowed,
        if all_allowed {
            crate::models::AuthorizationReason::Allowed
        } else {
            crate::models::AuthorizationReason::ExplicitDeny
        },
        None, // Mandate will be added below
        Some(latency_us),
    );

    // Build response
    let mut decision = AuthorizationDecision {
        allowed: all_allowed,
        reason: if all_allowed {
            crate::models::AuthorizationReason::Allowed
        } else {
            crate::models::AuthorizationReason::ExplicitDeny
        },
        mandate: None,
        violated_rule: first_violated_rule,
        missing_labels: all_missing_labels,
    };

    // If delegation is enabled and authorization allowed, issue a mandate
    if decision.allowed {
        if let Some(ref delegation_state) = state.delegation_state {
            // Build the ActionRequest structure for mandate signing
            let principal_ref = crate::models::PrincipalRef::new(&request.principal);

            // Build ActionSpec - use multi-scope if multiple scopes
            let action_spec = if is_multi_scope {
                ActionSpec::multi(
                    request_scopes.clone(),
                    &request.intent_hash.clone().unwrap_or_default(),
                )
            } else {
                ActionSpec::single(
                    &request.action,
                    &request.resource,
                    &request.intent_hash.clone().unwrap_or_default(),
                )
            };

            let state_evidence =
                crate::models::StateEvidence::new("authorize", &action_spec.action);
            let action_request = crate::models::ActionRequest {
                principal: principal_ref,
                action_spec,
                state_evidence,
                verification_evidence: Default::default(),
            };

            // Issue root mandate (no parent)
            let mandate = delegation_state.mandate_signer.issue(&action_request, None);
            debug!(
                "Issued mandate for {}: mandate_id={}, scopes={}",
                request.principal,
                mandate.claims.mandate_id,
                if is_multi_scope {
                    format!("{} scopes", request_scopes.len())
                } else {
                    "1 scope".to_string()
                }
            );

            // Store mandate in mandate store for /v1/execute endpoint
            if let Some(ref mandate_store) = state.mandate_store {
                mandate_store.store(mandate.clone());
                debug!(
                    "Stored mandate {} for execution proxying",
                    mandate.claims.mandate_id
                );
            }

            decision.mandate = Some(mandate);
        }
    }

    // Build response with scopes_authorized
    let mut response: SidecarAuthorizeResponse = decision.into();

    // Override scopes_authorized with our tracked results
    if all_allowed && !scopes_authorized.is_empty() {
        response.scopes_authorized = scopes_authorized;
    }

    // Override reason with detailed denial reason for multi-scope
    if !all_allowed {
        if let Some(denial_reason) = first_denial_reason {
            response.reason = denial_reason;
        }
    }

    // Return 200 for allowed, 403 for denied (matches Python sidecar behavior)
    let status = if response.allowed {
        StatusCode::OK
    } else {
        StatusCode::FORBIDDEN
    };

    (status, Json(response))
}

// --- Health & Status ---

#[derive(Serialize)]
struct HealthResponse {
    status: String,
    mode: String,
    uptime_s: u64,
}

async fn health_handler(State(state): State<AppState>) -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "healthy".to_string(),
        mode: state.mode.clone(),
        uptime_s: state.start_time.elapsed().as_secs(),
    })
}

#[derive(Serialize)]
struct StatusResponse {
    status: String,
    mode: String,
    identity_mode: String,
    uptime_s: u64,
    rule_count: usize,
    total_allowed: u64,
    total_denied: u64,
    event_count: usize,
}

async fn status_handler(State(state): State<AppState>) -> Json<StatusResponse> {
    let stats = state.proof_ledger.stats();
    Json(StatusResponse {
        status: "healthy".to_string(),
        mode: state.mode.clone(),
        identity_mode: state.identity_mode.clone(),
        uptime_s: state.start_time.elapsed().as_secs(),
        rule_count: state.policy_engine.rule_count(),
        total_allowed: stats.total_allowed,
        total_denied: stats.total_denied,
        event_count: state.proof_ledger.event_count(),
    })
}

// --- Metrics ---

async fn metrics_handler(State(state): State<AppState>) -> String {
    let stats = state.proof_ledger.stats();
    let uptime = state.start_time.elapsed().as_secs();

    let mut output = String::new();

    // Prometheus-style metrics
    output.push_str("# HELP predicate_authority_uptime_seconds Sidecar uptime in seconds\n");
    output.push_str("# TYPE predicate_authority_uptime_seconds counter\n");
    output.push_str(&format!("predicate_authority_uptime_seconds {}\n", uptime));

    output.push_str("# HELP predicate_authority_decisions_total Total authorization decisions\n");
    output.push_str("# TYPE predicate_authority_decisions_total counter\n");
    output.push_str(&format!(
        "predicate_authority_decisions_total{{result=\"allowed\"}} {}\n",
        stats.total_allowed
    ));
    output.push_str(&format!(
        "predicate_authority_decisions_total{{result=\"denied\"}} {}\n",
        stats.total_denied
    ));

    output.push_str("# HELP predicate_authority_denials_by_reason Denials by reason\n");
    output.push_str("# TYPE predicate_authority_denials_by_reason counter\n");
    for (reason, count) in &stats.denied_by_reason {
        output.push_str(&format!(
            "predicate_authority_denials_by_reason{{reason=\"{}\"}} {}\n",
            reason, count
        ));
    }

    output.push_str("# HELP predicate_authority_policy_rules Number of policy rules\n");
    output.push_str("# TYPE predicate_authority_policy_rules gauge\n");
    output.push_str(&format!(
        "predicate_authority_policy_rules {}\n",
        state.policy_engine.rule_count()
    ));

    output
}

// --- Policy Management ---

#[derive(Deserialize)]
struct PolicyReloadRequest {
    #[serde(default)]
    rules: Vec<PolicyRule>,
}

#[derive(Serialize)]
struct PolicyReloadResponse {
    success: bool,
    rule_count: usize,
    message: String,
}

async fn policy_reload_handler(
    State(state): State<AppState>,
    Json(request): Json<PolicyReloadRequest>,
) -> Json<PolicyReloadResponse> {
    let rule_count = request.rules.len();

    info!("Reloading policy with {} rules", rule_count);
    state.policy_engine.replace_rules(request.rules);

    Json(PolicyReloadResponse {
        success: true,
        rule_count,
        message: format!("Loaded {} rules", rule_count),
    })
}

// --- Identity Management ---

#[derive(Deserialize)]
struct IdentityTaskRequest {
    principal_id: String,
    task_id: String,
    ttl_seconds: Option<i64>,
    #[serde(default)]
    metadata: HashMap<String, String>,
}

#[derive(Serialize)]
struct IdentityTaskResponse {
    success: bool,
    identity: Option<TaskIdentityRecord>,
    error: Option<String>,
}

async fn identity_task_handler(
    State(state): State<AppState>,
    Json(request): Json<IdentityTaskRequest>,
) -> impl IntoResponse {
    let registry = match &state.identity_registry {
        Some(r) => r,
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(IdentityTaskResponse {
                    success: false,
                    identity: None,
                    error: Some("Local identity registry not enabled".to_string()),
                }),
            );
        }
    };

    let metadata = if request.metadata.is_empty() {
        None
    } else {
        Some(request.metadata)
    };

    match registry.issue_task_identity(
        &request.principal_id,
        &request.task_id,
        request.ttl_seconds,
        metadata,
    ) {
        Ok(identity) => (
            StatusCode::OK,
            Json(IdentityTaskResponse {
                success: true,
                identity: Some(identity),
                error: None,
            }),
        ),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(IdentityTaskResponse {
                success: false,
                identity: None,
                error: Some(e.to_string()),
            }),
        ),
    }
}

#[derive(Deserialize)]
struct IdentityRevokeRequest {
    identity_id: String,
}

#[derive(Serialize)]
struct IdentityRevokeResponse {
    success: bool,
    error: Option<String>,
}

async fn identity_revoke_handler(
    State(state): State<AppState>,
    Json(request): Json<IdentityRevokeRequest>,
) -> impl IntoResponse {
    let registry = match &state.identity_registry {
        Some(r) => r,
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(IdentityRevokeResponse {
                    success: false,
                    error: Some("Local identity registry not enabled".to_string()),
                }),
            );
        }
    };

    if registry.revoke_identity(&request.identity_id) {
        (
            StatusCode::OK,
            Json(IdentityRevokeResponse {
                success: true,
                error: None,
            }),
        )
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(IdentityRevokeResponse {
                success: false,
                error: Some("Identity not found".to_string()),
            }),
        )
    }
}

#[derive(Deserialize)]
struct IdentityListQuery {
    #[serde(default)]
    include_revoked: bool,
    #[serde(default)]
    include_expired: bool,
}

#[derive(Serialize)]
struct IdentityListResponse {
    identities: Vec<TaskIdentityRecord>,
    count: usize,
}

async fn identity_list_handler(
    State(state): State<AppState>,
    Query(query): Query<IdentityListQuery>,
) -> impl IntoResponse {
    let registry = match &state.identity_registry {
        Some(r) => r,
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(IdentityListResponse {
                    identities: vec![],
                    count: 0,
                }),
            );
        }
    };

    let identities = registry.list_identities(query.include_revoked, query.include_expired);
    let count = identities.len();

    (
        StatusCode::OK,
        Json(IdentityListResponse { identities, count }),
    )
}

// --- Ledger/Queue Management ---

#[derive(Deserialize)]
struct FlushQueueQuery {
    #[serde(default)]
    include_flushed: bool,
    #[serde(default)]
    include_quarantined: bool,
    limit: Option<usize>,
    #[serde(default = "default_true_for_redact")]
    redact_payloads: bool,
}

fn default_true_for_redact() -> bool {
    true
}

#[derive(Serialize)]
struct FlushQueueResponse {
    items: Vec<LedgerQueueItem>,
    count: usize,
}

async fn ledger_flush_queue_handler(
    State(state): State<AppState>,
    Query(query): Query<FlushQueueQuery>,
) -> impl IntoResponse {
    let registry = match &state.identity_registry {
        Some(r) => r,
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(FlushQueueResponse {
                    items: vec![],
                    count: 0,
                }),
            );
        }
    };

    let items = registry.list_flush_queue(
        query.include_flushed,
        query.include_quarantined,
        query.limit,
        query.redact_payloads,
    );
    let count = items.len();

    (StatusCode::OK, Json(FlushQueueResponse { items, count }))
}

#[derive(Deserialize)]
struct FlushNowRequest {
    max_items: Option<usize>,
}

#[derive(Serialize)]
struct FlushNowResponse {
    success: bool,
    scanned: usize,
    message: String,
}

async fn ledger_flush_now_handler(
    State(state): State<AppState>,
    Json(request): Json<FlushNowRequest>,
) -> impl IntoResponse {
    let registry = match &state.identity_registry {
        Some(r) => r,
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(FlushNowResponse {
                    success: false,
                    scanned: 0,
                    message: "Local identity registry not enabled".to_string(),
                }),
            );
        }
    };

    // Get pending items
    let items = registry.list_flush_queue(false, false, request.max_items, false);
    let scanned = items.len();

    // In local_only mode, just mark them as flushed (no control-plane to send to)
    for item in &items {
        registry.mark_flush_ack(&item.queue_item_id);
    }

    (
        StatusCode::OK,
        Json(FlushNowResponse {
            success: true,
            scanned,
            message: format!("Flushed {} items", scanned),
        }),
    )
}

#[derive(Deserialize)]
struct DeadLetterQuery {
    limit: Option<usize>,
    #[serde(default = "default_true_for_redact")]
    redact_payloads: bool,
}

async fn ledger_dead_letter_handler(
    State(state): State<AppState>,
    Query(query): Query<DeadLetterQuery>,
) -> impl IntoResponse {
    let registry = match &state.identity_registry {
        Some(r) => r,
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(FlushQueueResponse {
                    items: vec![],
                    count: 0,
                }),
            );
        }
    };

    let items = registry.list_dead_letter_queue(query.limit, query.redact_payloads);
    let count = items.len();

    (StatusCode::OK, Json(FlushQueueResponse { items, count }))
}

#[derive(Deserialize)]
struct RequeueRequest {
    queue_item_id: String,
    #[serde(default = "default_true_for_reset")]
    reset_attempts: bool,
}

fn default_true_for_reset() -> bool {
    true
}

#[derive(Serialize)]
struct RequeueResponse {
    success: bool,
    error: Option<String>,
}

async fn ledger_requeue_handler(
    State(state): State<AppState>,
    Json(request): Json<RequeueRequest>,
) -> impl IntoResponse {
    let registry = match &state.identity_registry {
        Some(r) => r,
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(RequeueResponse {
                    success: false,
                    error: Some("Local identity registry not enabled".to_string()),
                }),
            );
        }
    };

    if registry.requeue_item(&request.queue_item_id, request.reset_attempts) {
        (
            StatusCode::OK,
            Json(RequeueResponse {
                success: true,
                error: None,
            }),
        )
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(RequeueResponse {
                success: false,
                error: Some("Queue item not found or not quarantined".to_string()),
            }),
        )
    }
}

// --- Chain Integrity Endpoints (Merkle Hash Chain) ---

use crate::proof::ChainHead;

/// Get the current chain head for verification.
/// This allows external systems (control plane) to verify the integrity of the audit trail.
async fn ledger_chain_head_handler(State(state): State<AppState>) -> Json<ChainHead> {
    Json(state.proof_ledger.chain_head())
}

#[derive(Serialize)]
struct ChainVerifyResponse {
    valid: bool,
    chain_hash: String,
    event_count: u64,
    message: String,
}

/// Verify the integrity of the local hash chain.
/// Returns true if no tampering is detected.
async fn ledger_verify_handler(State(state): State<AppState>) -> Json<ChainVerifyResponse> {
    let valid = state.proof_ledger.verify_chain();
    let head = state.proof_ledger.chain_head();

    Json(ChainVerifyResponse {
        valid,
        chain_hash: head.chain_hash,
        event_count: head.event_count,
        message: if valid {
            "Chain integrity verified".to_string()
        } else {
            "TAMPERING DETECTED: Chain integrity check failed".to_string()
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use tower::util::ServiceExt;

    use crate::mandate::{LocalMandateSigner, SigningAlgorithm};
    use crate::models::{PolicyEffect, PolicyRule};

    fn test_state() -> AppState {
        AppState::new(PolicyEngine::new(), "test")
    }

    fn test_signer() -> LocalMandateSigner {
        LocalMandateSigner::new(
            "test-delegation-secret-key-minimum-32-chars",
            300,
            SigningAlgorithm::HS256,
            true,
            None,
            None,
        )
    }

    fn test_state_with_delegation() -> AppState {
        let delegation_state = DelegationState::new(test_signer()).with_max_depth(5);
        AppState::new(PolicyEngine::new(), "test").with_delegation(delegation_state)
    }

    fn test_state_with_policy_and_delegation() -> AppState {
        let rules = vec![PolicyRule {
            name: "allow-test-agent".to_string(),
            effect: PolicyEffect::Allow,
            principals: vec!["agent:test".to_string()],
            actions: vec!["test.action".to_string()],
            resources: vec!["test://resource".to_string()],
            required_labels: vec![],
            max_delegation_depth: None,
        }];
        let policy = PolicyEngine::with_rules(rules);
        // Disable SSRF protection for test URLs
        policy.set_ssrf_protection(None);

        let delegation_state = DelegationState::new(test_signer()).with_max_depth(5);
        AppState::new(policy, "test").with_delegation(delegation_state)
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
    async fn test_authorize_no_rules_returns_403() {
        let app = create_router(test_state());

        let body = r#"{"principal": "agent:test", "action": "test.action", "resource": "test://resource"}"#;

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/authorize")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_authorize_with_delegation_returns_mandate_token() {
        let app = create_router(test_state_with_policy_and_delegation());

        let body = r#"{"principal": "agent:test", "action": "test.action", "resource": "test://resource"}"#;

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/authorize")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        // Parse response body
        let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
        let response_json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

        // Verify mandate_token is present when delegation is enabled
        assert!(response_json["allowed"].as_bool().unwrap());
        assert!(response_json["mandate_token"].is_string());
        assert!(!response_json["mandate_token"].as_str().unwrap().is_empty());
        assert!(response_json["mandate_id"].is_string());
        assert!(!response_json["mandate_id"].as_str().unwrap().is_empty());

        // Mandate token should be a JWT (has 3 parts separated by dots)
        let mandate_token = response_json["mandate_token"].as_str().unwrap();
        assert_eq!(
            mandate_token.split('.').count(),
            3,
            "mandate_token should be a JWT"
        );
    }

    #[tokio::test]
    async fn test_authorize_without_delegation_no_mandate_token() {
        // Create state with policy but NO delegation
        let rules = vec![PolicyRule {
            name: "allow-test-agent".to_string(),
            effect: PolicyEffect::Allow,
            principals: vec!["agent:test".to_string()],
            actions: vec!["test.action".to_string()],
            resources: vec!["test://resource".to_string()],
            required_labels: vec![],
            max_delegation_depth: None,
        }];
        let policy = PolicyEngine::with_rules(rules);
        policy.set_ssrf_protection(None);
        let state = AppState::new(policy, "test");

        let app = create_router(state);

        let body = r#"{"principal": "agent:test", "action": "test.action", "resource": "test://resource"}"#;

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/authorize")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        // Parse response body
        let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
        let response_json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

        // Verify mandate_token is null when delegation is NOT enabled
        assert!(response_json["allowed"].as_bool().unwrap());
        assert!(response_json["mandate_token"].is_null());
        assert!(response_json["mandate_id"].is_null());
    }

    #[tokio::test]
    async fn test_authorize_denied_no_mandate_token() {
        // Delegation enabled but authorization denied - should not issue mandate
        let app = create_router(test_state_with_delegation());

        let body = r#"{"principal": "agent:test", "action": "test.action", "resource": "test://resource"}"#;

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/authorize")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        // Parse response body
        let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
        let response_json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

        // Verify no mandate token when authorization denied
        assert!(!response_json["allowed"].as_bool().unwrap());
        assert!(response_json["mandate_token"].is_null());
        assert!(response_json["mandate_id"].is_null());
    }

    // --- Multi-scope authorization tests ---

    fn test_state_with_multi_scope_policy() -> AppState {
        let rules = vec![
            PolicyRule {
                name: "allow-browser".to_string(),
                effect: PolicyEffect::Allow,
                principals: vec!["agent:orchestrator".to_string()],
                actions: vec!["browser.*".to_string()],
                resources: vec!["https://amazon.com/*".to_string()],
                required_labels: vec![],
                max_delegation_depth: None,
            },
            PolicyRule {
                name: "allow-fs".to_string(),
                effect: PolicyEffect::Allow,
                principals: vec!["agent:orchestrator".to_string()],
                actions: vec!["fs.*".to_string()],
                resources: vec!["/workspace/**".to_string()],
                required_labels: vec![],
                max_delegation_depth: None,
            },
        ];
        let policy = PolicyEngine::with_rules(rules);
        policy.set_ssrf_protection(None);

        let delegation_state = DelegationState::new(test_signer()).with_max_depth(5);
        AppState::new(policy, "test").with_delegation(delegation_state)
    }

    #[tokio::test]
    async fn test_authorize_multi_scope_all_allowed() {
        let app = create_router(test_state_with_multi_scope_policy());

        let body = r#"{
            "principal": "agent:orchestrator",
            "scopes": [
                {"action": "browser.navigate", "resource": "https://amazon.com/products"},
                {"action": "fs.write", "resource": "/workspace/data/output.json"}
            ],
            "intent_hash": "orchestrate:ecommerce:123"
        }"#;

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/authorize")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
        let response_json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

        assert!(response_json["allowed"].as_bool().unwrap());
        assert!(response_json["mandate_token"].is_string());
        assert!(!response_json["mandate_token"].as_str().unwrap().is_empty());

        // Verify scopes_authorized contains both scopes
        let scopes_authorized = response_json["scopes_authorized"].as_array().unwrap();
        assert_eq!(scopes_authorized.len(), 2);
    }

    #[tokio::test]
    async fn test_authorize_multi_scope_partial_denied() {
        let app = create_router(test_state_with_multi_scope_policy());

        // One scope allowed, one denied (network.* not in policy)
        let body = r#"{
            "principal": "agent:orchestrator",
            "scopes": [
                {"action": "browser.navigate", "resource": "https://amazon.com/products"},
                {"action": "network.connect", "resource": "tcp://internal:3306"}
            ],
            "intent_hash": "orchestrate:mixed:123"
        }"#;

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/authorize")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
        let response_json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

        assert!(!response_json["allowed"].as_bool().unwrap());
        assert!(response_json["mandate_token"].is_null());
        // Reason should mention which scope failed
        assert!(response_json["reason"]
            .as_str()
            .unwrap()
            .contains("network.connect"));
    }

    #[tokio::test]
    async fn test_authorize_empty_request_returns_400() {
        let app = create_router(test_state_with_multi_scope_policy());

        // No action or scopes provided
        let body = r#"{"principal": "agent:orchestrator"}"#;

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/authorize")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
        let response_json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

        assert!(!response_json["allowed"].as_bool().unwrap());
        assert!(response_json["reason"]
            .as_str()
            .unwrap()
            .contains("INVALID_REQUEST"));
    }

    #[tokio::test]
    async fn test_authorize_single_scope_still_works() {
        let app = create_router(test_state_with_multi_scope_policy());

        // Traditional single-scope request (backward compatible)
        let body = r#"{
            "principal": "agent:orchestrator",
            "action": "browser.click",
            "resource": "https://amazon.com/buy-button"
        }"#;

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/authorize")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
        let response_json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

        assert!(response_json["allowed"].as_bool().unwrap());
        assert!(response_json["mandate_token"].is_string());
    }
}
