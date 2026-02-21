//! Identity provider bridge implementations.
//!
//! Provides token exchange and validation for various identity providers:
//! - Local (development/offline mode)
//! - OIDC (generic OpenID Connect)
//! - Okta (with JWKS validation)
//! - Entra (Microsoft Entra ID)
//!
//! Note: Many types here are defined for future HTTP endpoint integration (Phase 5).

#![allow(dead_code)]

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use hmac::{Hmac, Mac};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;

use crate::models::{PrincipalRef, StateEvidence};

type HmacSha256 = Hmac<Sha256>;

/// Identity provider type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IdentityProviderType {
    Local,
    LocalIdp,
    Oidc,
    Entra,
    Okta,
}

/// Token exchange result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenExchangeResult {
    pub access_token: String,
    pub expires_at_epoch_s: i64,
    #[serde(default = "default_bearer")]
    pub token_type: String,
    pub provider: IdentityProviderType,
}

fn default_bearer() -> String {
    "Bearer".to_string()
}

/// Token validation error
#[derive(Debug, Clone, thiserror::Error)]
pub enum TokenValidationError {
    #[error("Token must be a 3-segment JWT")]
    InvalidFormat,
    #[error("Token segment is not valid base64url JSON")]
    InvalidEncoding,
    #[error("Token header missing required algorithm: alg")]
    MissingAlgorithm,
    #[error("Token algorithm 'none' is not allowed")]
    AlgorithmNone,
    #[error("Token algorithm is not in allowlist")]
    AlgorithmNotAllowed,
    #[error("Token missing required issuer claim: iss")]
    MissingIssuer,
    #[error("Token issuer mismatch")]
    IssuerMismatch,
    #[error("Token audience mismatch")]
    AudienceMismatch,
    #[error("Token missing required claim: {0}")]
    MissingClaim(String),
    #[error("Token claim is empty: {0}")]
    EmptyClaim(String),
    #[error("Token is expired")]
    Expired,
    #[error("Token not yet valid (nbf)")]
    NotYetValid,
    #[error("Token issued-at time is in the future")]
    IssuedInFuture,
    #[error("Token tenant is not in configured allow-list")]
    TenantNotAllowed,
    #[error("Token missing required scope")]
    MissingScope,
    #[error("Token missing required role/group")]
    MissingRole,
    #[error("Token header missing required key id: kid")]
    MissingKid,
    #[error("No JWKS key found for kid: {0}")]
    KeyNotFound(String),
    #[error("JWKS fetch failed: {0}")]
    JwksFetchFailed(String),
    #[error("JWKS response missing keys array")]
    JwksMissingKeys,
    #[error("JWKS response contains no usable kid entries")]
    JwksNoUsableKeys,
    #[error("No JWKS endpoint configured")]
    NoJwksEndpoint,
}

/// Okta bridge configuration
#[derive(Debug, Clone)]
pub struct OktaBridgeConfig {
    pub issuer: String,
    pub client_id: String,
    pub audience: String,
    pub token_ttl_seconds: i64,
    pub required_claims: Vec<String>,
    pub allowed_signing_algs: Vec<String>,
    pub clock_skew_leeway_seconds: i64,
    pub tenant_claim: String,
    pub scope_claim: String,
    pub role_claim: String,
    pub allowed_tenants: Vec<String>,
    pub required_scopes: Vec<String>,
    pub required_roles: Vec<String>,
    pub enable_jwks_validation: bool,
    pub jwks_url: Option<String>,
    pub discovery_url: Option<String>,
    pub jwks_cache_ttl_seconds: i64,
    pub jwks_timeout_s: f64,
    pub jwks_max_retries: u32,
    pub jwks_backoff_initial_s: f64,
}

impl Default for OktaBridgeConfig {
    fn default() -> Self {
        Self {
            issuer: String::new(),
            client_id: String::new(),
            audience: String::new(),
            token_ttl_seconds: 300,
            required_claims: vec!["sub".to_string()],
            allowed_signing_algs: vec!["RS256".to_string()],
            clock_skew_leeway_seconds: 30,
            tenant_claim: "tenant_id".to_string(),
            scope_claim: "scope".to_string(),
            role_claim: "groups".to_string(),
            allowed_tenants: vec![],
            required_scopes: vec![],
            required_roles: vec![],
            enable_jwks_validation: false,
            jwks_url: None,
            discovery_url: None,
            jwks_cache_ttl_seconds: 300,
            jwks_timeout_s: 1.0,
            jwks_max_retries: 1,
            jwks_backoff_initial_s: 0.1,
        }
    }
}

/// OIDC bridge configuration
#[derive(Debug, Clone)]
pub struct OidcBridgeConfig {
    pub issuer: String,
    pub client_id: String,
    pub audience: String,
    pub token_ttl_seconds: i64,
}

/// Entra bridge configuration
#[derive(Debug, Clone)]
pub struct EntraBridgeConfig {
    pub tenant_id: String,
    pub client_id: String,
    pub audience: String,
    pub token_ttl_seconds: i64,
}

/// Local IdP bridge configuration
#[derive(Debug, Clone)]
pub struct LocalIdpBridgeConfig {
    pub issuer: String,
    pub audience: String,
    pub signing_key: String,
    pub token_ttl_seconds: i64,
}

impl Default for LocalIdpBridgeConfig {
    fn default() -> Self {
        Self {
            issuer: "http://localhost/predicate-local-idp".to_string(),
            audience: "api://predicate-authority".to_string(),
            signing_key: "predicate-local-idp-dev-key".to_string(),
            token_ttl_seconds: 300,
        }
    }
}

/// Okta token claims
#[derive(Debug, Clone)]
pub struct OktaTokenClaims {
    pub issuer: String,
    pub subject: String,
    pub audience: Vec<String>,
    pub claims: HashMap<String, serde_json::Value>,
}

/// JWKS cache state
struct JwksCacheState {
    expires_at_epoch_s: i64,
    keys_by_kid: HashMap<String, serde_json::Value>,
}

/// Local identity bridge (development mode)
pub struct LocalIdentityBridge {
    token_ttl_seconds: i64,
}

impl LocalIdentityBridge {
    pub fn new(token_ttl_seconds: i64) -> Self {
        Self { token_ttl_seconds }
    }

    pub fn exchange_token(
        &self,
        subject: &PrincipalRef,
        state_evidence: &StateEvidence,
    ) -> TokenExchangeResult {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let expires_at = now + self.token_ttl_seconds;

        let token_seed = format!(
            "{}|{}|{}",
            subject.principal_id, state_evidence.state_hash, expires_at
        );
        let hash = hex::encode(Sha256::digest(token_seed.as_bytes()));

        TokenExchangeResult {
            access_token: format!("local.{}", hash),
            expires_at_epoch_s: expires_at,
            token_type: "Bearer".to_string(),
            provider: IdentityProviderType::Local,
        }
    }
}

/// Generic OIDC identity bridge
pub struct OidcIdentityBridge {
    config: OidcBridgeConfig,
}

impl OidcIdentityBridge {
    pub fn new(config: OidcBridgeConfig) -> Self {
        Self { config }
    }

    pub fn exchange_token(
        &self,
        subject: &PrincipalRef,
        state_evidence: &StateEvidence,
    ) -> TokenExchangeResult {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let expires_at = now + self.config.token_ttl_seconds;

        let token_seed = format!(
            "{}|{}|{}|{}|{}|{}",
            self.config.issuer,
            self.config.client_id,
            self.config.audience,
            subject.principal_id,
            state_evidence.state_hash,
            expires_at
        );
        let hash = hex::encode(Sha256::digest(token_seed.as_bytes()));

        TokenExchangeResult {
            access_token: format!("oidc.{}", hash),
            expires_at_epoch_s: expires_at,
            token_type: "Bearer".to_string(),
            provider: IdentityProviderType::Oidc,
        }
    }

    pub fn refresh_token(
        &self,
        refresh_token: &str,
        subject: &PrincipalRef,
        state_evidence: &StateEvidence,
    ) -> TokenExchangeResult {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let expires_at = now + self.config.token_ttl_seconds;

        let token_seed = format!(
            "{}|{}|{}|{}|{}",
            refresh_token,
            self.config.issuer,
            subject.principal_id,
            state_evidence.state_hash,
            expires_at
        );
        let hash = hex::encode(Sha256::digest(token_seed.as_bytes()));

        TokenExchangeResult {
            access_token: format!("oidc-refresh.{}", hash),
            expires_at_epoch_s: expires_at,
            token_type: "Bearer".to_string(),
            provider: IdentityProviderType::Oidc,
        }
    }
}

/// Microsoft Entra identity bridge
pub struct EntraIdentityBridge {
    inner: OidcIdentityBridge,
}

impl EntraIdentityBridge {
    pub fn new(config: EntraBridgeConfig) -> Self {
        let oidc_config = OidcBridgeConfig {
            issuer: format!(
                "https://login.microsoftonline.com/{}/v2.0",
                config.tenant_id
            ),
            client_id: config.client_id,
            audience: config.audience,
            token_ttl_seconds: config.token_ttl_seconds,
        };
        Self {
            inner: OidcIdentityBridge::new(oidc_config),
        }
    }

    pub fn exchange_token(
        &self,
        subject: &PrincipalRef,
        state_evidence: &StateEvidence,
    ) -> TokenExchangeResult {
        let mut result = self.inner.exchange_token(subject, state_evidence);
        result.provider = IdentityProviderType::Entra;
        result
    }
}

/// Okta identity bridge with JWKS validation
pub struct OktaIdentityBridge {
    config: OktaBridgeConfig,
    inner: OidcIdentityBridge,
    http_client: Client,
    jwks_cache: Arc<RwLock<Option<JwksCacheState>>>,
}

impl OktaIdentityBridge {
    pub fn new(config: OktaBridgeConfig) -> Result<Self, String> {
        if config.enable_jwks_validation
            && config.jwks_url.is_none()
            && config.discovery_url.is_none()
        {
            return Err(
                "Okta JWKS validation is enabled but no jwks_url/discovery_url configured"
                    .to_string(),
            );
        }

        let oidc_config = OidcBridgeConfig {
            issuer: config.issuer.clone(),
            client_id: config.client_id.clone(),
            audience: config.audience.clone(),
            token_ttl_seconds: config.token_ttl_seconds,
        };

        let http_client = Client::builder()
            .timeout(Duration::from_secs_f64(config.jwks_timeout_s))
            .build()
            .map_err(|e| format!("Failed to create HTTP client: {}", e))?;

        Ok(Self {
            config,
            inner: OidcIdentityBridge::new(oidc_config),
            http_client,
            jwks_cache: Arc::new(RwLock::new(None)),
        })
    }

    pub fn exchange_token(
        &self,
        subject: &PrincipalRef,
        state_evidence: &StateEvidence,
    ) -> TokenExchangeResult {
        let mut result = self.inner.exchange_token(subject, state_evidence);
        result.provider = IdentityProviderType::Okta;
        result
    }

    /// Validate token claims
    pub async fn validate_token_claims(
        &self,
        token: &str,
        now_epoch_s: Option<i64>,
    ) -> Result<OktaTokenClaims, TokenValidationError> {
        let (header, payload) = decode_jwt_parts(token)?;

        // Validate algorithm
        let alg = header
            .get("alg")
            .and_then(|v| v.as_str())
            .ok_or(TokenValidationError::MissingAlgorithm)?;

        if alg.to_lowercase() == "none" {
            return Err(TokenValidationError::AlgorithmNone);
        }

        if !self.config.allowed_signing_algs.contains(&alg.to_string()) {
            return Err(TokenValidationError::AlgorithmNotAllowed);
        }

        // Validate JWKS kid if enabled
        self.validate_jwks_kid(&header, now_epoch_s).await?;

        // Validate issuer
        let issuer = payload
            .get("iss")
            .and_then(|v| v.as_str())
            .ok_or(TokenValidationError::MissingIssuer)?;

        if issuer != self.config.issuer {
            return Err(TokenValidationError::IssuerMismatch);
        }

        // Validate audience
        let audiences = normalize_audience(payload.get("aud"));
        if !audiences.contains(&self.config.audience) {
            return Err(TokenValidationError::AudienceMismatch);
        }

        // Validate required claims
        for claim_name in &self.config.required_claims {
            let claim_value = payload.get(claim_name);
            if claim_value.is_none() {
                return Err(TokenValidationError::MissingClaim(claim_name.clone()));
            }
            if let Some(s) = claim_value.and_then(|v| v.as_str()) {
                if s.trim().is_empty() {
                    return Err(TokenValidationError::EmptyClaim(claim_name.clone()));
                }
            }
        }

        // Validate subject
        let subject = payload
            .get("sub")
            .and_then(|v| v.as_str())
            .ok_or(TokenValidationError::MissingClaim("sub".to_string()))?;

        if subject.trim().is_empty() {
            return Err(TokenValidationError::EmptyClaim("sub".to_string()));
        }

        // Validate temporal claims
        self.validate_temporal_claims(&payload, now_epoch_s)?;

        // Validate tenant/scope/role guards
        self.validate_tenant_scope_role_guards(&payload)?;

        Ok(OktaTokenClaims {
            issuer: issuer.to_string(),
            subject: subject.to_string(),
            audience: audiences,
            claims: payload
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
        })
    }

    fn validate_temporal_claims(
        &self,
        payload: &HashMap<String, serde_json::Value>,
        now_epoch_s: Option<i64>,
    ) -> Result<(), TokenValidationError> {
        let now = now_epoch_s.unwrap_or_else(|| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64
        });
        let leeway = self.config.clock_skew_leeway_seconds.max(0);

        let exp = payload
            .get("exp")
            .and_then(|v| v.as_i64())
            .ok_or(TokenValidationError::MissingClaim("exp".to_string()))?;

        let iat = payload
            .get("iat")
            .and_then(|v| v.as_i64())
            .ok_or(TokenValidationError::MissingClaim("iat".to_string()))?;

        let nbf = payload.get("nbf").and_then(|v| v.as_i64());

        if exp < now - leeway {
            return Err(TokenValidationError::Expired);
        }

        if let Some(nbf_val) = nbf {
            if nbf_val > now + leeway {
                return Err(TokenValidationError::NotYetValid);
            }
        }

        if iat > now + leeway {
            return Err(TokenValidationError::IssuedInFuture);
        }

        Ok(())
    }

    fn validate_tenant_scope_role_guards(
        &self,
        payload: &HashMap<String, serde_json::Value>,
    ) -> Result<(), TokenValidationError> {
        // Tenant validation
        if !self.config.allowed_tenants.is_empty() {
            let tenant_value = payload
                .get(&self.config.tenant_claim)
                .and_then(|v| v.as_str());

            match tenant_value {
                Some(t) if !t.trim().is_empty() => {
                    if !self.config.allowed_tenants.contains(&t.to_string()) {
                        return Err(TokenValidationError::TenantNotAllowed);
                    }
                }
                _ => {
                    return Err(TokenValidationError::MissingClaim(
                        self.config.tenant_claim.clone(),
                    ));
                }
            }
        }

        // Scope validation
        let scopes = normalize_string_collection(payload.get(&self.config.scope_claim));
        for required_scope in &self.config.required_scopes {
            if !scopes.contains(required_scope) {
                return Err(TokenValidationError::MissingScope);
            }
        }

        // Role validation
        let roles = normalize_string_collection(payload.get(&self.config.role_claim));
        for required_role in &self.config.required_roles {
            if !roles.contains(required_role) {
                return Err(TokenValidationError::MissingRole);
            }
        }

        Ok(())
    }

    async fn validate_jwks_kid(
        &self,
        header: &HashMap<String, serde_json::Value>,
        now_epoch_s: Option<i64>,
    ) -> Result<(), TokenValidationError> {
        if !self.config.enable_jwks_validation {
            return Ok(());
        }

        let kid = header
            .get("kid")
            .and_then(|v| v.as_str())
            .ok_or(TokenValidationError::MissingKid)?;

        if kid.trim().is_empty() {
            return Err(TokenValidationError::MissingKid);
        }

        let now = now_epoch_s.unwrap_or_else(|| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64
        });

        let key = self.get_key_for_kid(kid, now).await?;
        if key.is_none() {
            return Err(TokenValidationError::KeyNotFound(kid.to_string()));
        }

        Ok(())
    }

    async fn get_key_for_kid(
        &self,
        kid: &str,
        now_epoch_s: i64,
    ) -> Result<Option<serde_json::Value>, TokenValidationError> {
        // Check cache
        {
            let cache = self.jwks_cache.read().await;
            if let Some(ref state) = *cache {
                if now_epoch_s <= state.expires_at_epoch_s {
                    if let Some(key) = state.keys_by_kid.get(kid) {
                        return Ok(Some(key.clone()));
                    }
                }
            }
        }

        // Fetch and cache
        let keys = self.fetch_jwks_keys_with_retry().await?;

        let expires_at = now_epoch_s + self.config.jwks_cache_ttl_seconds.max(1);
        *self.jwks_cache.write().await = Some(JwksCacheState {
            expires_at_epoch_s: expires_at,
            keys_by_kid: keys.clone(),
        });

        Ok(keys.get(kid).cloned())
    }

    async fn fetch_jwks_keys_with_retry(
        &self,
    ) -> Result<HashMap<String, serde_json::Value>, TokenValidationError> {
        let mut attempts = self.config.jwks_max_retries + 1;
        let mut last_error = String::new();

        while attempts > 0 {
            match self.fetch_jwks_keys_once().await {
                Ok(keys) => return Ok(keys),
                Err(e) => {
                    last_error = e.to_string();
                    attempts -= 1;
                    if attempts > 0 {
                        let backoff = self.config.jwks_backoff_initial_s
                            * 2f64.powi((self.config.jwks_max_retries - attempts) as i32);
                        tokio::time::sleep(Duration::from_secs_f64(backoff)).await;
                    }
                }
            }
        }

        Err(TokenValidationError::JwksFetchFailed(last_error))
    }

    async fn fetch_jwks_keys_once(
        &self,
    ) -> Result<HashMap<String, serde_json::Value>, TokenValidationError> {
        let jwks_url = self.resolve_jwks_url().await?;

        let response = self
            .http_client
            .get(&jwks_url)
            .send()
            .await
            .map_err(|e| TokenValidationError::JwksFetchFailed(e.to_string()))?;

        if !response.status().is_success() {
            return Err(TokenValidationError::JwksFetchFailed(format!(
                "HTTP {}",
                response.status()
            )));
        }

        let payload: serde_json::Value = response
            .json()
            .await
            .map_err(|e| TokenValidationError::JwksFetchFailed(e.to_string()))?;

        let keys = payload
            .get("keys")
            .and_then(|v| v.as_array())
            .ok_or(TokenValidationError::JwksMissingKeys)?;

        let mut keys_by_kid = HashMap::new();
        for key in keys {
            if let Some(kid) = key.get("kid").and_then(|v| v.as_str()) {
                if !kid.is_empty() {
                    keys_by_kid.insert(kid.to_string(), key.clone());
                }
            }
        }

        if keys_by_kid.is_empty() {
            return Err(TokenValidationError::JwksNoUsableKeys);
        }

        Ok(keys_by_kid)
    }

    async fn resolve_jwks_url(&self) -> Result<String, TokenValidationError> {
        if let Some(ref url) = self.config.jwks_url {
            if !url.trim().is_empty() {
                return Ok(url.clone());
            }
        }

        let discovery_url = self
            .config
            .discovery_url
            .as_ref()
            .ok_or(TokenValidationError::NoJwksEndpoint)?;

        if discovery_url.trim().is_empty() {
            return Err(TokenValidationError::NoJwksEndpoint);
        }

        let response = self
            .http_client
            .get(discovery_url)
            .send()
            .await
            .map_err(|e| TokenValidationError::JwksFetchFailed(e.to_string()))?;

        let payload: serde_json::Value = response
            .json()
            .await
            .map_err(|e| TokenValidationError::JwksFetchFailed(e.to_string()))?;

        let jwks_uri = payload
            .get("jwks_uri")
            .and_then(|v| v.as_str())
            .ok_or(TokenValidationError::NoJwksEndpoint)?;

        if jwks_uri.trim().is_empty() {
            return Err(TokenValidationError::NoJwksEndpoint);
        }

        Ok(jwks_uri.to_string())
    }
}

/// Local IdP bridge for dev/offline/air-gapped workflows
pub struct LocalIdpBridge {
    config: LocalIdpBridgeConfig,
}

impl LocalIdpBridge {
    pub fn new(config: LocalIdpBridgeConfig) -> Self {
        Self { config }
    }

    pub fn exchange_token(
        &self,
        subject: &PrincipalRef,
        state_evidence: &StateEvidence,
    ) -> TokenExchangeResult {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let expires_at = now + self.config.token_ttl_seconds;

        let token = self.mint_token(subject, state_evidence, expires_at, "access", None);

        TokenExchangeResult {
            access_token: token,
            expires_at_epoch_s: expires_at,
            token_type: "Bearer".to_string(),
            provider: IdentityProviderType::LocalIdp,
        }
    }

    pub fn refresh_token(
        &self,
        refresh_token: &str,
        subject: &PrincipalRef,
        state_evidence: &StateEvidence,
    ) -> TokenExchangeResult {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let expires_at = now + self.config.token_ttl_seconds;

        let token = self.mint_token(
            subject,
            state_evidence,
            expires_at,
            "refresh_access",
            Some(refresh_token),
        );

        TokenExchangeResult {
            access_token: token,
            expires_at_epoch_s: expires_at,
            token_type: "Bearer".to_string(),
            provider: IdentityProviderType::LocalIdp,
        }
    }

    fn mint_token(
        &self,
        subject: &PrincipalRef,
        state_evidence: &StateEvidence,
        expires_at_epoch_s: i64,
        grant_kind: &str,
        refresh_token: Option<&str>,
    ) -> String {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let header = serde_json::json!({
            "alg": "HS256",
            "typ": "JWT",
            "kid": "predicate-local-idp-dev"
        });

        let refresh_token_hash = refresh_token.map(|rt| hex::encode(Sha256::digest(rt.as_bytes())));

        let payload = serde_json::json!({
            "iss": self.config.issuer,
            "aud": self.config.audience,
            "sub": subject.principal_id,
            "state_hash": state_evidence.state_hash,
            "state_source": state_evidence.source,
            "token_kind": grant_kind,
            "exp": expires_at_epoch_s,
            "iat": now,
            "tenant_id": subject.tenant_id,
            "session_id": subject.session_id,
            "refresh_token_hash": refresh_token_hash,
        });

        let header_b64 = URL_SAFE_NO_PAD.encode(header.to_string().as_bytes());
        let payload_b64 = URL_SAFE_NO_PAD.encode(payload.to_string().as_bytes());

        let signing_input = format!("{}.{}", header_b64, payload_b64);

        let mut mac = HmacSha256::new_from_slice(self.config.signing_key.as_bytes())
            .expect("HMAC can take any size key");
        mac.update(signing_input.as_bytes());
        let signature = mac.finalize().into_bytes();
        let signature_b64 = URL_SAFE_NO_PAD.encode(signature);

        format!("{}.{}.{}", header_b64, payload_b64, signature_b64)
    }
}

// --- Helper functions ---

/// JWT claims map type alias
type JwtClaims = HashMap<String, serde_json::Value>;

#[allow(clippy::type_complexity)]
fn decode_jwt_parts(token: &str) -> Result<(JwtClaims, JwtClaims), TokenValidationError> {
    let segments: Vec<&str> = token.split('.').collect();
    if segments.len() != 3 {
        return Err(TokenValidationError::InvalidFormat);
    }

    let header = decode_jwt_segment(segments[0])?;
    let payload = decode_jwt_segment(segments[1])?;

    Ok((header, payload))
}

fn decode_jwt_segment(
    segment: &str,
) -> Result<HashMap<String, serde_json::Value>, TokenValidationError> {
    let padding = match segment.len() % 4 {
        0 => "",
        2 => "==",
        3 => "=",
        _ => return Err(TokenValidationError::InvalidEncoding),
    };

    let padded = format!("{}{}", segment, padding);

    let decoded = base64::engine::general_purpose::URL_SAFE
        .decode(padded.as_bytes())
        .map_err(|_| TokenValidationError::InvalidEncoding)?;

    let parsed: HashMap<String, serde_json::Value> =
        serde_json::from_slice(&decoded).map_err(|_| TokenValidationError::InvalidEncoding)?;

    Ok(parsed)
}

fn normalize_audience(audience_raw: Option<&serde_json::Value>) -> Vec<String> {
    match audience_raw {
        Some(serde_json::Value::String(s)) if !s.trim().is_empty() => vec![s.clone()],
        Some(serde_json::Value::Array(arr)) => arr
            .iter()
            .filter_map(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect(),
        _ => vec![],
    }
}

fn normalize_string_collection(value: Option<&serde_json::Value>) -> Vec<String> {
    match value {
        Some(serde_json::Value::String(s)) if !s.trim().is_empty() => {
            s.split_whitespace().map(|s| s.to_string()).collect()
        }
        Some(serde_json::Value::Array(arr)) => arr
            .iter()
            .filter_map(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect(),
        _ => vec![],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_local_identity_bridge() {
        let bridge = LocalIdentityBridge::new(300);
        let subject = PrincipalRef::new("agent:test");
        let state = StateEvidence::new("web", "state123");

        let result = bridge.exchange_token(&subject, &state);

        assert!(result.access_token.starts_with("local."));
        assert_eq!(result.provider, IdentityProviderType::Local);
        assert_eq!(result.token_type, "Bearer");
    }

    #[test]
    fn test_oidc_identity_bridge() {
        let config = OidcBridgeConfig {
            issuer: "https://issuer.example.com".to_string(),
            client_id: "client123".to_string(),
            audience: "api://test".to_string(),
            token_ttl_seconds: 300,
        };
        let bridge = OidcIdentityBridge::new(config);

        let subject = PrincipalRef::new("agent:test");
        let state = StateEvidence::new("web", "state123");

        let result = bridge.exchange_token(&subject, &state);

        assert!(result.access_token.starts_with("oidc."));
        assert_eq!(result.provider, IdentityProviderType::Oidc);
    }

    #[test]
    fn test_local_idp_bridge() {
        let config = LocalIdpBridgeConfig::default();
        let bridge = LocalIdpBridge::new(config);

        let subject = PrincipalRef::new("agent:test");
        let state = StateEvidence::new("web", "state123");

        let result = bridge.exchange_token(&subject, &state);

        // Should be a valid JWT format
        let parts: Vec<&str> = result.access_token.split('.').collect();
        assert_eq!(parts.len(), 3);
        assert_eq!(result.provider, IdentityProviderType::LocalIdp);
    }

    #[test]
    fn test_decode_jwt_parts() {
        // Create a simple JWT-like token
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"HS256","typ":"JWT"}"#.as_bytes());
        let payload = URL_SAFE_NO_PAD.encode(r#"{"sub":"test","iss":"issuer"}"#.as_bytes());
        let signature = URL_SAFE_NO_PAD.encode(b"fake_signature");

        let token = format!("{}.{}.{}", header, payload, signature);

        let (h, p) = decode_jwt_parts(&token).unwrap();

        assert_eq!(h.get("alg").unwrap().as_str().unwrap(), "HS256");
        assert_eq!(p.get("sub").unwrap().as_str().unwrap(), "test");
    }

    #[test]
    fn test_normalize_audience() {
        // String audience
        let aud = serde_json::json!("api://test");
        assert_eq!(normalize_audience(Some(&aud)), vec!["api://test"]);

        // Array audience
        let aud = serde_json::json!(["api://test", "api://other"]);
        assert_eq!(
            normalize_audience(Some(&aud)),
            vec!["api://test", "api://other"]
        );

        // Empty
        assert!(normalize_audience(None).is_empty());
    }
}
