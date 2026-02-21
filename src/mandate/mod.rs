//! JWT mandate signing and verification.
//!
//! Supports ES256 (ECDSA P-256) and HS256 (HMAC-SHA256) algorithms.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use hmac::{Hmac, Mac};
use p256::ecdsa::{signature::Signer, signature::Verifier, Signature, SigningKey, VerifyingKey};
use p256::elliptic_curve::generic_array::GenericArray;
use parking_lot::RwLock;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::models::{ActionRequest, MandateClaims, SignedMandate};

type HmacSha256 = Hmac<Sha256>;

/// Signing algorithm
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningAlgorithm {
    ES256, // ECDSA P-256 with SHA-256
    HS256, // HMAC with SHA-256
}

impl SigningAlgorithm {
    pub fn as_str(&self) -> &'static str {
        match self {
            SigningAlgorithm::ES256 => "ES256",
            SigningAlgorithm::HS256 => "HS256",
        }
    }
}

/// Key material for signing and verification
struct SigningKeyMaterial {
    secret_key: Vec<u8>,
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
}

impl SigningKeyMaterial {
    fn from_secret(secret: &str) -> Self {
        let secret_bytes = secret.as_bytes();

        // Derive private key from secret using SHA256
        let digest = Sha256::digest(secret_bytes);
        let scalar_bytes: [u8; 32] = digest.into();

        // Try to create the signing key from the hash bytes
        // SigningKey::from_bytes performs modular reduction internally
        let signing_key = match SigningKey::from_bytes(GenericArray::from_slice(&scalar_bytes)) {
            Ok(key) => key,
            Err(_) => {
                // Fallback: hash again if the first attempt fails (extremely unlikely)
                let fallback_digest = Sha256::digest(&digest);
                let fallback_bytes: [u8; 32] = fallback_digest.into();
                SigningKey::from_bytes(GenericArray::from_slice(&fallback_bytes))
                    .expect("fallback scalar should be valid")
            }
        };

        let verifying_key = *signing_key.verifying_key();

        Self {
            secret_key: secret_bytes.to_vec(),
            signing_key,
            verifying_key,
        }
    }
}

/// Key lifecycle status
#[derive(Debug, Clone, Serialize)]
pub struct KeyLifecycleStatus {
    pub active_kid: String,
    pub next_kid: Option<String>,
    pub verification_kids: Vec<String>,
    pub signing_alg: String,
}

/// Local mandate signer with key lifecycle management
pub struct LocalMandateSigner {
    ttl_seconds: i64,
    signing_alg: SigningAlgorithm,
    allow_legacy_hs256_verify: bool,
    token_issuer: String,
    token_audience: String,

    // Key management
    active_kid: Arc<RwLock<String>>,
    next_kid: Arc<RwLock<Option<String>>>,
    verification_keys: Arc<RwLock<HashMap<String, SigningKeyMaterial>>>,
}

impl LocalMandateSigner {
    /// Create a new mandate signer with the given secret key
    pub fn new(
        secret_key: &str,
        ttl_seconds: i64,
        signing_alg: SigningAlgorithm,
        allow_legacy_hs256_verify: bool,
        token_issuer: Option<&str>,
        token_audience: Option<&str>,
    ) -> Self {
        if ttl_seconds <= 0 {
            panic!("ttl_seconds must be > 0");
        }

        let kid = Self::key_id_for_secret(secret_key);
        let material = SigningKeyMaterial::from_secret(secret_key);

        let mut verification_keys = HashMap::new();
        verification_keys.insert(kid.clone(), material);

        Self {
            ttl_seconds,
            signing_alg,
            allow_legacy_hs256_verify,
            token_issuer: token_issuer.unwrap_or("predicate-authorityd").to_string(),
            token_audience: token_audience.unwrap_or("predicate-authority").to_string(),
            active_kid: Arc::new(RwLock::new(kid)),
            next_kid: Arc::new(RwLock::new(None)),
            verification_keys: Arc::new(RwLock::new(verification_keys)),
        }
    }

    /// Get the key lifecycle status
    pub fn key_lifecycle_status(&self) -> KeyLifecycleStatus {
        let keys = self.verification_keys.read();
        let mut kids: Vec<String> = keys.keys().cloned().collect();
        kids.sort();

        KeyLifecycleStatus {
            active_kid: self.active_kid.read().clone(),
            next_kid: self.next_kid.read().clone(),
            verification_kids: kids,
            signing_alg: self.signing_alg.as_str().to_string(),
        }
    }

    /// Stage a new signing key for activation
    pub fn stage_next_signing_key(&self, secret_key: &str) -> String {
        let kid = Self::key_id_for_secret(secret_key);
        let material = SigningKeyMaterial::from_secret(secret_key);

        let mut keys = self.verification_keys.write();
        keys.insert(kid.clone(), material);

        let mut next = self.next_kid.write();
        *next = Some(kid.clone());

        kid
    }

    /// Activate the staged signing key
    pub fn activate_staged_signing_key(&self) -> Result<String, &'static str> {
        let next = self.next_kid.read().clone();
        match next {
            Some(kid) => {
                let mut active = self.active_kid.write();
                *active = kid.clone();

                let mut next_lock = self.next_kid.write();
                *next_lock = None;

                Ok(kid)
            }
            None => Err("No staged signing key to activate"),
        }
    }

    /// Retire a verification key (cannot retire active or staged keys)
    pub fn retire_verification_key(&self, kid: &str) -> bool {
        let active = self.active_kid.read();
        let next = self.next_kid.read();

        if kid == active.as_str() || next.as_ref().map(|n| n.as_str()) == Some(kid) {
            return false;
        }

        let mut keys = self.verification_keys.write();
        keys.remove(kid).is_some()
    }

    /// Issue a signed mandate for the given action request
    pub fn issue(
        &self,
        request: &ActionRequest,
        parent_mandate: Option<&SignedMandate>,
    ) -> SignedMandate {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let issued_at = now;
        let expires_at = now + self.ttl_seconds;

        // Compute intent hash
        let intent_hash = Self::sha256_hex(&request.action_spec.intent);

        // Extract delegation info from parent
        let delegated_by = parent_mandate.map(|p| p.claims.principal_id.clone());
        let parent_mandate_id = parent_mandate.map(|p| p.claims.mandate_id.clone());
        let delegation_depth = parent_mandate
            .map(|p| p.claims.delegation_depth + 1)
            .unwrap_or(0);

        // Generate mandate ID
        let mandate_id_seed = format!(
            "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
            request.principal.principal_id,
            request.action_spec.action,
            request.action_spec.resource,
            intent_hash,
            request.state_evidence.state_hash,
            delegated_by.as_deref().unwrap_or("none"),
            parent_mandate_id.as_deref().unwrap_or("none"),
            delegation_depth,
            issued_at,
            now, // Using seconds instead of nanoseconds for simplicity
        );
        let mandate_id = Self::sha256_hex(&mandate_id_seed)[..24].to_string();

        // Compute delegation chain hash
        let delegation_chain_hash = Self::compute_delegation_chain_hash(
            request,
            &mandate_id,
            &intent_hash,
            delegated_by.as_deref(),
            delegation_depth,
            parent_mandate,
        );

        let claims = MandateClaims {
            mandate_id: mandate_id.clone(),
            principal_id: request.principal.principal_id.clone(),
            action: request.action_spec.action.clone(),
            resource: request.action_spec.resource.clone(),
            intent_hash,
            state_hash: request.state_evidence.state_hash.clone(),
            issued_at_epoch_s: issued_at,
            expires_at_epoch_s: expires_at,
            delegated_by,
            parent_mandate_id,
            delegation_depth,
            delegation_chain_hash: Some(delegation_chain_hash),
            iss: Some(self.token_issuer.clone()),
            aud: Some(self.token_audience.clone()),
            sub: Some(request.principal.principal_id.clone()),
            iat: Some(issued_at),
            exp: Some(expires_at),
            nbf: Some(issued_at),
            jti: Some(mandate_id),
        };

        let (token, signature) = self.sign_claims(&claims);

        SignedMandate {
            token,
            claims,
            signature,
        }
    }

    /// Verify a mandate token and return the signed mandate if valid
    pub fn verify(&self, token: &str) -> Option<SignedMandate> {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return None;
        }

        let encoded_header = parts[0];
        let encoded_payload = parts[1];
        let encoded_signature = parts[2];

        // Parse header to get algorithm and kid
        let (alg, kid) = self.parse_header_fields(encoded_header)?;

        // Verify signature
        let signing_input = format!("{}.{}", encoded_header, encoded_payload);
        if !self.verify_signature(
            &alg,
            signing_input.as_bytes(),
            encoded_signature,
            kid.as_deref(),
        ) {
            return None;
        }

        // Parse claims
        let claims = self.parse_claims(encoded_payload)?;

        // Validate claims
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        if !Self::claims_valid_for_epoch(&claims, now) {
            return None;
        }

        Some(SignedMandate {
            token: token.to_string(),
            claims,
            signature: encoded_signature.to_string(),
        })
    }

    /// Verify delegation chain
    pub fn verify_delegation(
        &self,
        mandate: &SignedMandate,
        parent_mandate: Option<&SignedMandate>,
    ) -> bool {
        let claims = &mandate.claims;

        // Must have chain hash
        let chain_hash = match &claims.delegation_chain_hash {
            Some(h) => h,
            None => return false,
        };

        if parent_mandate.is_none() {
            // Root mandate verification
            if claims.delegation_depth != 0 || claims.delegated_by.is_some() {
                return false;
            }
            let expected = Self::compute_delegation_chain_hash_for_claims(claims, None);
            return constant_time_eq(expected.as_bytes(), chain_hash.as_bytes());
        }

        // Child mandate verification
        let parent = parent_mandate.unwrap();
        let parent_claims = &parent.claims;

        if claims.delegated_by.as_ref() != Some(&parent_claims.principal_id) {
            return false;
        }
        if claims.delegation_depth != parent_claims.delegation_depth + 1 {
            return false;
        }

        let expected = Self::compute_delegation_chain_hash_for_claims(claims, parent_mandate);
        constant_time_eq(expected.as_bytes(), chain_hash.as_bytes())
    }

    // --- Internal methods ---

    fn sign_claims(&self, claims: &MandateClaims) -> (String, String) {
        let active_kid = self.active_kid.read().clone();
        let keys = self.verification_keys.read();
        let material = keys.get(&active_kid).expect("active key must exist");

        // Build JWT header
        let header = serde_json::json!({
            "alg": self.signing_alg.as_str(),
            "typ": "JWT",
            "kid": active_kid,
        });
        let header_json = serde_json::to_string(&header).unwrap();

        // Build payload
        let payload_json = serde_json::to_string(claims).unwrap();

        let encoded_header = URL_SAFE_NO_PAD.encode(header_json.as_bytes());
        let encoded_payload = URL_SAFE_NO_PAD.encode(payload_json.as_bytes());
        let signing_input = format!("{}.{}", encoded_header, encoded_payload);

        let signature_bytes = match self.signing_alg {
            SigningAlgorithm::HS256 => {
                Self::hmac_sha256(signing_input.as_bytes(), &material.secret_key)
            }
            SigningAlgorithm::ES256 => {
                let signature: Signature = material.signing_key.sign(signing_input.as_bytes());
                signature.to_bytes().to_vec()
            }
        };

        let signature = URL_SAFE_NO_PAD.encode(&signature_bytes);
        let token = format!("{}.{}.{}", encoded_header, encoded_payload, signature);

        (token, signature)
    }

    fn verify_signature(
        &self,
        alg: &str,
        signing_input: &[u8],
        encoded_signature: &str,
        kid: Option<&str>,
    ) -> bool {
        let signature_bytes = match URL_SAFE_NO_PAD.decode(encoded_signature) {
            Ok(b) => b,
            Err(_) => return false,
        };

        let candidate_kids = self.candidate_kids_for_verify(kid);
        let keys = self.verification_keys.read();

        match alg {
            "ES256" => {
                if signature_bytes.len() != 64 {
                    return false;
                }
                let signature = match Signature::from_slice(&signature_bytes) {
                    Ok(s) => s,
                    Err(_) => return false,
                };

                for candidate_kid in candidate_kids {
                    if let Some(material) = keys.get(&candidate_kid) {
                        if material
                            .verifying_key
                            .verify(signing_input, &signature)
                            .is_ok()
                        {
                            return true;
                        }
                    }
                }
                false
            }
            "HS256" => {
                if !self.allow_legacy_hs256_verify && self.signing_alg != SigningAlgorithm::HS256 {
                    return false;
                }
                for candidate_kid in candidate_kids {
                    if let Some(material) = keys.get(&candidate_kid) {
                        let expected = Self::hmac_sha256(signing_input, &material.secret_key);
                        if constant_time_eq(&expected, &signature_bytes) {
                            return true;
                        }
                    }
                }
                false
            }
            _ => false,
        }
    }

    fn candidate_kids_for_verify(&self, kid: Option<&str>) -> Vec<String> {
        if let Some(k) = kid {
            vec![k.to_string()]
        } else {
            // Try all keys if no kid specified
            let keys = self.verification_keys.read();
            keys.keys().cloned().collect()
        }
    }

    fn parse_header_fields(&self, encoded_header: &str) -> Option<(String, Option<String>)> {
        let header_bytes = URL_SAFE_NO_PAD.decode(encoded_header).ok()?;
        let header: serde_json::Value = serde_json::from_slice(&header_bytes).ok()?;

        let alg = header.get("alg")?.as_str()?.to_string();
        let kid = header
            .get("kid")
            .and_then(|k| k.as_str())
            .map(|s| s.to_string());

        Some((alg, kid))
    }

    fn parse_claims(&self, encoded_payload: &str) -> Option<MandateClaims> {
        let payload_bytes = URL_SAFE_NO_PAD.decode(encoded_payload).ok()?;
        serde_json::from_slice(&payload_bytes).ok()
    }

    fn claims_valid_for_epoch(claims: &MandateClaims, now_epoch: i64) -> bool {
        // Check expiration
        let effective_exp = claims.exp.unwrap_or(claims.expires_at_epoch_s);
        if effective_exp < now_epoch {
            return false;
        }

        // Check issued at (not in future)
        if let Some(iat) = claims.iat {
            if iat > now_epoch {
                return false;
            }
        }

        // Check not before
        if let Some(nbf) = claims.nbf {
            if nbf > now_epoch {
                return false;
            }
        }

        // Validate delegation consistency
        if claims.delegation_depth < 0 {
            return false;
        }
        if claims.delegation_depth == 0 && claims.delegated_by.is_some() {
            return false;
        }
        if claims.delegation_depth > 0 && claims.delegated_by.is_none() {
            return false;
        }

        claims.delegation_chain_hash.is_some()
    }

    fn compute_delegation_chain_hash(
        request: &ActionRequest,
        mandate_id: &str,
        intent_hash: &str,
        delegated_by: Option<&str>,
        delegation_depth: u32,
        parent_mandate: Option<&SignedMandate>,
    ) -> String {
        let parent_chain = parent_mandate
            .and_then(|p| p.claims.delegation_chain_hash.as_deref())
            .unwrap_or("root");
        let parent_mandate_id = parent_mandate
            .map(|p| p.claims.mandate_id.as_str())
            .unwrap_or("none");

        let chain_seed = format!(
            "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
            parent_chain,
            parent_mandate_id,
            delegated_by.unwrap_or("none"),
            delegation_depth,
            mandate_id,
            request.principal.principal_id,
            request.action_spec.action,
            request.action_spec.resource,
            intent_hash,
            request.state_evidence.state_hash,
        );

        Self::sha256_hex(&chain_seed)
    }

    fn compute_delegation_chain_hash_for_claims(
        claims: &MandateClaims,
        parent_mandate: Option<&SignedMandate>,
    ) -> String {
        let parent_chain = parent_mandate
            .and_then(|p| p.claims.delegation_chain_hash.as_deref())
            .unwrap_or("root");
        let parent_mandate_id = parent_mandate
            .map(|p| p.claims.mandate_id.as_str())
            .unwrap_or("none");

        let chain_seed = format!(
            "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
            parent_chain,
            parent_mandate_id,
            claims.delegated_by.as_deref().unwrap_or("none"),
            claims.delegation_depth,
            claims.mandate_id,
            claims.principal_id,
            claims.action,
            claims.resource,
            claims.intent_hash,
            claims.state_hash,
        );

        Self::sha256_hex(&chain_seed)
    }

    fn key_id_for_secret(secret: &str) -> String {
        let input = format!("mandate-signing:{}", secret);
        Self::sha256_hex(&input)[..16].to_string()
    }

    fn sha256_hex(input: &str) -> String {
        let digest = Sha256::digest(input.as_bytes());
        hex::encode(digest)
    }

    fn hmac_sha256(data: &[u8], key: &[u8]) -> Vec<u8> {
        let mut mac = HmacSha256::new_from_slice(key).expect("HMAC can take key of any size");
        mac.update(data);
        mac.finalize().into_bytes().to_vec()
    }
}

/// Constant-time comparison to prevent timing attacks
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{ActionSpec, PrincipalRef, StateEvidence, VerificationEvidence};

    fn test_signer() -> LocalMandateSigner {
        LocalMandateSigner::new(
            "test-secret-key",
            300,
            SigningAlgorithm::ES256,
            true,
            None,
            None,
        )
    }

    fn test_request() -> ActionRequest {
        ActionRequest {
            principal: PrincipalRef::new("agent:test"),
            action_spec: ActionSpec {
                action: "browser.click".to_string(),
                resource: "https://example.com".to_string(),
                intent: "click button".to_string(),
            },
            state_evidence: StateEvidence::new("web", "state123"),
            verification_evidence: VerificationEvidence {
                schema_version: "1.0".to_string(),
                signals: vec![],
                verified: true,
            },
        }
    }

    #[test]
    fn test_issue_and_verify() {
        let signer = test_signer();
        let request = test_request();

        let mandate = signer.issue(&request, None);

        assert!(!mandate.token.is_empty());
        assert_eq!(mandate.claims.principal_id, "agent:test");
        assert_eq!(mandate.claims.action, "browser.click");
        assert_eq!(mandate.claims.delegation_depth, 0);
        assert!(mandate.claims.delegated_by.is_none());

        // Verify the token
        let verified = signer.verify(&mandate.token);
        assert!(verified.is_some());
        assert_eq!(
            verified.unwrap().claims.mandate_id,
            mandate.claims.mandate_id
        );
    }

    #[test]
    fn test_delegation_chain() {
        let signer = test_signer();

        // Root mandate
        let root_request = ActionRequest {
            principal: PrincipalRef::new("agent:root"),
            action_spec: ActionSpec {
                action: "task.delegate".to_string(),
                resource: "worker:queue".to_string(),
                intent: "delegate task".to_string(),
            },
            state_evidence: StateEvidence::new("non-web", "root-state"),
            verification_evidence: VerificationEvidence {
                schema_version: "1.0".to_string(),
                signals: vec![],
                verified: true,
            },
        };
        let root_mandate = signer.issue(&root_request, None);

        // Child mandate
        let child_request = ActionRequest {
            principal: PrincipalRef::new("agent:worker"),
            action_spec: ActionSpec {
                action: "job.execute".to_string(),
                resource: "queue://jobs".to_string(),
                intent: "execute job".to_string(),
            },
            state_evidence: StateEvidence::new("non-web", "worker-state"),
            verification_evidence: VerificationEvidence {
                schema_version: "1.0".to_string(),
                signals: vec![],
                verified: true,
            },
        };
        let child_mandate = signer.issue(&child_request, Some(&root_mandate));

        // Verify delegation claims
        assert_eq!(root_mandate.claims.delegation_depth, 0);
        assert!(root_mandate.claims.delegated_by.is_none());

        assert_eq!(child_mandate.claims.delegation_depth, 1);
        assert_eq!(
            child_mandate.claims.delegated_by,
            Some("agent:root".to_string())
        );
        assert_eq!(
            child_mandate.claims.parent_mandate_id,
            Some(root_mandate.claims.mandate_id.clone())
        );

        // Verify delegation chain
        assert!(signer.verify_delegation(&root_mandate, None));
        assert!(signer.verify_delegation(&child_mandate, Some(&root_mandate)));
        assert!(!signer.verify_delegation(&child_mandate, None));
    }

    #[test]
    fn test_key_lifecycle() {
        let signer = test_signer();

        let status = signer.key_lifecycle_status();
        assert!(!status.active_kid.is_empty());
        assert!(status.next_kid.is_none());
        assert_eq!(status.verification_kids.len(), 1);

        // Stage new key
        let new_kid = signer.stage_next_signing_key("new-secret-key");
        let status = signer.key_lifecycle_status();
        assert_eq!(status.next_kid, Some(new_kid.clone()));
        assert_eq!(status.verification_kids.len(), 2);

        // Activate staged key
        let activated = signer.activate_staged_signing_key().unwrap();
        assert_eq!(activated, new_kid);
        let status = signer.key_lifecycle_status();
        assert_eq!(status.active_kid, new_kid);
        assert!(status.next_kid.is_none());

        // Retire old key
        let old_kid = &status.verification_kids[0];
        if old_kid != &new_kid {
            assert!(signer.retire_verification_key(old_kid));
            let status = signer.key_lifecycle_status();
            assert_eq!(status.verification_kids.len(), 1);
        }
    }

    #[test]
    fn test_hs256_signing() {
        let signer = LocalMandateSigner::new(
            "test-secret",
            300,
            SigningAlgorithm::HS256,
            true,
            None,
            None,
        );
        let request = test_request();

        let mandate = signer.issue(&request, None);
        let verified = signer.verify(&mandate.token);
        assert!(verified.is_some());
    }

    #[test]
    fn test_expired_token_rejected() {
        let signer = LocalMandateSigner::new(
            "test-secret",
            1, // 1 second TTL
            SigningAlgorithm::ES256,
            true,
            None,
            None,
        );
        let request = test_request();

        let mandate = signer.issue(&request, None);

        // Wait for expiration
        std::thread::sleep(std::time::Duration::from_secs(2));

        let verified = signer.verify(&mandate.token);
        assert!(verified.is_none());
    }
}
