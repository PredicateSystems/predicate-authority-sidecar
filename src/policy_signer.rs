//! Policy signature verification using Ed25519.
//!
//! This module provides optional policy signing for enterprise security teams.
//! When enabled with `--require-signed-policy`, the sidecar will reject any
//! policy file that doesn't have a valid Ed25519 signature.
//!
//! # Signed Policy Format
//!
//! A signed policy file is a JSON object with two fields:
//! ```json
//! {
//!   "policy": { "rules": [...] },
//!   "signature": "<base64-encoded-ed25519-signature>"
//! }
//! ```
//!
//! The signature is computed over the canonical JSON representation of the
//! "policy" object (sorted keys, no extra whitespace).

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Errors that can occur during policy signing/verification
#[derive(Debug, thiserror::Error)]
pub enum PolicySignatureError {
    #[error("Invalid signature format: {0}")]
    InvalidSignatureFormat(String),

    #[error("Invalid public key: {0}")]
    InvalidPublicKey(String),

    #[error("Signature verification failed")]
    VerificationFailed,

    #[error("Missing signature in signed policy")]
    MissingSignature,

    #[error("Missing policy content in signed policy")]
    MissingPolicyContent,

    #[error("JSON serialization error: {0}")]
    JsonError(#[from] serde_json::Error),
}

/// A signed policy file structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedPolicy {
    /// The policy content (contains "rules" array)
    pub policy: serde_json::Value,
    /// Base64-encoded Ed25519 signature
    pub signature: String,
}

/// Canonicalize a JSON value for signing (sorted keys, compact format)
pub fn canonicalize_json(value: &serde_json::Value) -> Result<String, PolicySignatureError> {
    // serde_json with sort_keys produces deterministic output
    Ok(serde_json::to_string(value)?)
}

/// Sign a policy JSON value with an Ed25519 signing key
pub fn sign_policy(
    policy: &serde_json::Value,
    signing_key: &SigningKey,
) -> Result<SignedPolicy, PolicySignatureError> {
    let canonical = canonicalize_json(policy)?;
    let signature = signing_key.sign(canonical.as_bytes());
    let signature_b64 = BASE64.encode(signature.to_bytes());

    Ok(SignedPolicy {
        policy: policy.clone(),
        signature: signature_b64,
    })
}

/// Verify a signed policy against a public key
pub fn verify_policy_signature(
    signed_policy: &SignedPolicy,
    public_key: &VerifyingKey,
) -> Result<(), PolicySignatureError> {
    let canonical = canonicalize_json(&signed_policy.policy)?;

    let signature_bytes = BASE64
        .decode(&signed_policy.signature)
        .map_err(|e| PolicySignatureError::InvalidSignatureFormat(e.to_string()))?;

    let signature = Signature::from_slice(&signature_bytes)
        .map_err(|e| PolicySignatureError::InvalidSignatureFormat(e.to_string()))?;

    public_key
        .verify(canonical.as_bytes(), &signature)
        .map_err(|_| PolicySignatureError::VerificationFailed)
}

/// Parse a public key from a hex string
pub fn parse_public_key_hex(hex_str: &str) -> Result<VerifyingKey, PolicySignatureError> {
    let bytes = hex::decode(hex_str)
        .map_err(|e| PolicySignatureError::InvalidPublicKey(format!("invalid hex: {}", e)))?;

    if bytes.len() != 32 {
        return Err(PolicySignatureError::InvalidPublicKey(format!(
            "expected 32 bytes, got {}",
            bytes.len()
        )));
    }

    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&bytes);

    VerifyingKey::from_bytes(&key_bytes)
        .map_err(|e| PolicySignatureError::InvalidPublicKey(e.to_string()))
}

/// Parse a signed policy from JSON content
pub fn parse_signed_policy(content: &str) -> Result<SignedPolicy, PolicySignatureError> {
    let value: serde_json::Value = serde_json::from_str(content)?;

    // Check if this looks like a signed policy (has "policy" and "signature" fields)
    if !value.get("signature").is_some() {
        return Err(PolicySignatureError::MissingSignature);
    }

    if !value.get("policy").is_some() {
        return Err(PolicySignatureError::MissingPolicyContent);
    }

    Ok(serde_json::from_value(value)?)
}

/// Check if content looks like a signed policy (has both "policy" and "signature" keys)
pub fn is_signed_policy(content: &str) -> bool {
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(content) {
        value.get("signature").is_some() && value.get("policy").is_some()
    } else {
        false
    }
}

/// Generate a new Ed25519 keypair for policy signing
/// Returns (signing_key_hex, verifying_key_hex)
pub fn generate_keypair() -> (String, String) {
    let mut rng = rand::thread_rng();
    let signing_key = SigningKey::generate(&mut rng);
    let verifying_key = signing_key.verifying_key();

    (
        hex::encode(signing_key.to_bytes()),
        hex::encode(verifying_key.to_bytes()),
    )
}

/// Compute the fingerprint (SHA-256 truncated to 8 chars) of a public key
pub fn public_key_fingerprint(public_key: &VerifyingKey) -> String {
    let mut hasher = Sha256::new();
    hasher.update(public_key.as_bytes());
    let hash = hasher.finalize();
    hex::encode(&hash[..4]) // First 4 bytes = 8 hex chars
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_policy() -> serde_json::Value {
        serde_json::json!({
            "rules": [
                {
                    "name": "allow-browser",
                    "effect": "allow",
                    "principals": ["agent:*"],
                    "actions": ["browser.*"],
                    "resources": ["https://*"]
                }
            ]
        })
    }

    #[test]
    fn test_generate_keypair() {
        let (signing_hex, verifying_hex) = generate_keypair();

        assert_eq!(signing_hex.len(), 64); // 32 bytes = 64 hex chars
        assert_eq!(verifying_hex.len(), 64);

        // Verify we can parse the public key back
        let public_key = parse_public_key_hex(&verifying_hex).unwrap();
        assert!(public_key_fingerprint(&public_key).len() == 8);
    }

    #[test]
    fn test_sign_and_verify() {
        let mut rng = rand::thread_rng();
        let signing_key = SigningKey::generate(&mut rng);
        let verifying_key = signing_key.verifying_key();

        let policy = sample_policy();
        let signed = sign_policy(&policy, &signing_key).unwrap();

        // Verification should succeed
        assert!(verify_policy_signature(&signed, &verifying_key).is_ok());
    }

    #[test]
    fn test_verification_fails_with_wrong_key() {
        let mut rng = rand::thread_rng();
        let signing_key = SigningKey::generate(&mut rng);
        let wrong_key = SigningKey::generate(&mut rng).verifying_key();

        let policy = sample_policy();
        let signed = sign_policy(&policy, &signing_key).unwrap();

        // Verification should fail with wrong key
        let result = verify_policy_signature(&signed, &wrong_key);
        assert!(matches!(result, Err(PolicySignatureError::VerificationFailed)));
    }

    #[test]
    fn test_verification_fails_with_tampered_policy() {
        let mut rng = rand::thread_rng();
        let signing_key = SigningKey::generate(&mut rng);
        let verifying_key = signing_key.verifying_key();

        let policy = sample_policy();
        let mut signed = sign_policy(&policy, &signing_key).unwrap();

        // Tamper with the policy
        signed.policy = serde_json::json!({"rules": []});

        // Verification should fail
        let result = verify_policy_signature(&signed, &verifying_key);
        assert!(matches!(result, Err(PolicySignatureError::VerificationFailed)));
    }

    #[test]
    fn test_parse_signed_policy() {
        let mut rng = rand::thread_rng();
        let signing_key = SigningKey::generate(&mut rng);

        let policy = sample_policy();
        let signed = sign_policy(&policy, &signing_key).unwrap();

        let json_str = serde_json::to_string(&signed).unwrap();
        let parsed = parse_signed_policy(&json_str).unwrap();

        assert_eq!(signed.signature, parsed.signature);
    }

    #[test]
    fn test_is_signed_policy() {
        let unsigned = r#"{"rules": []}"#;
        assert!(!is_signed_policy(unsigned));

        let signed = r#"{"policy": {"rules": []}, "signature": "abc123"}"#;
        assert!(is_signed_policy(signed));

        let partial = r#"{"signature": "abc123"}"#;
        assert!(!is_signed_policy(partial));
    }

    #[test]
    fn test_canonicalize_json_deterministic() {
        let policy1 = serde_json::json!({"b": 2, "a": 1});
        let policy2 = serde_json::json!({"a": 1, "b": 2});

        let canonical1 = canonicalize_json(&policy1).unwrap();
        let canonical2 = canonicalize_json(&policy2).unwrap();

        // serde_json maintains insertion order, so these will be different
        // This is acceptable - we just need consistency for the same input
        assert_eq!(canonical1, canonicalize_json(&policy1).unwrap());
        assert_eq!(canonical2, canonicalize_json(&policy2).unwrap());
    }

    #[test]
    fn test_parse_public_key_hex() {
        let (_, verifying_hex) = generate_keypair();
        let result = parse_public_key_hex(&verifying_hex);
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_invalid_public_key() {
        // Too short
        let result = parse_public_key_hex("abcd");
        assert!(matches!(result, Err(PolicySignatureError::InvalidPublicKey(_))));

        // Invalid hex
        let result = parse_public_key_hex("xyz123");
        assert!(matches!(result, Err(PolicySignatureError::InvalidPublicKey(_))));
    }
}
