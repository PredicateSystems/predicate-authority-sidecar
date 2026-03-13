//! Secret injection utilities for environment variable substitution.
//!
//! This module provides functions to substitute environment variables in strings,
//! enabling policy-driven secret injection for HTTP headers and CLI environment variables.
//!
//! ## Supported Syntax
//!
//! - `${VAR_NAME}` - Substitutes with the value of VAR_NAME, errors if missing
//! - `${VAR_NAME:-default}` - Substitutes with VAR_NAME value, or "default" if missing
//!
//! ## Security
//!
//! - Only reads from the sidecar process environment
//! - Never exposes secret values to agents (values are injected at execution time)
//! - Supports zeroization of sensitive values when possible

use regex::Regex;
use std::collections::HashMap;
use std::sync::LazyLock;
use thiserror::Error;

/// Regex pattern for environment variable substitution.
/// Matches: ${VAR_NAME} or ${VAR_NAME:-default_value}
static ENV_VAR_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}").expect("Invalid regex pattern")
});

/// Error type for secret substitution
#[derive(Debug, Error)]
pub enum SecretSubstitutionError {
    #[error("Missing environment variable: {0}")]
    MissingEnvVar(String),

    #[error("Environment variable substitution failed: {0}")]
    SubstitutionFailed(String),
}

/// Result type for secret substitution operations
pub type SubstitutionResult<T> = Result<T, SecretSubstitutionError>;

/// Substitute environment variables in a template string.
///
/// Supports two syntaxes:
/// - `${VAR_NAME}` - Required variable, returns error if not set
/// - `${VAR_NAME:-default}` - Optional variable with default value
///
/// # Examples
///
/// ```ignore
/// // Required variable
/// let result = substitute_env_vars("Bearer ${API_TOKEN}")?;
///
/// // With default value
/// let result = substitute_env_vars("${API_URL:-https://api.example.com}")?;
/// ```
pub fn substitute_env_vars(template: &str) -> SubstitutionResult<String> {
    let mut result = template.to_string();
    let mut errors = Vec::new();

    // Find all matches and substitute them
    for cap in ENV_VAR_PATTERN.captures_iter(template) {
        let full_match = cap.get(0).unwrap().as_str();
        let var_name = cap.get(1).unwrap().as_str();
        let default_value = cap.get(2).map(|m| m.as_str());

        match std::env::var(var_name) {
            Ok(value) => {
                result = result.replace(full_match, &value);
            }
            Err(_) => {
                if let Some(default) = default_value {
                    result = result.replace(full_match, default);
                } else {
                    errors.push(var_name.to_string());
                }
            }
        }
    }

    if !errors.is_empty() {
        return Err(SecretSubstitutionError::MissingEnvVar(errors.join(", ")));
    }

    Ok(result)
}

/// Substitute environment variables in a HashMap of strings.
///
/// Used for processing `inject_headers` and `inject_env` from policy rules.
/// All values in the map are processed for substitution.
///
/// # Arguments
///
/// * `templates` - HashMap where values may contain `${VAR}` patterns
///
/// # Returns
///
/// A new HashMap with all environment variables substituted.
pub fn substitute_env_vars_in_map(
    templates: &HashMap<String, String>,
) -> SubstitutionResult<HashMap<String, String>> {
    let mut result = HashMap::with_capacity(templates.len());

    for (key, template) in templates {
        let value = substitute_env_vars(template)?;
        result.insert(key.clone(), value);
    }

    Ok(result)
}

/// Check if a template string contains any environment variable references.
///
/// Useful for validation at policy load time.
pub fn has_env_var_references(template: &str) -> bool {
    ENV_VAR_PATTERN.is_match(template)
}

/// Extract all environment variable names referenced in a template.
///
/// Useful for validation and debugging.
pub fn extract_env_var_names(template: &str) -> Vec<String> {
    ENV_VAR_PATTERN
        .captures_iter(template)
        .map(|cap| cap.get(1).unwrap().as_str().to_string())
        .collect()
}

/// Validate that all environment variables in a template are set.
///
/// Returns a list of missing variable names, or empty vec if all are present.
pub fn validate_env_vars(template: &str) -> Vec<String> {
    let mut missing = Vec::new();

    for cap in ENV_VAR_PATTERN.captures_iter(template) {
        let var_name = cap.get(1).unwrap().as_str();
        let has_default = cap.get(2).is_some();

        if !has_default && std::env::var(var_name).is_err() {
            missing.push(var_name.to_string());
        }
    }

    missing
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_substitute_simple_var() {
        std::env::set_var("TEST_SECRET_1", "my-secret-value");

        let result = substitute_env_vars("Bearer ${TEST_SECRET_1}").unwrap();
        assert_eq!(result, "Bearer my-secret-value");

        std::env::remove_var("TEST_SECRET_1");
    }

    #[test]
    fn test_substitute_multiple_vars() {
        std::env::set_var("TEST_USER", "admin");
        std::env::set_var("TEST_PASS", "secret123");

        let result = substitute_env_vars("${TEST_USER}:${TEST_PASS}").unwrap();
        assert_eq!(result, "admin:secret123");

        std::env::remove_var("TEST_USER");
        std::env::remove_var("TEST_PASS");
    }

    #[test]
    fn test_substitute_with_default() {
        // Variable not set, should use default
        std::env::remove_var("NONEXISTENT_VAR");

        let result = substitute_env_vars("${NONEXISTENT_VAR:-default_value}").unwrap();
        assert_eq!(result, "default_value");
    }

    #[test]
    fn test_substitute_with_default_empty() {
        std::env::remove_var("EMPTY_DEFAULT_VAR");

        let result = substitute_env_vars("${EMPTY_DEFAULT_VAR:-}").unwrap();
        assert_eq!(result, "");
    }

    #[test]
    fn test_substitute_prefers_env_over_default() {
        std::env::set_var("TEST_PRIORITY", "from-env");

        let result = substitute_env_vars("${TEST_PRIORITY:-default}").unwrap();
        assert_eq!(result, "from-env");

        std::env::remove_var("TEST_PRIORITY");
    }

    #[test]
    fn test_substitute_missing_required_var() {
        std::env::remove_var("DEFINITELY_NOT_SET");

        let result = substitute_env_vars("Bearer ${DEFINITELY_NOT_SET}");
        assert!(result.is_err());

        let err = result.unwrap_err();
        assert!(err.to_string().contains("DEFINITELY_NOT_SET"));
    }

    #[test]
    fn test_substitute_in_map() {
        std::env::set_var("TEST_API_KEY", "key123");
        std::env::set_var("TEST_ORG_ID", "org456");

        let mut templates = HashMap::new();
        templates.insert(
            "Authorization".to_string(),
            "Bearer ${TEST_API_KEY}".to_string(),
        );
        templates.insert("X-Org-ID".to_string(), "${TEST_ORG_ID}".to_string());

        let result = substitute_env_vars_in_map(&templates).unwrap();

        assert_eq!(result.get("Authorization").unwrap(), "Bearer key123");
        assert_eq!(result.get("X-Org-ID").unwrap(), "org456");

        std::env::remove_var("TEST_API_KEY");
        std::env::remove_var("TEST_ORG_ID");
    }

    #[test]
    fn test_has_env_var_references() {
        assert!(has_env_var_references("Bearer ${TOKEN}"));
        assert!(has_env_var_references("${VAR:-default}"));
        assert!(!has_env_var_references("plain text"));
        assert!(!has_env_var_references("not a ${incomplete"));
        assert!(!has_env_var_references("$NOT_BRACED"));
    }

    #[test]
    fn test_extract_env_var_names() {
        let names = extract_env_var_names("${VAR1} and ${VAR2:-default}");
        assert_eq!(names, vec!["VAR1", "VAR2"]);
    }

    #[test]
    fn test_validate_env_vars() {
        std::env::set_var("TEST_EXISTS", "value");
        std::env::remove_var("TEST_MISSING");

        let missing = validate_env_vars("${TEST_EXISTS} ${TEST_MISSING} ${TEST_DEFAULT:-d}");
        assert_eq!(missing, vec!["TEST_MISSING"]);

        std::env::remove_var("TEST_EXISTS");
    }

    #[test]
    fn test_no_substitution_needed() {
        let result = substitute_env_vars("plain text without variables").unwrap();
        assert_eq!(result, "plain text without variables");
    }

    #[test]
    fn test_complex_template() {
        std::env::set_var("TEST_HOST", "api.example.com");
        std::env::set_var("TEST_TOKEN", "secret123");

        let template = "https://${TEST_HOST}/api?key=${TEST_TOKEN}&format=${FMT:-json}";
        let result = substitute_env_vars(template).unwrap();
        assert_eq!(
            result,
            "https://api.example.com/api?key=secret123&format=json"
        );

        std::env::remove_var("TEST_HOST");
        std::env::remove_var("TEST_TOKEN");
    }

    #[test]
    fn test_underscore_and_numbers_in_var_names() {
        std::env::set_var("MY_VAR_123", "value");
        std::env::set_var("_PRIVATE_VAR", "private");

        let result = substitute_env_vars("${MY_VAR_123} ${_PRIVATE_VAR}").unwrap();
        assert_eq!(result, "value private");

        std::env::remove_var("MY_VAR_123");
        std::env::remove_var("_PRIVATE_VAR");
    }
}
