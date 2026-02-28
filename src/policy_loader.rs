//! Policy file loader with support for JSON and YAML formats.
//!
//! JSON is the default format. YAML is supported for files with `.yaml` or `.yml` extensions.

use std::path::Path;

use crate::models::PolicyRule;

/// Supported policy file formats
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyFormat {
    /// JSON format (default)
    Json,
    /// YAML format
    Yaml,
}

/// Error type for policy loading
#[derive(Debug, thiserror::Error)]
pub enum PolicyLoadError {
    #[error("Failed to read policy file: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Failed to parse JSON policy: {0}")]
    JsonParseError(#[from] serde_json::Error),

    #[error("Failed to parse YAML policy: {0}")]
    YamlParseError(#[from] serde_yaml::Error),

    #[error("Policy file missing 'rules' array")]
    MissingRulesArray,
}

/// Result of loading a policy file
#[derive(Debug)]
pub struct PolicyLoadResult {
    pub rules: Vec<PolicyRule>,
    pub format: PolicyFormat,
    pub skipped_rules: usize,
}

/// Detect the format of a policy file based on its extension.
///
/// Returns `PolicyFormat::Yaml` for `.yaml` or `.yml` extensions.
/// Returns `PolicyFormat::Json` for all other extensions (default).
pub fn detect_format<P: AsRef<Path>>(path: P) -> PolicyFormat {
    let path = path.as_ref();
    match path.extension().and_then(|ext| ext.to_str()) {
        Some("yaml") | Some("yml") => PolicyFormat::Yaml,
        _ => PolicyFormat::Json, // Default to JSON
    }
}

/// Load policy rules from a file, auto-detecting the format.
///
/// Format is determined by file extension:
/// - `.yaml` or `.yml` -> YAML format
/// - All other extensions -> JSON format (default)
pub fn load_policy_file<P: AsRef<Path>>(path: P) -> Result<PolicyLoadResult, PolicyLoadError> {
    let path = path.as_ref();
    let content = std::fs::read_to_string(path)?;
    let format = detect_format(path);

    load_policy_from_string(&content, format)
}

/// Load policy rules from a string with the specified format.
pub fn load_policy_from_string(
    content: &str,
    format: PolicyFormat,
) -> Result<PolicyLoadResult, PolicyLoadError> {
    // Parse content to a generic JSON Value (both formats can deserialize to this)
    let json_value: serde_json::Value = match format {
        PolicyFormat::Json => serde_json::from_str(content)?,
        PolicyFormat::Yaml => serde_yaml::from_str(content)?,
    };

    // Extract the "rules" array
    let rules_array = json_value
        .get("rules")
        .and_then(|r| r.as_array())
        .ok_or(PolicyLoadError::MissingRulesArray)?;

    // Parse each rule, tracking how many we skip
    let total_rules = rules_array.len();
    let parsed_rules: Vec<PolicyRule> = rules_array
        .iter()
        .filter_map(|r| serde_json::from_value(r.clone()).ok())
        .collect();

    let skipped_rules = total_rules - parsed_rules.len();

    Ok(PolicyLoadResult {
        rules: parsed_rules,
        format,
        skipped_rules,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    const SAMPLE_JSON_POLICY: &str = r#"{
        "rules": [
            {
                "name": "allow-browser-https",
                "effect": "allow",
                "principals": ["agent:*"],
                "actions": ["browser.*"],
                "resources": ["https://*"]
            },
            {
                "name": "deny-admin-actions",
                "effect": "deny",
                "principals": ["*"],
                "actions": ["admin.*"],
                "resources": ["*"]
            }
        ]
    }"#;

    const SAMPLE_YAML_POLICY: &str = r#"rules:
  - name: allow-browser-https
    effect: allow
    principals:
      - "agent:*"
    actions:
      - "browser.*"
    resources:
      - "https://*"
  - name: deny-admin-actions
    effect: deny
    principals:
      - "*"
    actions:
      - "admin.*"
    resources:
      - "*"
"#;

    #[test]
    fn test_detect_format_json_default() {
        assert_eq!(detect_format("policy.json"), PolicyFormat::Json);
        assert_eq!(detect_format("policy.txt"), PolicyFormat::Json);
        assert_eq!(detect_format("policy"), PolicyFormat::Json);
        assert_eq!(detect_format("/path/to/policy.JSON"), PolicyFormat::Json); // case-sensitive
    }

    #[test]
    fn test_detect_format_yaml() {
        assert_eq!(detect_format("policy.yaml"), PolicyFormat::Yaml);
        assert_eq!(detect_format("policy.yml"), PolicyFormat::Yaml);
        assert_eq!(detect_format("/path/to/my-policy.yaml"), PolicyFormat::Yaml);
        assert_eq!(detect_format("config/rules.yml"), PolicyFormat::Yaml);
    }

    #[test]
    fn test_load_json_from_string() {
        let result = load_policy_from_string(SAMPLE_JSON_POLICY, PolicyFormat::Json).unwrap();

        assert_eq!(result.format, PolicyFormat::Json);
        assert_eq!(result.rules.len(), 2);
        assert_eq!(result.skipped_rules, 0);

        assert_eq!(result.rules[0].name, "allow-browser-https");
        assert_eq!(result.rules[1].name, "deny-admin-actions");
    }

    #[test]
    fn test_load_yaml_from_string() {
        let result = load_policy_from_string(SAMPLE_YAML_POLICY, PolicyFormat::Yaml).unwrap();

        assert_eq!(result.format, PolicyFormat::Yaml);
        assert_eq!(result.rules.len(), 2);
        assert_eq!(result.skipped_rules, 0);

        assert_eq!(result.rules[0].name, "allow-browser-https");
        assert_eq!(result.rules[1].name, "deny-admin-actions");
    }

    #[test]
    fn test_json_and_yaml_produce_same_rules() {
        let json_result = load_policy_from_string(SAMPLE_JSON_POLICY, PolicyFormat::Json).unwrap();
        let yaml_result = load_policy_from_string(SAMPLE_YAML_POLICY, PolicyFormat::Yaml).unwrap();

        assert_eq!(json_result.rules.len(), yaml_result.rules.len());

        for (json_rule, yaml_rule) in json_result.rules.iter().zip(yaml_result.rules.iter()) {
            assert_eq!(json_rule.name, yaml_rule.name);
            assert_eq!(json_rule.effect, yaml_rule.effect);
            assert_eq!(json_rule.principals, yaml_rule.principals);
            assert_eq!(json_rule.actions, yaml_rule.actions);
            assert_eq!(json_rule.resources, yaml_rule.resources);
        }
    }

    #[test]
    fn test_load_json_file() {
        let mut file = NamedTempFile::with_suffix(".json").unwrap();
        file.write_all(SAMPLE_JSON_POLICY.as_bytes()).unwrap();
        file.flush().unwrap();

        let result = load_policy_file(file.path()).unwrap();

        assert_eq!(result.format, PolicyFormat::Json);
        assert_eq!(result.rules.len(), 2);
    }

    #[test]
    fn test_load_yaml_file() {
        let mut file = NamedTempFile::with_suffix(".yaml").unwrap();
        file.write_all(SAMPLE_YAML_POLICY.as_bytes()).unwrap();
        file.flush().unwrap();

        let result = load_policy_file(file.path()).unwrap();

        assert_eq!(result.format, PolicyFormat::Yaml);
        assert_eq!(result.rules.len(), 2);
    }

    #[test]
    fn test_load_yml_extension() {
        let mut file = NamedTempFile::with_suffix(".yml").unwrap();
        file.write_all(SAMPLE_YAML_POLICY.as_bytes()).unwrap();
        file.flush().unwrap();

        let result = load_policy_file(file.path()).unwrap();

        assert_eq!(result.format, PolicyFormat::Yaml);
        assert_eq!(result.rules.len(), 2);
    }

    #[test]
    fn test_missing_rules_array() {
        let bad_policy = r#"{"not_rules": []}"#;
        let result = load_policy_from_string(bad_policy, PolicyFormat::Json);

        assert!(matches!(result, Err(PolicyLoadError::MissingRulesArray)));
    }

    #[test]
    fn test_invalid_json() {
        let bad_json = "{ this is not valid json }";
        let result = load_policy_from_string(bad_json, PolicyFormat::Json);

        assert!(matches!(result, Err(PolicyLoadError::JsonParseError(_))));
    }

    #[test]
    fn test_invalid_yaml() {
        let bad_yaml = "rules:\n  - [invalid yaml structure";
        let result = load_policy_from_string(bad_yaml, PolicyFormat::Yaml);

        assert!(matches!(result, Err(PolicyLoadError::YamlParseError(_))));
    }

    #[test]
    fn test_skipped_malformed_rules() {
        let policy_with_bad_rule = r#"{
            "rules": [
                {
                    "name": "valid-rule",
                    "effect": "allow",
                    "principals": ["*"],
                    "actions": ["*"],
                    "resources": ["*"]
                },
                {
                    "name": "missing-effect-rule",
                    "principals": ["*"]
                }
            ]
        }"#;

        let result = load_policy_from_string(policy_with_bad_rule, PolicyFormat::Json).unwrap();

        assert_eq!(result.rules.len(), 1);
        assert_eq!(result.skipped_rules, 1);
        assert_eq!(result.rules[0].name, "valid-rule");
    }

    #[test]
    fn test_yaml_with_required_labels() {
        let yaml_with_labels = r#"rules:
  - name: allow-with-mfa
    effect: allow
    principals:
      - "agent:*"
    actions:
      - "sensitive.*"
    resources:
      - "*"
    required_labels:
      - mfa_verified
      - approved
"#;
        let result = load_policy_from_string(yaml_with_labels, PolicyFormat::Yaml).unwrap();

        assert_eq!(result.rules.len(), 1);
        assert_eq!(
            result.rules[0].required_labels,
            vec!["mfa_verified", "approved"]
        );
    }

    #[test]
    fn test_yaml_with_max_delegation_depth() {
        let yaml_with_depth = r#"rules:
  - name: allow-with-depth
    effect: allow
    principals:
      - "agent:*"
    actions:
      - "*"
    resources:
      - "*"
    max_delegation_depth: 3
"#;
        let result = load_policy_from_string(yaml_with_depth, PolicyFormat::Yaml).unwrap();

        assert_eq!(result.rules.len(), 1);
        assert_eq!(result.rules[0].max_delegation_depth, Some(3));
    }

    #[test]
    fn test_file_not_found() {
        let result = load_policy_file("/nonexistent/path/to/policy.json");

        assert!(matches!(result, Err(PolicyLoadError::IoError(_))));
    }

    #[test]
    fn test_empty_rules_array() {
        let empty_rules = r#"{"rules": []}"#;
        let result = load_policy_from_string(empty_rules, PolicyFormat::Json).unwrap();

        assert_eq!(result.rules.len(), 0);
        assert_eq!(result.skipped_rules, 0);
    }
}
