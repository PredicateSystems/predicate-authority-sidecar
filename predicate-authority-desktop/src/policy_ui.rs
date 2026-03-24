//! Policy templates, rule drafts, and validation using the sidecar `policy_loader`.

use predicate_authorityd::models::{PolicyEffect, PolicyRule};
use predicate_authorityd::policy_loader::{self};
use std::path::Path;

pub use predicate_authorityd::policy_loader::PolicyFormat;

#[derive(Debug, Clone)]
pub struct RuleDraft {
    pub name: String,
    pub allow: bool,
    pub principals: String,
    pub actions: String,
    pub resources: String,
}

impl Default for RuleDraft {
    fn default() -> Self {
        Self {
            name: String::new(),
            allow: true,
            principals: "agent:*".to_string(),
            actions: "browser.*".to_string(),
            resources: "https://*".to_string(),
        }
    }
}

impl RuleDraft {
    pub fn from_rule(r: &PolicyRule) -> Self {
        Self {
            name: r.name.clone(),
            allow: r.effect == PolicyEffect::Allow,
            principals: r.principals.join(", "),
            actions: r.actions.join(", "),
            resources: r.resources.join(", "),
        }
    }

    fn split_list(s: &str) -> Vec<String> {
        s.split(|c: char| c == ',' || c == '\n')
            .map(str::trim)
            .filter(|x| !x.is_empty())
            .map(String::from)
            .collect()
    }

    pub fn to_rule(&self) -> Result<PolicyRule, String> {
        let name = self.name.trim();
        if name.is_empty() {
            return Err("rule name is empty".into());
        }
        let principals = Self::split_list(&self.principals);
        let actions = Self::split_list(&self.actions);
        let resources = Self::split_list(&self.resources);
        if principals.is_empty() || actions.is_empty() || resources.is_empty() {
            return Err(format!(
                "rule \"{name}\": principals, actions, and resources must each have at least one entry"
            ));
        }
        Ok(PolicyRule {
            name: name.to_string(),
            effect: if self.allow {
                PolicyEffect::Allow
            } else {
                PolicyEffect::Deny
            },
            principals,
            actions,
            resources,
            required_labels: vec![],
            max_delegation_depth: None,
            inject_headers: None,
            inject_headers_from_file: None,
            inject_env: None,
            inject_env_from_file: None,
        })
    }
}

pub fn drafts_to_rules(drafts: &[RuleDraft]) -> Result<Vec<PolicyRule>, String> {
    drafts.iter().map(RuleDraft::to_rule).collect()
}

/// Named starter policies (template index).
pub fn template_rules(index: usize) -> Vec<PolicyRule> {
    match index {
        0 => vec![
            PolicyRule {
                name: "allow-browser-https".into(),
                effect: PolicyEffect::Allow,
                principals: vec!["agent:*".into()],
                actions: vec!["browser.*".into()],
                resources: vec!["https://*".into()],
                required_labels: vec![],
                max_delegation_depth: None,
                inject_headers: None,
                inject_headers_from_file: None,
                inject_env: None,
                inject_env_from_file: None,
            },
            PolicyRule {
                name: "deny-admin".into(),
                effect: PolicyEffect::Deny,
                principals: vec!["agent:*".into()],
                actions: vec!["admin.*".into()],
                resources: vec!["*".into()],
                required_labels: vec![],
                max_delegation_depth: None,
                inject_headers: None,
                inject_headers_from_file: None,
                inject_env: None,
                inject_env_from_file: None,
            },
        ],
        1 => vec![PolicyRule {
            name: "allow-browser-only".into(),
            effect: PolicyEffect::Allow,
            principals: vec!["agent:*".into()],
            actions: vec!["browser.*".into()],
            resources: vec!["https://*".into()],
            required_labels: vec![],
            max_delegation_depth: None,
            inject_headers: None,
            inject_headers_from_file: None,
            inject_env: None,
            inject_env_from_file: None,
        }],
        _ => vec![],
    }
}

pub const TEMPLATE_LABELS: [&str; 3] = [
    "Browser + deny admin",
    "Browser HTTPS only",
    "Empty (add rules)",
];

pub fn validate_rules_json_or_yaml(content: &str, path: &Path) -> Result<Vec<PolicyRule>, String> {
    let format = policy_loader::detect_format(path);
    policy_loader::load_policy_from_string(content, format)
        .map(|r| r.rules)
        .map_err(|e| e.to_string())
}

pub fn validate_rules_raw(content: &str, format: PolicyFormat) -> Result<Vec<PolicyRule>, String> {
    policy_loader::load_policy_from_string(content, format)
        .map(|r| r.rules)
        .map_err(|e| e.to_string())
}

pub fn save_rules_json(path: &Path, rules: &[PolicyRule]) -> Result<(), String> {
    let doc = serde_json::json!({ "rules": rules });
    match policy_loader::detect_format(path) {
        PolicyFormat::Json => {
            let pretty = serde_json::to_string_pretty(&doc).map_err(|e| e.to_string())?;
            std::fs::write(path, pretty).map_err(|e| e.to_string())
        }
        PolicyFormat::Yaml => {
            let yaml = serde_yaml::to_string(&doc).map_err(|e| e.to_string())?;
            std::fs::write(path, yaml).map_err(|e| e.to_string())
        }
    }
}
