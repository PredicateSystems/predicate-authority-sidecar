//! Scope subset validation for delegation.
//!
//! Determines if a requested scope (action, resource) is a valid subset
//! of a parent's scope. Used to enforce scope narrowing in delegation chains.
//!
//! # Subset Rules
//!
//! - Exact match: `"browser.click"` is subset of `"browser.click"`
//! - Wildcard narrowing: `"browser.click"` is subset of `"browser.*"`
//! - Wildcard NOT subset of specific: `"browser.*"` is NOT subset of `"browser.click"`
//! - Universal wildcard: `"browser.click"` is subset of `"*"`

use glob::Pattern;

/// Determines if `requested_action` is a valid subset of `parent_action`.
///
/// # Subset Rules
/// - Exact match: `"browser.click"` is subset of `"browser.click"` ✓
/// - Wildcard narrowing: `"browser.click"` is subset of `"browser.*"` ✓
/// - Universal wildcard: `"browser.click"` is subset of `"*"` ✓
/// - Wildcard NOT subset of specific: `"browser.*"` is NOT subset of `"browser.click"` ✗
/// - Different prefix: `"fs.read"` is NOT subset of `"browser.*"` ✗
///
/// # Examples
/// ```
/// use predicate_authorityd::policy::subset::is_action_subset;
///
/// assert!(is_action_subset("browser.click", "browser.click"));
/// assert!(is_action_subset("browser.*", "browser.click"));
/// assert!(is_action_subset("*", "browser.click"));
/// assert!(!is_action_subset("browser.click", "browser.*"));
/// ```
pub fn is_action_subset(parent_action: &str, requested_action: &str) -> bool {
    is_pattern_subset(parent_action, requested_action)
}

/// Determines if `requested_resource` is a valid subset of `parent_resource`.
///
/// Uses the same rules as action subset validation.
///
/// # Examples
/// ```
/// use predicate_authorityd::policy::subset::is_resource_subset;
///
/// assert!(is_resource_subset("https://*", "https://example.com"));
/// assert!(is_resource_subset("button#*", "button#submit"));
/// assert!(!is_resource_subset("button#submit", "button#*"));
/// ```
pub fn is_resource_subset(parent_resource: &str, requested_resource: &str) -> bool {
    is_pattern_subset(parent_resource, requested_resource)
}

/// Validates both action and resource scope subset in one call.
///
/// Returns `true` if both the requested action AND resource are
/// valid subsets of the parent's scope.
pub fn is_scope_subset(
    parent_action: &str,
    parent_resource: &str,
    requested_action: &str,
    requested_resource: &str,
) -> bool {
    is_action_subset(parent_action, requested_action)
        && is_resource_subset(parent_resource, requested_resource)
}

/// Core pattern subset validation logic.
///
/// A pattern P1 is a subset of P2 if:
/// 1. P2 is `"*"` (universal wildcard)
/// 2. P1 equals P2 (exact match)
/// 3. P2 contains wildcards and P1 matches P2's pattern AND
///    P1 has equal or fewer wildcards than P2
fn is_pattern_subset(parent_pattern: &str, requested_pattern: &str) -> bool {
    // Universal wildcard allows everything
    if parent_pattern == "*" {
        return true;
    }

    // Exact match
    if parent_pattern == requested_pattern {
        return true;
    }

    // If requested contains wildcards but parent doesn't, it's NOT a subset
    // (requested is broader than parent)
    let requested_has_wildcard = has_glob_wildcards(requested_pattern);
    let parent_has_wildcard = has_glob_wildcards(parent_pattern);

    if requested_has_wildcard && !parent_has_wildcard {
        // e.g., requested="browser.*" but parent="browser.click"
        // This is escalation, not narrowing
        return false;
    }

    // If parent has wildcards, check if requested matches the pattern
    if parent_has_wildcard {
        // The requested pattern must match the parent's glob pattern
        // AND the requested must not expand beyond parent's scope
        if let Ok(pattern) = Pattern::new(parent_pattern) {
            if pattern.matches(requested_pattern) {
                // Also ensure requested isn't a superset by checking wildcard expansion
                // If requested also has wildcards, we need to verify it's not broader
                if requested_has_wildcard {
                    // Compare wildcard specificity
                    // "browser.*" is NOT subset of "browser.click.*"
                    // "browser.click.*" IS subset of "browser.*"
                    return is_wildcard_narrower_or_equal(parent_pattern, requested_pattern);
                }
                return true;
            }
        }
    }

    false
}

/// Check if a pattern contains glob wildcards
fn has_glob_wildcards(pattern: &str) -> bool {
    pattern.contains('*') || pattern.contains('?') || pattern.contains('[')
}

/// Compare wildcard patterns to determine if requested is narrower or equal to parent.
///
/// This handles cases like:
/// - "browser.*" vs "browser.click.*" -> browser.click.* is narrower
/// - "*.click" vs "browser.*" -> different axes, need careful comparison
fn is_wildcard_narrower_or_equal(parent: &str, requested: &str) -> bool {
    // Split patterns into segments
    let parent_segments: Vec<&str> = parent.split('.').collect();
    let requested_segments: Vec<&str> = requested.split('.').collect();

    // More segments generally means more specific (narrower)
    if requested_segments.len() < parent_segments.len() {
        // Fewer segments with wildcards = broader, not narrower
        // But we need to check if wildcard positions differ
        let parent_wildcards: usize = parent_segments.iter().filter(|s| s.contains('*')).count();
        let requested_wildcards: usize = requested_segments
            .iter()
            .filter(|s| s.contains('*'))
            .count();

        // If requested has more wildcards with fewer segments, it's broader
        if requested_wildcards > parent_wildcards {
            return false;
        }
    }

    // Check each segment
    for (i, parent_seg) in parent_segments.iter().enumerate() {
        if i >= requested_segments.len() {
            // Requested is shorter, could be broader
            // If parent has more specific segments after, requested is broader
            return false;
        }

        let requested_seg = requested_segments[i];

        // If parent segment is wildcard but requested isn't, that's narrowing (good)
        if *parent_seg == "*" && requested_seg != "*" {
            continue;
        }

        // If requested segment is wildcard but parent isn't, that's expansion (bad)
        if requested_seg == "*" && *parent_seg != "*" {
            return false;
        }

        // If both are specific, they must match
        if !parent_seg.contains('*') && !requested_seg.contains('*') && *parent_seg != requested_seg
        {
            return false;
        }
    }

    // Requested can have more segments (more specific) - that's allowed
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Action subset tests ---

    #[test]
    fn test_exact_action_match() {
        assert!(is_action_subset("browser.click", "browser.click"));
        assert!(is_action_subset("fs.read", "fs.read"));
        assert!(is_action_subset("http.get", "http.get"));
    }

    #[test]
    fn test_wildcard_parent_allows_specific() {
        assert!(is_action_subset("browser.*", "browser.click"));
        assert!(is_action_subset("browser.*", "browser.type"));
        assert!(is_action_subset("browser.*", "browser.navigate"));
        assert!(is_action_subset("*", "browser.click"));
        assert!(is_action_subset("*", "fs.read"));
    }

    #[test]
    fn test_specific_parent_denies_wildcard() {
        // Wildcard request is NOT a subset of specific parent
        assert!(!is_action_subset("browser.click", "browser.*"));
        assert!(!is_action_subset("fs.read", "fs.*"));
        assert!(!is_action_subset("http.get", "*"));
    }

    #[test]
    fn test_different_prefix_not_subset() {
        assert!(!is_action_subset("browser.*", "fs.read"));
        assert!(!is_action_subset("browser.click", "fs.read"));
        assert!(!is_action_subset("http.*", "browser.click"));
    }

    #[test]
    fn test_nested_wildcard_narrowing() {
        // More specific wildcard is subset of broader wildcard
        assert!(is_action_subset("browser.*", "browser.click.*"));
        assert!(is_action_subset("*.*", "browser.*"));
    }

    // --- Resource subset tests ---

    #[test]
    fn test_exact_resource_match() {
        assert!(is_resource_subset(
            "https://example.com",
            "https://example.com"
        ));
        assert!(is_resource_subset("button#submit", "button#submit"));
    }

    #[test]
    fn test_wildcard_resource_allows_specific() {
        assert!(is_resource_subset("https://*", "https://example.com"));
        assert!(is_resource_subset("button#*", "button#submit"));
        assert!(is_resource_subset("*", "https://example.com"));
    }

    #[test]
    fn test_specific_resource_denies_wildcard() {
        assert!(!is_resource_subset("https://example.com", "https://*"));
        assert!(!is_resource_subset("button#submit", "button#*"));
    }

    // --- Combined scope tests ---

    #[test]
    fn test_scope_subset_both_match() {
        assert!(is_scope_subset(
            "browser.*",
            "https://*",
            "browser.click",
            "https://example.com"
        ));
    }

    #[test]
    fn test_scope_subset_action_exceeds() {
        assert!(!is_scope_subset(
            "browser.click",
            "https://*",
            "browser.*", // Exceeds parent action scope
            "https://example.com"
        ));
    }

    #[test]
    fn test_scope_subset_resource_exceeds() {
        assert!(!is_scope_subset(
            "browser.*",
            "https://example.com",
            "browser.click",
            "https://*" // Exceeds parent resource scope
        ));
    }

    #[test]
    fn test_scope_subset_both_exceed() {
        assert!(!is_scope_subset(
            "browser.click",
            "https://example.com",
            "browser.*",
            "https://*"
        ));
    }

    // --- Edge cases ---

    #[test]
    fn test_empty_patterns() {
        assert!(is_action_subset("", ""));
        assert!(!is_action_subset("browser.click", ""));
        assert!(!is_action_subset("", "browser.click"));
    }

    #[test]
    fn test_universal_wildcard() {
        // Universal wildcard allows anything
        assert!(is_action_subset("*", ""));
        assert!(is_action_subset("*", "anything.at.all"));
        assert!(is_resource_subset("*", "any://resource/path"));
    }

    #[test]
    fn test_question_mark_wildcard() {
        // Single-character wildcard
        assert!(is_action_subset("browser.clic?", "browser.click"));
        assert!(!is_action_subset("browser.click", "browser.clic?"));
    }

    #[test]
    fn test_path_style_resources() {
        assert!(is_resource_subset(
            "/home/*/data/*",
            "/home/user/data/file.txt"
        ));
        assert!(!is_resource_subset(
            "/home/user/data/file.txt",
            "/home/*/data/*"
        ));
    }
}
