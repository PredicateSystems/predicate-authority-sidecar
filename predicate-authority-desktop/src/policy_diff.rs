//! Unified line diff for policy JSON snapshots.

use similar::TextDiff;

pub fn unified_line_diff(old: &str, new: &str) -> String {
    let diff = TextDiff::from_lines(old, new);
    let mut u = diff.unified_diff();
    u.context_radius(3);
    u.header("last_applied", "current");
    let s = format!("{u}");
    if s.trim().is_empty() {
        "(no differences)".into()
    } else {
        s
    }
}
