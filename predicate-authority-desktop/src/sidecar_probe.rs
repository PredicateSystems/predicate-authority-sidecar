//! Detect a `predicate-authorityd` binary next to the desktop app and query `--version`.

use std::path::{Path, PathBuf};
use std::process::Command;

#[cfg(windows)]
const SIDECAR_EXE: &str = "predicate-authorityd.exe";
#[cfg(not(windows))]
const SIDECAR_EXE: &str = "predicate-authorityd";

/// If the desktop executable sits in the same directory as `predicate-authorityd`, return that path.
pub fn sibling_sidecar_binary() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let dir = exe.parent()?;
    let cand = dir.join(SIDECAR_EXE);
    cand.is_file().then_some(cand)
}

/// Run `binary --version` and return trimmed stdout (or stderr if stdout empty).
pub fn version_for_binary(binary: &str) -> Result<String, String> {
    let bin = binary.trim();
    if bin.is_empty() {
        return Err("binary path is empty".into());
    }
    let out = Command::new(bin)
        .arg("--version")
        .output()
        .map_err(|e| format!("failed to run --version: {e}"))?;
    let mut s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if s.is_empty() {
        s = String::from_utf8_lossy(&out.stderr).trim().to_string();
    }
    if s.is_empty() {
        return Err(format!("no output (exit {})", out.status));
    }
    Ok(s)
}

/// File size in bytes and modified time (for display; not a cryptographic checksum).
pub fn binary_file_meta(path: &Path) -> Option<(u64, String)> {
    let meta = std::fs::metadata(path).ok()?;
    let len = meta.len();
    let mtime = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| format!("{}s since epoch", d.as_secs()))
        .unwrap_or_else(|| "unknown".into());
    Some((len, mtime))
}
