//! Named launch presets persisted under the OS config directory.

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct LaunchPreset {
    pub name: String,
    pub binary_path: String,
    pub config_path: String,
    pub policy_path: String,
    pub host: String,
    pub port: String,
    pub web_ui: bool,
    pub audit_mode: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct PersistedState {
    pub presets: Vec<LaunchPreset>,
    /// When `apply_startup_preset` is true, this preset is applied on launch if it exists.
    pub startup_preset_name: Option<String>,
    pub apply_startup_preset: bool,
}

pub fn state_path() -> Option<PathBuf> {
    dirs::config_dir().map(|d| d.join("predicate-authority-desktop").join("state.json"))
}

pub fn load() -> PersistedState {
    let Some(path) = state_path() else {
        return PersistedState::default();
    };
    let Ok(bytes) = fs::read(&path) else {
        return PersistedState::default();
    };
    serde_json::from_slice(&bytes).unwrap_or_default()
}

pub fn save(state: &PersistedState) -> Result<(), String> {
    let Some(path) = state_path() else {
        return Err("no config directory".into());
    };
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    let json = serde_json::to_string_pretty(state).map_err(|e| e.to_string())?;
    fs::write(path, json).map_err(|e| e.to_string())
}
