//! Optional OS keychain storage for the policy reload secret.

use keyring::Entry;

const SERVICE: &str = "predicate-authority-desktop";
const ACCOUNT: &str = "policy_reload_secret";

pub fn save_reload_secret(secret: &str) -> Result<(), String> {
    let entry = Entry::new(SERVICE, ACCOUNT).map_err(|e| e.to_string())?;
    entry
        .set_password(secret)
        .map_err(|e| format!("keychain set failed: {e}"))
}

pub fn load_reload_secret() -> Result<String, String> {
    let entry = Entry::new(SERVICE, ACCOUNT).map_err(|e| e.to_string())?;
    entry
        .get_password()
        .map_err(|e| format!("keychain get failed: {e}"))
}

pub fn delete_reload_secret() -> Result<(), String> {
    let entry = Entry::new(SERVICE, ACCOUNT).map_err(|e| e.to_string())?;
    match entry.delete_credential() {
        Ok(()) => Ok(()),
        Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(format!("keychain delete failed: {e}")),
    }
}
