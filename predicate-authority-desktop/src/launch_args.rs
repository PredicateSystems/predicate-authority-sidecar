//! Build CLI arguments for spawning `predicate-authorityd` (globals before `run`).

#[derive(Debug, Clone)]
pub struct LaunchConfig<'a> {
    pub config_path: &'a str,
    pub policy_path: &'a str,
    pub host: &'a str,
    pub port: &'a str,
    pub web_ui: bool,
    pub audit_mode: bool,
    pub reload_secret: &'a str,
}

pub fn build_sidecar_args(cfg: LaunchConfig<'_>) -> Result<Vec<String>, String> {
    let mut args: Vec<String> = Vec::new();
    let config = cfg.config_path.trim();
    if !config.is_empty() {
        args.push("--config".into());
        args.push(config.to_string());
    }
    let policy = cfg.policy_path.trim();
    if !policy.is_empty() {
        args.push("--policy-file".into());
        args.push(policy.to_string());
    }
    let host = cfg.host.trim();
    if host.is_empty() {
        return Err("host is empty".into());
    }
    let port = cfg.port.trim();
    if port.is_empty() {
        return Err("port is empty".into());
    }
    args.push("--host".into());
    args.push(host.to_string());
    args.push("--port".into());
    args.push(port.to_string());
    if cfg.web_ui {
        args.push("--web-ui".into());
    }
    if cfg.audit_mode {
        args.push("--audit-mode".into());
    }
    let secret = cfg.reload_secret.trim();
    if !secret.is_empty() {
        args.push("--policy-reload-secret".into());
        args.push(secret.to_string());
    }
    Ok(args)
}

/// Run `predicate-authorityd check-config -c <path>` and return stdout/stderr.
pub fn run_check_config(binary: &str, config_path: &str) -> Result<String, String> {
    let c = config_path.trim();
    if c.is_empty() {
        return Err("Set a config file path first.".into());
    }
    let bin = binary.trim();
    if bin.is_empty() {
        return Err("Set sidecar binary path first.".into());
    }
    let out = std::process::Command::new(bin)
        .args(["check-config", "--config", c])
        .output()
        .map_err(|e| format!("failed to run check-config: {e}"))?;
    let mut s = String::new();
    if !out.stdout.is_empty() {
        s.push_str(&String::from_utf8_lossy(&out.stdout));
    }
    if !out.stderr.is_empty() {
        if !s.is_empty() {
            s.push('\n');
        }
        s.push_str(&String::from_utf8_lossy(&out.stderr));
    }
    if s.is_empty() {
        s = format!("exit code {}", out.status);
    } else if !out.status.success() {
        s = format!("(exit {})\n{s}", out.status);
    }
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minimal_args() {
        let args = build_sidecar_args(LaunchConfig {
            config_path: "",
            policy_path: "",
            host: "127.0.0.1",
            port: "8787",
            web_ui: false,
            audit_mode: false,
            reload_secret: "",
        })
        .unwrap();
        assert_eq!(
            args,
            vec!["--host", "127.0.0.1", "--port", "8787",]
                .into_iter()
                .map(String::from)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn with_policy_and_secret() {
        let args = build_sidecar_args(LaunchConfig {
            config_path: "",
            policy_path: "/tmp/p.json",
            host: "0.0.0.0",
            port: "9000",
            web_ui: true,
            audit_mode: true,
            reload_secret: "abc",
        })
        .unwrap();
        assert!(args.contains(&"--policy-file".into()));
        assert!(args.contains(&"/tmp/p.json".into()));
        assert!(args.contains(&"--web-ui".into()));
        assert!(args.contains(&"--audit-mode".into()));
        assert!(args.contains(&"--policy-reload-secret".into()));
        assert!(args.contains(&"abc".into()));
    }
}
