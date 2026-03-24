# Predicate Authority Desktop

GUI companion for [`predicate-authorityd`](../): start/stop/**restart** the sidecar, tail logs, poll `/health` and `/status`, open the Web UI from the printed URL, and edit policies via **templates**, a **simple rule builder** (duplicate / reorder), or **raw JSON/YAML** with validation via the same `policy_loader` as the daemon. **Import/export** policies, **diff vs last successful reload**, optional **keychain** for the reload secret, **`check-config`** against your TOML, and **diagnostics ZIP** export from the Logs tab. **Startup presets** (saved under the OS config directory) can restore paths/host/flags on launch. If `predicate-authorityd` sits **next to** the desktop binary, the app offers **Use as binary** and can run **`--version`**. **Reload** uses `POST /policy/reload` with optional `Authorization: Bearer` when you configure a reload secret.

## Build

From the workspace root (`rust-predicate-authorityd/`):

```bash
cargo build -p predicate-authority-desktop --release
```

Binary: `target/release/predicate-authority-desktop`

## Run

1. Set **Sidecar binary** to your `predicate-authorityd` executable (e.g. `target/release/predicate-authorityd`).
2. Set **Policy file** to a path (e.g. `./policy.json`).
3. Optionally set **Config TOML**, **reload secret** (must match `--policy-reload-secret` on the daemon), host/port, **Web UI**, **Audit mode**.
4. **Start sidecar**, then **Open dashboard** once the log line `Web UI enabled: http://...` appears (if Web UI is on).

## Workspace layout

This crate lives next to the daemon in a Cargo workspace; the root `Cargo.toml` lists `members = [".", "predicate-authority-desktop"]`.
