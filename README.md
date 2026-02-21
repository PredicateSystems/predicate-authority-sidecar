# predicate-authorityd (Rust)

A high-performance Rust implementation of the Predicate Authority sidecar daemon.

## Overview

This sidecar enforces policy rules for agent actions, providing:
- Policy-based authorization decisions
- Mandate signing with JWT (ES256/HS256)
- Local identity registry
- Audit logging with proof ledger
- Control plane sync (cloud-connected mode)
- Wire-compatible with TypeScript and Python SDKs

## Installation

### Download Binary

Download the latest release for your platform from [GitHub Releases](https://github.com/PredicateSystems/predicate-authority-sidecar/releases):

- **Linux x64**: `predicate-authorityd-linux-x64.tar.gz`
- **Linux x64 (musl)**: `predicate-authorityd-linux-x64-musl.tar.gz`
- **macOS x64**: `predicate-authorityd-darwin-x64.tar.gz`
- **macOS ARM64**: `predicate-authorityd-darwin-arm64.tar.gz`
- **Windows x64**: `predicate-authorityd-windows-x64.zip`

```bash
# Extract and make executable
tar -xzf predicate-authorityd-*.tar.gz
chmod +x predicate-authorityd
```

### Build from Source

```bash
cargo build --release
./target/release/predicate-authorityd
```

## Quick Start

```bash
# Generate example configuration file
./predicate-authorityd init-config

# Validate configuration
./predicate-authorityd check-config -c predicate-authorityd.toml

# Run with default settings
./predicate-authorityd run

# Run with custom port and policy file
./predicate-authorityd run --port 8787 --policy-file policy.json
```

## Commands

| Command | Description |
|---------|-------------|
| `run` | Start the daemon (default) |
| `init-config` | Generate example configuration file |
| `check-config` | Validate configuration file |
| `version` | Show version and build info |

## CLI Options

```
Options:
  -c, --config <CONFIG>                Path to configuration file (TOML)
      --host <HOST>                    Host to bind to [env: PREDICATE_HOST]
      --port <PORT>                    Port to bind to [env: PREDICATE_PORT]
      --mode <MODE>                    Operating mode: local_only or cloud_connected
      --policy-file <POLICY_FILE>      Path to policy JSON file
      --identity-file <IDENTITY_FILE>  Path to local identity registry JSON file
      --log-level <LOG_LEVEL>          Log level: trace, debug, info, warn, error
      --control-plane-url <URL>        Control-plane base URL
      --tenant-id <TENANT_ID>          Tenant ID for control-plane
      --project-id <PROJECT_ID>        Project ID for control-plane
      --predicate-api-key <API_KEY>    API key for control-plane authentication
      --sync-enabled                   Enable control-plane sync
      --fail-open                      Fail open if control-plane unreachable
  -h, --help                           Print help
  -V, --version                        Print version
```

## Configuration

Configuration can be provided via:
1. CLI arguments (highest priority)
2. Environment variables (e.g., `PREDICATE_PORT=8787`)
3. Configuration file (TOML)
4. Default values

### Configuration File

The daemon searches for configuration files in these locations:
- `./predicate-authorityd.toml`
- `./config/predicate-authorityd.toml`
- `~/.predicate/authorityd.toml`
- `/etc/predicate/authorityd.toml`

Generate an example configuration:

```bash
./predicate-authorityd init-config -o ./predicate-authorityd.toml
```

Example configuration:

```toml
[server]
host = "127.0.0.1"
port = 8787
mode = "local_only"  # or "cloud_connected"
shutdown_timeout_s = 30

[policy]
file = "/path/to/policy.json"
hot_reload = false
hot_reload_interval_s = 30

[identity]
file = "~/.predicate/local-identity-registry.json"
default_ttl_s = 900       # 15 minutes
queue_item_ttl_s = 86400  # 24 hours

[control_plane]
url = "https://api.predicatesystems.dev"
tenant_id = "your-tenant-id"
project_id = "your-project-id"
# api_key = "prefer-env-var-PREDICATE_API_KEY"
sync_enabled = false
sync_wait_timeout_s = 15.0
fail_open = true
timeout_s = 2.0
max_retries = 2

[logging]
level = "info"        # trace, debug, info, warn, error
format = "compact"    # compact, pretty, json
include_target = true
```

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/v1/authorize` | POST | Core authorization check |
| `/authorize` | POST | Legacy alias |
| `/health` | GET | Health check |
| `/status` | GET | Detailed status with stats |
| `/metrics` | GET | Prometheus-format metrics |
| `/policy/reload` | POST | Hot-reload policy rules |
| `/identity/task` | POST | Issue task identity |
| `/identity/revoke` | POST | Revoke identity |
| `/identity/list` | GET | List identities |
| `/revoke/principal` | POST | Revoke by principal |
| `/revoke/intent` | POST | Revoke by intent |
| `/revoke/mandate` | POST | Revoke mandate |
| `/ledger/flush-queue` | GET | Get flush queue |
| `/ledger/flush-ack` | POST | Acknowledge flush |
| `/ledger/flush-now` | POST | Force flush |
| `/ledger/requeue` | POST | Requeue item |
| `/ledger/dead-letter` | GET | Get dead letter queue |

## Authorization Request

```bash
curl -X POST http://127.0.0.1:8787/v1/authorize \
  -H "Content-Type: application/json" \
  -d '{
    "principal": "agent:web",
    "action": "browser.click",
    "resource": "https://example.com"
  }'
```

Response:
```json
{
  "allowed": true,
  "reason": "allowed",
  "missing_labels": []
}
```

## Policy Format

```json
{
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
      "principals": ["agent:*"],
      "actions": ["admin.*"],
      "resources": ["*"]
    },
    {
      "name": "require-verified-label",
      "effect": "allow",
      "principals": ["agent:secure"],
      "actions": ["sensitive.*"],
      "resources": ["*"],
      "required_labels": ["verified", "approved"]
    }
  ]
}
```

### Policy Effects

- `allow` - Permit the action
- `deny` - Explicitly deny (takes precedence over allow)

### Pattern Matching

Patterns support shell-style wildcards:
- `*` matches any sequence of characters
- `agent:*` matches any agent principal
- `browser.*` matches any browser action

## Operating Modes

### Local Only (Default)

Standalone mode with local policy file and identity registry:

```bash
./predicate-authorityd run --mode local_only --policy-file policy.json
```

### Cloud Connected

Sync policies and revocations from control plane:

```bash
./predicate-authorityd run \
  --mode cloud_connected \
  --control-plane-url https://api.predicatesystems.dev \
  --tenant-id your-tenant \
  --project-id your-project \
  --predicate-api-key $PREDICATE_API_KEY \
  --sync-enabled
```

## Graceful Shutdown

The daemon handles `SIGTERM` and `SIGINT` (Ctrl+C) for graceful shutdown, allowing in-flight requests to complete.

## Development

```bash
# Run tests
cargo test

# Run integration tests
cargo test --test integration_test

# Run with verbose logging
cargo run -- run --log-level debug

# Check formatting
cargo fmt --check

# Run lints
cargo clippy --all-targets --all-features -- -D warnings
```

## Architecture

See [DESIGN.md](DESIGN.md) for detailed architecture documentation.

## License

MIT
