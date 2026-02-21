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

**IMPORTANT:** CLI arguments must be placed **before** the `run` subcommand.

```
GLOBAL OPTIONS (use before 'run'):
  -c, --config <FILE>           Path to TOML config file [env: PREDICATE_CONFIG]
      --host <HOST>             Host to bind to [env: PREDICATE_HOST] [default: 127.0.0.1]
      --port <PORT>             Port to bind to [env: PREDICATE_PORT] [default: 8787]
      --mode <MODE>             local_only or cloud_connected [env: PREDICATE_MODE]
      --policy-file <PATH>      Path to policy JSON [env: PREDICATE_POLICY_FILE]
      --identity-file <PATH>    Path to local identity registry [env: PREDICATE_IDENTITY_FILE]
      --log-level <LEVEL>       trace, debug, info, warn, error [env: PREDICATE_LOG_LEVEL]
      --control-plane-url <URL> Control-plane URL [env: PREDICATE_CONTROL_PLANE_URL]
      --tenant-id <ID>          Tenant ID [env: PREDICATE_TENANT_ID]
      --project-id <ID>         Project ID [env: PREDICATE_PROJECT_ID]
      --predicate-api-key <KEY> API key [env: PREDICATE_API_KEY]
      --sync-enabled            Enable control-plane sync [env: PREDICATE_SYNC_ENABLED]
      --fail-open               Fail open if control-plane unreachable [env: PREDICATE_FAIL_OPEN]

IDENTITY PROVIDER OPTIONS:
      --identity-mode <MODE>    local, local-idp, oidc, entra, or okta [env: PREDICATE_IDENTITY_MODE]
      --allow-local-fallback    Allow local/local-idp in cloud_connected mode [env: PREDICATE_ALLOW_LOCAL_FALLBACK]
      --idp-token-ttl-s <SECS>  IdP token TTL seconds [env: PREDICATE_IDP_TOKEN_TTL_S] [default: 300]
      --mandate-ttl-s <SECS>    Mandate TTL seconds [env: PREDICATE_MANDATE_TTL_S] [default: 300]

LOCAL IDP OPTIONS (for identity-mode=local-idp):
      --local-idp-issuer <URL>  Issuer URL [env: LOCAL_IDP_ISSUER]
      --local-idp-audience <AUD> Audience [env: LOCAL_IDP_AUDIENCE]
      --local-idp-signing-key-env <VAR> Env var for signing key [default: LOCAL_IDP_SIGNING_KEY]

OIDC OPTIONS (for identity-mode=oidc):
      --oidc-issuer <URL>       Issuer URL [env: OIDC_ISSUER]
      --oidc-client-id <ID>     Client ID [env: OIDC_CLIENT_ID]
      --oidc-audience <AUD>     Audience [env: OIDC_AUDIENCE]

ENTRA OPTIONS (for identity-mode=entra):
      --entra-tenant-id <ID>    Tenant ID [env: ENTRA_TENANT_ID]
      --entra-client-id <ID>    Client ID [env: ENTRA_CLIENT_ID]
      --entra-audience <AUD>    Audience [env: ENTRA_AUDIENCE]

OKTA OPTIONS (for identity-mode=okta):
      --okta-issuer <URL>       Issuer URL [env: OKTA_ISSUER]
      --okta-client-id <ID>     Client ID [env: OKTA_CLIENT_ID]
      --okta-audience <AUD>     Audience [env: OKTA_AUDIENCE]
      --okta-required-claims <CLAIMS> Required claims (comma-separated) [env: OKTA_REQUIRED_CLAIMS]
      --okta-required-scopes <SCOPES> Required scopes (comma-separated) [env: OKTA_REQUIRED_SCOPES]
      --okta-required-roles <ROLES> Required roles/groups (comma-separated) [env: OKTA_REQUIRED_ROLES]
      --okta-allowed-tenants <IDS> Allowed tenant IDs (comma-separated) [env: OKTA_ALLOWED_TENANTS]
      --okta-tenant-claim <NAME> Claim for tenant ID [env: OKTA_TENANT_CLAIM] [default: tenant_id]
      --okta-scope-claim <NAME> Claim for scopes [env: OKTA_SCOPE_CLAIM] [default: scope]
      --okta-role-claim <NAME>  Claim for roles [env: OKTA_ROLE_CLAIM] [default: groups]

COMMANDS:
  run          Start the daemon (default)
  init-config  Generate example config file
  check-config Validate config file
  version      Show version info
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
./predicate-authorityd --mode local_only --policy-file policy.json run
```

### Cloud Connected

Sync policies and revocations from control plane:

```bash
./predicate-authorityd \
  --mode cloud_connected \
  --control-plane-url https://api.predicatesystems.dev \
  --tenant-id your-tenant \
  --project-id your-project \
  --predicate-api-key $PREDICATE_API_KEY \
  --sync-enabled \
  run
```

## Identity Provider Modes

The sidecar supports multiple identity provider modes for token validation on authorization requests.

### Local Mode (Default)

No token validation required. Suitable for development and trusted environments:

```bash
./predicate-authorityd --identity-mode local --policy-file policy.json run
```

### Local IDP Mode

Self-issued JWT tokens for ephemeral task identities:

```bash
export LOCAL_IDP_SIGNING_KEY="your-signing-key"

./predicate-authorityd \
  --identity-mode local-idp \
  --local-idp-issuer "http://localhost/predicate-local-idp" \
  --local-idp-audience "api://predicate-authority" \
  --policy-file policy.json \
  run
```

### OIDC Mode

Generic OIDC provider integration:

```bash
./predicate-authorityd \
  --identity-mode oidc \
  --oidc-issuer "https://your-oidc-provider/.well-known/openid-configuration" \
  --oidc-client-id "your-client-id" \
  --oidc-audience "api://predicate-authority" \
  --policy-file policy.json \
  run
```

### Entra Mode

Microsoft Entra ID (Azure AD) integration:

```bash
./predicate-authorityd \
  --identity-mode entra \
  --entra-tenant-id "your-tenant-id" \
  --entra-client-id "your-client-id" \
  --entra-audience "api://predicate-authority" \
  --policy-file policy.json \
  run
```

### Okta Mode

Enterprise Okta integration with JWKS validation:

```bash
export OKTA_ISSUER="https://your-org.okta.com/oauth2/default"
export OKTA_CLIENT_ID="your-client-id"
export OKTA_AUDIENCE="api://predicate-authority"

./predicate-authorityd \
  --identity-mode okta \
  --okta-issuer "$OKTA_ISSUER" \
  --okta-client-id "$OKTA_CLIENT_ID" \
  --okta-audience "$OKTA_AUDIENCE" \
  --okta-required-claims "sub,tenant_id" \
  --okta-required-scopes "authority:check" \
  --okta-required-roles "authority-operator" \
  --okta-allowed-tenants "tenant-a,tenant-b" \
  --idp-token-ttl-s 300 \
  --mandate-ttl-s 300 \
  --policy-file policy.json \
  run
```

### Safety Notes

- **TTL alignment**: Startup enforces `idp-token-ttl-s >= mandate-ttl-s` to prevent mandates from outliving identity session controls.
- **Cloud-connected safety**: In `cloud_connected` mode, using `local` or `local-idp` identity mode requires explicit `--allow-local-fallback` flag to prevent accidental downgrade to local identity behavior.

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
