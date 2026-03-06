# Predicate Authority Sidecar User Manual

A comprehensive guide to installing, configuring, and operating the Predicate Authority sidecar daemon.

---

## Table of Contents

1. [Overview](#overview)
2. [Installation](#installation)
3. [Quick Start](#quick-start)
4. [Commands](#commands)
5. [Configuration](#configuration)
6. [Identity Provider Modes](#identity-provider-modes)
7. [Policy Files](#policy-files)
8. [API Reference](#api-reference)
9. [Terminal Dashboard](#terminal-dashboard)
10. [Delegation Chains](#delegation-chains)
11. [Security Features (Phase 5)](#security-features-phase-5)
12. [Troubleshooting](#troubleshooting)

---

## Overview

The Predicate Authority sidecar (`predicate-authorityd`) is a high-performance authorization daemon that enforces policy rules for AI agent actions. It provides:

- **Policy-based authorization** - Deterministic ALLOW/DENY decisions based on configurable rules
- **Mandate signing** - Short-lived cryptographic tokens (JWT ES256/HS256) for authorized actions
- **Identity provider integration** - Okta, Entra ID, OIDC, or local token issuance
- **Delegation chains** - Hierarchical mandate delegation with scope narrowing
- **Audit logging** - In-memory proof ledger for all authorization decisions
- **Control plane sync** - Optional enterprise features via cloud connection

### Architecture

```
┌─────────────┐     ┌─────────┐     ┌──────────────────────┐     ┌─────────┐
│  AI Agent   │────▶│  IdP    │────▶│  predicate-authority │────▶│ Backend │
│             │     │ (Okta)  │     │      (Sidecar)       │     │   API   │
└─────────────┘     └─────────┘     └──────────────────────┘     └─────────┘
```

1. Agent obtains access token from Identity Provider
2. Agent requests authorization from sidecar with token
3. Sidecar validates token, evaluates policy, issues mandate
4. Agent uses mandate to call backend API

---

## Installation

### Download Binary

Download the latest release for your platform:

| Platform | Binary |
|----------|--------|
| Linux x64 | `predicate-authorityd-linux-x64.tar.gz` |
| Linux x64 (musl) | `predicate-authorityd-linux-x64-musl.tar.gz` |
| macOS x64 | `predicate-authorityd-darwin-x64.tar.gz` |
| macOS ARM64 | `predicate-authorityd-darwin-arm64.tar.gz` |
| Windows x64 | `predicate-authorityd-windows-x64.zip` |

```bash
# Extract and make executable
tar -xzf predicate-authorityd-*.tar.gz
chmod +x predicate-authorityd

# Verify installation
./predicate-authorityd version
```

### Build from Source

```bash
git clone https://github.com/PredicateSystems/predicate-authority-sidecar.git
cd predicate-authority-sidecar/rust-predicate-authorityd

cargo build --release
./target/release/predicate-authorityd version
```

---

## Quick Start

### 1. Generate Configuration

```bash
./predicate-authorityd init-config -o predicate-authorityd.toml
```

### 2. Create a Policy File

Create `policy.json`:

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
    }
  ]
}
```

### 3. Start the Sidecar

```bash
./predicate-authorityd --policy-file policy.json run
```

### 4. Test Authorization

```bash
# This should be ALLOWED
curl -X POST http://127.0.0.1:8787/v1/authorize \
  -H "Content-Type: application/json" \
  -d '{
    "principal": "agent:web",
    "action": "browser.click",
    "resource": "https://example.com"
  }'

# Response: {"allowed":true,"reason":"allowed","missing_labels":[]}

# This should be DENIED
curl -X POST http://127.0.0.1:8787/v1/authorize \
  -H "Content-Type: application/json" \
  -d '{
    "principal": "agent:web",
    "action": "admin.delete",
    "resource": "/users/123"
  }'

# Response: {"allowed":false,"reason":"explicit_deny","missing_labels":[]}
```

---

## Commands

| Command | Description |
|---------|-------------|
| `run` | Start the daemon (default) |
| `dashboard` | Start with interactive TUI dashboard |
| `init-config` | Generate example configuration file |
| `check-config` | Validate configuration file |
| `version` | Show version and build info |

### Examples

```bash
# Run with default settings
./predicate-authorityd run

# Run with interactive dashboard
./predicate-authorityd dashboard

# Generate config file
./predicate-authorityd init-config -o config.toml

# Validate config
./predicate-authorityd check-config -c config.toml

# Show version
./predicate-authorityd version
```

---

## Configuration

Configuration can be provided via (in order of precedence):
1. CLI arguments (highest priority)
2. Environment variables
3. Configuration file (TOML)
4. Default values

### CLI Arguments

**Important:** CLI arguments must be placed **before** the subcommand.

```bash
# Correct
./predicate-authorityd --port 9000 --policy-file policy.json run

# Incorrect
./predicate-authorityd run --port 9000  # This won't work!
```

### Common Options

| Option | Environment Variable | Default | Description |
|--------|---------------------|---------|-------------|
| `--host` | `PREDICATE_HOST` | `127.0.0.1` | Host to bind to |
| `--port` | `PREDICATE_PORT` | `8787` | Port to bind to |
| `--mode` | `PREDICATE_MODE` | `local_only` | `local_only` or `cloud_connected` |
| `--policy-file` | `PREDICATE_POLICY_FILE` | - | Path to policy file |
| `--log-level` | `PREDICATE_LOG_LEVEL` | `info` | trace/debug/info/warn/error |
| `--identity-mode` | `PREDICATE_IDENTITY_MODE` | `local` | Identity provider mode |

### Security Options (Phase 5)

| Option | Environment Variable | Default | Description |
|--------|---------------------|---------|-------------|
| `--disable-ssrf-protection` | `PREDICATE_DISABLE_SSRF` | `false` | Disable SSRF blocking |
| `--require-signed-policy` | `PREDICATE_REQUIRE_SIGNED_POLICY` | `false` | Require Ed25519-signed policies |
| `--policy-signing-key` | `PREDICATE_POLICY_SIGNING_KEY` | - | Ed25519 public key (hex) |
| `--loop-guard-threshold` | `PREDICATE_LOOP_GUARD_THRESHOLD` | `5` | Failure count before blocking |
| `--loop-guard-window-s` | `PREDICATE_LOOP_GUARD_WINDOW_S` | `60` | Time window for failures |

### Configuration File

The daemon searches for configuration files in these locations:
- `./predicate-authorityd.toml`
- `./config/predicate-authorityd.toml`
- `~/.predicate/authorityd.toml`
- `/etc/predicate/authorityd.toml`

Example configuration:

```toml
[server]
host = "127.0.0.1"
port = 8787
mode = "local_only"
shutdown_timeout_s = 30

[policy]
file = "/path/to/policy.json"
hot_reload = false

[identity]
default_ttl_s = 900       # 15 minutes
queue_item_ttl_s = 86400  # 24 hours

[idp]
mode = "local"
idp_token_ttl_s = 300
mandate_ttl_s = 300

[logging]
level = "info"
format = "compact"
```

---

## Identity Provider Modes

The sidecar supports multiple identity provider modes for token validation.

### Local Mode (Default)

No token validation required. Use for development and trusted environments.

```bash
./predicate-authorityd --identity-mode local --policy-file policy.json run
```

Authorization requests don't require an `Authorization` header.

### Local IDP Mode

The sidecar issues its own JWT tokens. Use for air-gapped environments, CI/CD, or ephemeral task isolation.

```bash
export LOCAL_IDP_SIGNING_KEY="your-secret-signing-key"

./predicate-authorityd \
  --identity-mode local-idp \
  --local-idp-issuer "http://localhost/predicate-local-idp" \
  --local-idp-audience "api://predicate-authority" \
  --policy-file policy.json \
  run
```

Get a task identity token:

```bash
curl -X POST http://127.0.0.1:8787/identity/task \
  -H "Content-Type: application/json" \
  -d '{
    "principal_id": "agent:web",
    "task_id": "task-123",
    "ttl_seconds": 300
  }'

# Response: {"token": "eyJ...", "expires_at": "2024-..."}
```

Use the token for authorization:

```bash
curl -X POST http://127.0.0.1:8787/v1/authorize \
  -H "Authorization: Bearer eyJ..." \
  -H "Content-Type: application/json" \
  -d '{
    "principal": "agent:web",
    "action": "browser.click",
    "resource": "https://example.com"
  }'
```

### Okta Mode

Enterprise Okta integration with JWKS validation.

```bash
export OKTA_ISSUER="https://your-org.okta.com/oauth2/default"
export OKTA_CLIENT_ID="your-client-id"
export OKTA_AUDIENCE="api://predicate-authority"

./predicate-authorityd \
  --identity-mode okta \
  --okta-issuer "$OKTA_ISSUER" \
  --okta-client-id "$OKTA_CLIENT_ID" \
  --okta-audience "$OKTA_AUDIENCE" \
  --okta-required-scopes "authority:check" \
  --idp-token-ttl-s 300 \
  --mandate-ttl-s 300 \
  --policy-file policy.json \
  run
```

The sidecar validates tokens by:
1. Fetching JWKS from `${OKTA_ISSUER}/.well-known/jwks.json`
2. Verifying JWT signature using Okta's public keys
3. Checking issuer, audience, expiration, and required scopes

### Entra Mode

Microsoft Entra ID (Azure AD) integration.

```bash
./predicate-authorityd \
  --identity-mode entra \
  --entra-tenant-id "your-tenant-id" \
  --entra-client-id "your-client-id" \
  --entra-audience "api://predicate-authority" \
  --policy-file policy.json \
  run
```

### OIDC Mode

Generic OIDC provider integration.

```bash
./predicate-authorityd \
  --identity-mode oidc \
  --oidc-issuer "https://your-oidc-provider/.well-known/openid-configuration" \
  --oidc-client-id "your-client-id" \
  --oidc-audience "api://predicate-authority" \
  --policy-file policy.json \
  run
```

### TTL Safety

The sidecar enforces `idp-token-ttl-s >= mandate-ttl-s` to prevent mandates from outliving identity sessions.

---

## Policy Files

### Supported Formats

Policy files support JSON and YAML. Format is auto-detected by extension:
- `.json` - JSON format
- `.yaml` or `.yml` - YAML format

### Policy Schema

```json
{
  "rules": [
    {
      "name": "rule-name",
      "effect": "allow",
      "principals": ["agent:*"],
      "actions": ["browser.*"],
      "resources": ["https://*"],
      "required_labels": ["verified"]
    }
  ]
}
```

### Rule Fields

| Field | Required | Description |
|-------|----------|-------------|
| `name` | Yes | Unique rule identifier |
| `effect` | Yes | `allow` or `deny` |
| `principals` | Yes | List of principal patterns |
| `actions` | Yes | List of action patterns |
| `resources` | Yes | List of resource patterns |
| `required_labels` | No | Labels that must be present in request |

### Pattern Matching

Patterns support shell-style wildcards:

| Pattern | Matches |
|---------|---------|
| `*` | Any string |
| `agent:*` | Any agent principal |
| `browser.*` | Any browser action |
| `https://*` | Any HTTPS URL |
| `browser.click` | Exact match only |
| `**/workspace/**` | Any path containing `/workspace/` |

### Path Normalization (v0.5.7+)

For file system actions (`fs.read`, `fs.write`, `fs.list`, etc.), the sidecar automatically normalizes resource paths before policy evaluation:

- **Path traversal resolution**: `../` and `./` components are resolved
- **Home directory expansion**: `~` is expanded to the user's home directory
- **Redundant slashes removed**: `//` becomes `/`

**Example:**
```
Input:  ./workspace/../../../etc/passwd
After:  /etc/passwd
```

**Important:** Because paths are normalized to absolute paths, policy rules should use patterns that match absolute paths:

| Pattern Type | Example | Recommended |
|--------------|---------|-------------|
| Relative paths | `./workspace/**` | No - won't match normalized paths |
| Absolute paths | `/app/workspace/**` | Yes - matches specific location |
| Wildcard prefix | `**/workspace/**` | Yes - matches workspace anywhere |

**Recommended policy pattern for workspace access:**
```json
{
  "name": "allow-workspace-reads",
  "effect": "allow",
  "principals": ["agent:*"],
  "actions": ["fs.read"],
  "resources": ["**/workspace/**"]
}
```

This pattern matches `/app/workspace/file.txt`, `/home/user/workspace/src/index.ts`, etc.

### Evaluation Order

1. **DENY rules first** - Any matching DENY immediately blocks
2. **ALLOW rules** - Must match AND have all required_labels
3. **Default DENY** - If no rules match, action is blocked (fail-closed)

### Example Policy

```json
{
  "rules": [
    {
      "name": "deny-admin-actions",
      "effect": "deny",
      "principals": ["agent:*"],
      "actions": ["admin.*"],
      "resources": ["*"]
    },
    {
      "name": "allow-browser-https",
      "effect": "allow",
      "principals": ["agent:*"],
      "actions": ["browser.*"],
      "resources": ["https://*"]
    },
    {
      "name": "allow-read-workspace",
      "effect": "allow",
      "principals": ["agent:*"],
      "actions": ["fs.read"],
      "resources": ["/workspace/*"]
    },
    {
      "name": "require-approval-for-sensitive",
      "effect": "allow",
      "principals": ["agent:secure"],
      "actions": ["sensitive.*"],
      "resources": ["*"],
      "required_labels": ["verified", "approved"]
    }
  ]
}
```

### Bundled Templates

The `policies/` directory contains ready-to-use templates:

| Policy | Use Case |
|--------|----------|
| `strict.json` | Production - workspace isolation, safe commands |
| `read-only.json` | Code review - read-only access |
| `strict-web-only.json` | Browser automation - no filesystem |
| `ci-cd.json` | CI/CD pipelines - build/test commands |
| `permissive.json` | Development - minimal restrictions |

---

## API Reference

### Authorization

**POST /v1/authorize**

Check if an action is authorized.

Request:
```json
{
  "principal": "agent:web",
  "action": "browser.click",
  "resource": "https://example.com",
  "labels": {"verified": "true"},
  "intent_hash": "optional-intent-hash"
}
```

Response (allowed):
```json
{
  "allowed": true,
  "reason": "allowed",
  "mandate_id": "m_7f3a2b1c",
  "missing_labels": []
}
```

Response (denied):
```json
{
  "allowed": false,
  "reason": "explicit_deny",
  "missing_labels": []
}
```

Denial reasons:
- `explicit_deny` - Policy explicitly denies the action
- `no_matching_policy` - No rule matches (fail-closed)
- `missing_labels` - Required labels not provided
- `mandate_revoked` - Mandate was revoked
- `mandate_expired` - Mandate TTL exceeded

### Health & Status

**GET /health**

```json
{"status": "ok"}
```

**GET /status**

```json
{
  "version": "0.4.1",
  "mode": "local_only",
  "identity_mode": "local",
  "rule_count": 12,
  "uptime_s": 3600,
  "total_requests": 1500,
  "total_allowed": 1450,
  "total_denied": 50
}
```

**GET /metrics**

Returns Prometheus-format metrics.

### Policy Reload

**POST /policy/reload**

Hot-reload policy rules from file.

```bash
curl -X POST http://127.0.0.1:8787/policy/reload
```

### Identity Management

**POST /identity/task** (local-idp mode)

Issue a task identity token.

```json
{
  "principal_id": "agent:web",
  "task_id": "task-123",
  "ttl_seconds": 300
}
```

**POST /identity/revoke**

Revoke an identity.

**GET /identity/list**

List active identities.

### Delegation

**POST /v1/delegate**

Delegate a mandate to another agent with narrower scope.

```json
{
  "parent_mandate_token": "eyJ...",
  "delegate_to": "agent:sub-agent",
  "action_scope": "browser.click",
  "resource_scope": "https://example.com/*",
  "ttl_seconds": 60
}
```

**POST /revoke/mandate**

Revoke a mandate and all derived mandates.

```json
{
  "mandate_id": "m_7f3a2b1c",
  "reason": "security concern"
}
```

---

## Terminal Dashboard

The sidecar includes an interactive TUI dashboard for real-time monitoring.

### Starting the Dashboard

```bash
./predicate-authorityd --policy-file policy.json dashboard
```

Or set refresh rate:
```bash
export PREDICATE_TUI_REFRESH_MS=50
./predicate-authorityd --policy-file policy.json dashboard
```

### Dashboard Layout

```
┌────────────────────────────────────────────────────────────────────────────┐
│  PREDICATE AUTHORITY v0.4.1    MODE: strict  [LIVE]  UPTIME: 2h 34m  [?]  │
│  Policy: loaded                Rules: 12 active      [Q:quit P:pause]     │
├─────────────────────────────────────────┬──────────────────────────────────┤
│  LIVE AUTHORITY GATE [1/47]             │  METRICS                         │
│                                         │                                  │
│  [ ✓ ALLOW ] agent:web                  │  Total Requests:    1,870        │
│    browser.navigate → github.com        │  ├─ Allowed:        1,847 (98.8%)│
│    m_7f3a2b1c | 0.4ms                   │  └─ Blocked:           23  (1.2%)│
│                                         │                                  │
│  [ ✗ DENY  ] agent:scraper              │  Throughput:        12.3 req/s   │
│    fs.write → ~/.ssh/config             │  Avg Latency:       0.8ms        │
│    EXPLICIT_DENY | 0.2ms                │                                  │
│                                         │  TOKEN CONTEXT SAVED             │
│  [ ✓ ALLOW ] agent:worker               │  Blocked early:     23 actions   │
│    browser.click → button#checkout      │  Est. tokens saved: ~4,200       │
│    m_9c2d4e5f | 0.6ms                   │                                  │
├─────────────────────────────────────────┴──────────────────────────────────┤
│  Generated 47 proofs this session. Run `predicate login` to sync to vault.│
└────────────────────────────────────────────────────────────────────────────┘
```

### Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `Q` / `Esc` | Quit dashboard |
| `j` / `↓` | Scroll down event list |
| `k` / `↑` | Scroll up event list |
| `g` | Jump to newest event |
| `G` | Jump to oldest event |
| `P` | Pause/resume live updates |
| `?` | Toggle help overlay |
| `f` | Cycle filter: ALL → DENY → agent input |
| `/` | Filter by agent ID (type + Enter) |
| `c` | Clear filter (show all) |

### Live Filtering

When an agent is running a heavy web loop, the LIVE AUTHORITY GATE can be spammed with hundreds of `[ ✓ ALLOW ]` events. Use filtering to focus on what matters:

**Filter to DENY only:**
Press `f` once to show only blocked events.

**Filter by agent:**
Press `f` twice (or `/`) to enter agent filter mode. Type an agent ID (e.g., `web`) and press Enter. Events are filtered by partial match on the principal.

**Clear filter:**
Press `c` to return to showing all events.

The current filter is displayed in the header and title:
```
  PREDICATE AUTHORITY v0.4.1    MODE: strict  [LIVE]  FILTER: DENY
```

### Audit Mode

When running with the audit-only policy (or `--audit-mode` flag), the dashboard shows a visual distinction for blocked events:

```bash
# Enable audit mode explicitly
./predicate-authorityd --audit-mode --policy-file policy.json dashboard

# Or use audit-only policy (auto-detected from filename)
./predicate-authorityd --policy-file policies/audit-only.json dashboard
```

In audit mode:
- The header shows `[AUDIT]` instead of `[LIVE]`
- Blocked events display `[ ⚠ WOULD DENY ]` in yellow instead of `[ ✗ DENY ]` in red
- The LIVE AUTHORITY GATE border turns yellow

This makes it visually obvious that the sidecar is logging decisions but not actually blocking the agent.

### Session Summary

When you quit the dashboard, a session summary is printed:

```
────────────────────────────────────────────────────────
  PREDICATE AUTHORITY SESSION SUMMARY
────────────────────────────────────────────────────────
  Duration:         2h 34m 12s
  Total Requests:   1,870
  ├─ Allowed:       1,847 (98.8%)
  └─ Blocked:       23 (1.2%)

  Proofs Generated: 1,870
  Est. Tokens Saved: ~4,140

  To sync proofs to enterprise vault, run:
    $ predicate login

────────────────────────────────────────────────────────
```

---

## Delegation Chains

Delegation allows agents to pass limited permissions to sub-agents.

### How Delegation Works

1. Agent A receives a mandate for `browser.*` on `https://*`
2. Agent A delegates to Agent B with narrower scope: `browser.click` on `https://example.com/*`
3. Agent B can only act within the delegated scope
4. If Agent A's mandate is revoked, Agent B's mandate is automatically revoked (cascade)

### Delegation Request

```bash
curl -X POST http://127.0.0.1:8787/v1/delegate \
  -H "Content-Type: application/json" \
  -d '{
    "parent_mandate_token": "eyJ...",
    "delegate_to": "agent:sub-agent",
    "action_scope": "browser.click",
    "resource_scope": "https://example.com/*",
    "ttl_seconds": 60
  }'
```

Response:
```json
{
  "mandate_id": "m_derived_123",
  "mandate_token": "eyJ...",
  "delegation_depth": 1,
  "expires_at": "2024-..."
}
```

### Scope Narrowing Rules

- Child scope must be a **subset** of parent scope
- `browser.*` can delegate to `browser.click` (narrower)
- `browser.click` cannot delegate to `browser.*` (broader - rejected)
- `https://*` can delegate to `https://example.com/*`

### Depth Limits

Delegation depth is configurable (default: 5 levels). Attempting to exceed the limit returns an error.

### Cascade Revocation

When a mandate is revoked, all derived mandates are automatically revoked:

```
Agent A (root)
  └── Agent B (depth 1)
        └── Agent C (depth 2)
              └── Agent D (depth 3)

Revoke Agent B's mandate → Agent C and D are also revoked
Agent A's mandate remains valid
```

---

## Security Features (Phase 5)

The sidecar includes built-in security hardening features for enterprise deployments.

### SSRF Protection

Server-Side Request Forgery (SSRF) protection blocks requests to internal network resources:

**Protected resources:**
- **Private IPs**: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
- **Link-local**: 169.254.0.0/16
- **Localhost**: 127.0.0.0/8, localhost, ::1
- **Cloud Metadata**: AWS (169.254.169.254), GCP, Azure, Kubernetes
- **Internal DNS**: *.internal, *.local, *.localhost, *.corp, *.lan, *.intranet

SSRF protection is **enabled by default**. Blocked requests return:
```json
{
  "allowed": false,
  "reason": "explicit_deny",
  "violated_rule": "ssrf-protection: SSRF: cloud metadata endpoint blocked (169.254.169.254)"
}
```

To disable (development only, not recommended for production):
```bash
./predicate-authorityd --disable-ssrf-protection --policy-file policy.json run
```

### Policy Signature Verification

Prevent unauthorized policy modifications with Ed25519 cryptographic signatures.

**Signed policy file format:**
```json
{
  "policy": {
    "rules": [...]
  },
  "signature": "<base64-encoded-ed25519-signature>"
}
```

**Enable signature verification:**
```bash
./predicate-authorityd \
  --require-signed-policy \
  --policy-signing-key "a1b2c3d4e5f6..." \
  --policy-file signed-policy.json \
  run
```

The sidecar will:
1. Parse the signed policy JSON
2. Verify the signature against the configured public key
3. Reject policies with invalid or missing signatures

**Key management:**
- Private key: Keep secure on control plane or CI/CD system
- Public key: Distribute to sidecars via `--policy-signing-key` or environment variable

### Loop Guard

Prevents runaway agents from infinitely retrying failed actions.

**Configuration:**
```bash
./predicate-authorityd \
  --loop-guard-threshold 5 \
  --loop-guard-window-s 60 \
  --policy-file policy.json \
  run
```

**Behavior:**
- Tracks failures per (principal, action, resource) tuple
- After threshold consecutive failures within the window, requests are blocked
- Returns `LOOP_GUARD_TRIGGERED` reason
- Automatically resets after cooldown period

### Merkle Hash Chain (Audit Integrity)

The proof ledger uses SHA-256 hash chaining for tamper-evident audit trails.

**Each proof event contains:**
- `event_id`: Unique identifier
- `chain_hash`: SHA-256(previous_hash + event_data)
- `timestamp`: ISO 8601 timestamp

**Verify chain integrity:**
```bash
# Get current chain head (latest hash)
curl -s http://127.0.0.1:8787/ledger/chain-head | jq
# Response: {"chain_hash": "abc123...", "event_count": 47}

# Verify full chain integrity
curl -s http://127.0.0.1:8787/ledger/verify | jq
# Response: {"valid": true, "event_count": 47}
```

### Secret Zeroization

Sensitive key material (signing keys, OIDC secrets) is automatically zeroized from memory when no longer needed using the `zeroize` crate. This protects against memory-dump attacks.

---

## Troubleshooting

### Common Issues

#### "No matching policy" for all requests

**Cause:** No policy file loaded or rules don't match.

**Fix:**
1. Verify policy file exists: `--policy-file policy.json`
2. Check rule patterns match your request
3. Run with `--log-level debug` to see rule evaluation

#### "Connection refused" on port 8787

**Cause:** Sidecar not running or bound to different address.

**Fix:**
1. Check if process is running: `ps aux | grep predicate`
2. Check bound address: default is `127.0.0.1:8787`
3. For external access, use `--host 0.0.0.0`

#### "Invalid token" errors

**Cause:** Token validation failed in IdP mode.

**Fix:**
1. Check token is not expired
2. Verify issuer/audience match configuration
3. Check JWKS endpoint is reachable
4. Run with `--log-level debug` to see validation details

#### Dashboard shows "Waiting for authorization requests..."

**Cause:** No authorization requests have been made yet.

**Fix:** Make a test request:
```bash
curl -X POST http://127.0.0.1:8787/v1/authorize \
  -H "Content-Type: application/json" \
  -d '{"principal":"agent:test","action":"test","resource":"test"}'
```

### Debug Logging

Enable verbose logging to diagnose issues:

```bash
./predicate-authorityd --log-level debug --policy-file policy.json run
```

Or set via environment:
```bash
export PREDICATE_LOG_LEVEL=debug
./predicate-authorityd run
```

### Health Check

Verify the sidecar is running:

```bash
curl http://127.0.0.1:8787/health
# Response: {"status":"ok"}

curl http://127.0.0.1:8787/status
# Response: detailed status with version, mode, stats
```

---

## Related Documentation

- [how-it-works.md](../how-it-works.md) - Architectural overview of IdP + Sidecar + Mandates
- [policies/README.md](../policies/README.md) - Policy template documentation
- [DESIGN.md](../DESIGN.md) - Internal design documentation

---

## Support

- GitHub Issues: https://github.com/PredicateSystems/predicate-authority-sidecar/issues
- Documentation: https://docs.predicatesystems.dev
