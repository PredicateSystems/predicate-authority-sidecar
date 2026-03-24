# predicate-authorityd

**Zero-Trust Authorization for AI Agents. Sub-millisecond latency. No LLM required.**

---

## Two Primitives: Identity vs Mandate

| Primitive | What it proves | Lifetime | Analogy |
|-----------|---------------|----------|---------|
| **Identity** | Who the agent is | Session-scoped (minutes–hours) | Passport |
| **Mandate** | What this exact action may do, under whose authority | Action-scoped (seconds–minutes) | Work visa |

An IdP token (Okta, Entra) proves identity. A mandate proves per-action authorization.

---

## The Problem: Authorization ≠ Intent

When you connect an AI agent to an Identity Provider, it receives an access token—a **passport** that proves identity and carries static scopes like `database:write`.

But IdP scopes are coarse-grained. If a prompt injection tricks your agent into calling `drop_database` instead of `update_record`, your API executes the attack because the agent's token legitimately holds the `database:write` scope.

**The IdP authorized the agent, not the action.**

## The Solution: Per-Action Mandates

Predicate Authority adds a **deterministic policy layer** between your agent and your tools. Every action is evaluated in <1ms against explicit ALLOW/DENY rules before execution. Approved actions receive a short-lived **mandate**—a cryptographic proof of authorization for that specific (action, resource, principal) tuple.

```
┌─────────────┐     ┌─────────────────────┐     ┌─────────────┐
│  AI Agent   │────▶│ predicate-authorityd│────▶│  Your Tools │
│             │     │      (Sidecar)      │     │             │
│  "Click X"  │     │  ALLOW/DENY in <1ms │     │  Execute    │
└─────────────┘     └─────────────────────┘     └─────────────┘
```

- **Fail-closed**: No matching rule = DENY
- **Deterministic**: No LLM, no probabilistic reasoning
- **Fast**: p99 < 1ms authorization latency
- **Auditable**: Cryptographic proof ledger for every decision

The sidecar runs as a separate process, not as a framework hook. Framework integrations can disappear when orchestration changes; execution boundaries should survive runtime changes.

---

<details>
<summary><h2>Terminal Dashboard</h2></summary>

Watch authorization decisions in real-time with the built-in TUI:

![TUI Dashboard](docs/assets/tui.gif)

```bash
./predicate-authorityd --policy-file policy.json dashboard
```

**Keyboard:** `j/k` scroll, `f` filter, `c` clear, `P` pause, `?` help, `Q` quit | **Audit mode:** `--audit-mode` shows `[ ⚠ WOULD DENY ]` in yellow instead of blocking.

</details>

<details>
<summary><h2>Web UI</h2></summary>

Browser-based monitoring dashboard with real-time authorization event streaming:

![Web UI Screenshot](docs/images/web-ui.png)

```bash
./predicate-authorityd --policy-file policy.json --web-ui run
```

On startup, a secure URL is printed to the terminal:

```
  Web UI enabled: http://127.0.0.1:8787/ui/?token=a1b2c3d4e5f6...
```

**Features:**
- **Split-pane layout:** Policy viewer on the left, live event feed on the right
- **Real-time streaming:** Events appear instantly via Server-Sent Events (SSE)
- **Color-coded results:** Green for ALLOW, red for DENY
- **Event filtering:** Filter by principal, action, or result type
- **Statistics:** Total allowed/denied counts and average latency
- **Copy URL button:** Share the dashboard URL (includes auth token)
- **Connection status:** Visual indicator when SSE connection is active

**Security:**
- Token-based authentication (32-character random token)
- Token stored in `sessionStorage` (cleared on tab close)
- URL cleaned after token extraction (no token in history)

The `--web-ui` flag works with both `run` and `dashboard` commands. When used with `dashboard`, both the TUI and Web UI run simultaneously.

</details>

---

## Quick Start

**30 seconds to your first authorization decision.**

```bash
# 1. Download (or cargo build --release)
curl -LO https://github.com/PredicateSystems/predicate-authority-sidecar/releases/latest/download/predicate-authorityd-darwin-arm64.tar.gz
tar -xzf predicate-authorityd-*.tar.gz && chmod +x predicate-authorityd

# 2. Create a policy
cat > policy.json << 'EOF'
{
  "rules": [
    {"name": "allow-browser-https", "effect": "allow", "principals": ["agent:*"], "actions": ["browser.*"], "resources": ["https://*"]},
    {"name": "deny-admin", "effect": "deny", "principals": ["agent:*"], "actions": ["admin.*"], "resources": ["*"]}
  ]
}
EOF

# 3. Start the sidecar
./predicate-authorityd --policy-file policy.json run
```

**Test it:**

```bash
# ALLOWED - browser action on HTTPS
curl -X POST http://127.0.0.1:8787/v1/authorize \
  -H "Content-Type: application/json" \
  -d '{"principal":"agent:web","action":"browser.click","resource":"https://example.com"}'
# {"allowed":true,"reason":"allowed"}

# DENIED - admin action blocked
curl -X POST http://127.0.0.1:8787/v1/authorize \
  -H "Content-Type: application/json" \
  -d '{"principal":"agent:web","action":"admin.delete","resource":"/users/123"}'
# {"allowed":false,"reason":"explicit_deny"}
```

<details>
<summary><h3>Multi-Scope Authorization</h3></summary>

Request authorization for multiple action/resource pairs in a single call. This is useful for orchestrators that need broad permissions across different domains (e.g., browser access AND filesystem access):

```bash
# Multi-scope authorization request
curl -X POST http://127.0.0.1:8787/v1/authorize \
  -H "Content-Type: application/json" \
  -d '{
    "principal": "agent:orchestrator",
    "scopes": [
      {"action": "browser.*", "resource": "https://www.amazon.com/*"},
      {"action": "fs.*", "resource": "**/workspace/data/**"}
    ],
    "intent_hash": "orchestrate:ecommerce:run-123"
  }'
# Response includes scopes_authorized showing which scopes matched and their rules:
# {
#   "allowed": true,
#   "mandate_token": "m_abc123...",
#   "scopes_authorized": [
#     {"action": "browser.*", "resource": "https://www.amazon.com/*", "matched_rule": "allow-browser-https"},
#     {"action": "fs.*", "resource": "**/workspace/data/**", "matched_rule": "allow-workspace-fs"}
#   ]
# }
```

**When to use multi-scope:**
- Orchestrators delegating to multiple sub-agents with different capabilities
- Workflows requiring cross-domain permissions (browser + filesystem + HTTP)
- Reducing round-trips when multiple scopes are known upfront

**Backward compatibility:** Single action/resource requests continue to work as before.

</details>

## Demos

*See the sidecar in action—securing AI agents across popular frameworks.*

### 1. Secure Your OpenClaw Agents
* [Zero-Trust File Processor Agent Demo](https://github.com/PredicateSystems/predicate-claw/tree/main/examples/file-processor-demo)
* [SecureClaw Integration Demo](https://github.com/PredicateSystems/predicate-claw/tree/main/examples/integration-demo)
* [Amazon Kiro Reenactment Demo](https://github.com/PredicateSystems/predicate-claw/tree/main/examples/kiro-reenactment-demo)
* [Zero-Trust AI Agent Demo](https://github.com/PredicateSystems/predicate-claw/tree/main/examples/real-openclaw-demo)

### 2. CrewAI Multi-Agents
* [Zero-Trust Multi-Agent E-commerce Price Monitoring](https://github.com/PredicateSystems/predicate-secure-crewai-demo)

### 3. LangChain / LangGraph
* [Poisoned Escalation Demo with Multiple Agents](https://github.com/PredicateSystems/langgraph-poisoned-escalation-demo)

### 4. Temporal.io
* [Protect your temporal.io agents with zero-trust runtime authorization.](https://github.com/PredicateSystems/temporal-predicate-py)

**[More Demos...](https://predicatesystems.ai/demos)**

---

## Why This Exists

| Traditional Auth | Predicate Authority |
|-----------------|---------------------|
| "Agent can access database" | "Agent can `SELECT` from `orders` table" |
| Scope granted at login | Permission evaluated per-action |
| Trust the agent | Trust the policy |
| Prompt injection = game over | Prompt injection = blocked |

**Every rogue `fs.write ~/.ssh/config` gets intercepted. Every unauthorized API call gets logged. Every action has a cryptographic proof.**

---

## Documentation

- **[User Manual](docs/sidecar-user-manual.md)** - Complete guide to installation, configuration, and operation
- **[How It Works](how-it-works.md)** - Architecture of IdP + Sidecar + Mandates
- **[Policy Templates](policies/README.md)** - Ready-to-use policy files

---

## Security

For production enterprise deployments, Predicate supports Ed25519 cryptographic policy signing via the Control Plane to prevent local file tampering. [Read the Enterprise Hardening Guide here](https://www.predicatesystems.ai/docs/authority/sidecar/policy-signing).

---

## Installation

### Download Binary

| Platform | Binary |
|----------|--------|
| macOS ARM64 | `predicate-authorityd-darwin-arm64.tar.gz` |
| macOS x64 | `predicate-authorityd-darwin-x64.tar.gz` |
| Linux x64 | `predicate-authorityd-linux-x64.tar.gz` |
| Linux x64 (musl) | `predicate-authorityd-linux-x64-musl.tar.gz` |
| Windows x64 | `predicate-authorityd-windows-x64.zip` |

```bash
tar -xzf predicate-authorityd-*.tar.gz
chmod +x predicate-authorityd
./predicate-authorityd version
```

### Build from Source

```bash
cargo build --release
./target/release/predicate-authorityd version
```

### Desktop companion

Optional launcher and policy UI (egui):

```bash
cargo build -p predicate-authority-desktop --release
./target/release/predicate-authority-desktop
```

See [`predicate-authority-desktop/README.md`](predicate-authority-desktop/README.md).

### Install via pip (Python SDK)

```bash
pip install "predicate-authority[sidecar]"
predicate-download-sidecar
```

---

## Commands

| Command | Description |
|---------|-------------|
| `run` | Start the authorization daemon |
| `dashboard` | Start with interactive TUI |
| `init-config` | Generate example TOML config |
| `check-config` | Validate configuration |
| `version` | Show version info |

---

## Policy Rules

Policies are JSON or YAML files with ALLOW/DENY rules:

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
      "name": "deny-filesystem-writes",
      "effect": "deny",
      "principals": ["agent:*"],
      "actions": ["fs.write", "fs.delete"],
      "resources": ["*"]
    }
  ]
}
```

**Evaluation order:**
1. DENY rules checked first (any match = blocked)
2. ALLOW rules checked (must match + have required_labels)
3. Default DENY (fail-closed)

**Bundled templates:** `strict.json`, `read-only.json`, `ci-cd.json`, `permissive.json`, `secret-injection.json`

---

## Identity Providers

Integrate with your existing IdP for token validation:

| Mode | Use Case |
|------|----------|
| `local` | Development, no token required |
| `local-idp` | Self-issued tokens, CI/CD, air-gapped |
| `okta` | Enterprise Okta with JWKS |
| `entra` | Microsoft Entra ID (Azure AD) |
| `oidc` | Generic OIDC provider |

```bash
# Okta example
./predicate-authorityd \
  --identity-mode okta \
  --okta-issuer "https://your-org.okta.com/oauth2/default" \
  --okta-client-id "your-client-id" \
  --okta-audience "api://predicate-authority" \
  --policy-file policy.json \
  run
```

---

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/v1/authorize` | POST | Core authorization check (single or multi-scope) |
| `/v1/delegate` | POST | Delegate mandate to sub-agent |
| `/v1/execute` | POST | Execute operation via sidecar (zero-trust mode) |
| `/health` | GET | Health check |
| `/status` | GET | Stats and status |
| `/metrics` | GET | Prometheus metrics |
| `/policy/reload` | POST | Hot-reload policy |

### Delegation Semantics

**Strict subset rule:** A child mandate's (action, resource) must be equal to or narrower than the parent's. `browser.*` can delegate to `browser.click`; `browser.click` cannot delegate to `browser.*`.

**Multi-scope parents:** When a parent mandate has multiple scopes, child delegations are validated using **OR semantics**—the child's scope must be a subset of at least one parent scope:

```
┌─────────────────────────────────────────────────────────────────┐
│  Root Mandate (Orchestrator)                                    │
│  scopes:                                                        │
│    - action: browser.* | resource: https://www.amazon.com/*     │
│    - action: fs.*      | resource: **/workspace/data/**         │
└─────────────────────────────┬───────────────────────────────────┘
                              │
            ┌─────────────────┴─────────────────┐
            ▼                                   ▼
┌───────────────────────┐           ┌───────────────────────┐
│  Scraper Delegation   │           │  Analyst Delegation   │
│  action: browser.*    │           │  action: fs.read      │
│  resource: https://   │           │  resource: **/work    │
│    www.amazon.com/*   │           │    space/data/**      │
│                       │           │                       │
│  ✓ Subset of scope 1  │           │  ✓ Subset of scope 2  │
└───────────────────────┘           └───────────────────────┘
```

### Cascade Revocation

When a mandate is revoked, **all derived child mandates are immediately invalidated**:

```
A (root)
└── B (depth 1)
    └── C (depth 2)
        └── D (depth 3)

Revoke B → C and D die instantly. A survives.
```

Child authority does not survive parent revocation. To restore access, the child must obtain a fresh mandate from an active parent—there is no automatic re-minting.

**Delegation request:**

```bash
# Delegate from multi-scope parent to narrower child scope
curl -X POST http://127.0.0.1:8787/v1/delegate \
  -H "Content-Type: application/json" \
  -d '{
    "parent_mandate_token": "m_orchestrator_abc123...",
    "principal": "agent:scraper",
    "action": "browser.navigate",
    "resource": "https://www.amazon.com/dp/*",
    "intent_hash": "scrape:product-page"
  }'
# Child scope (browser.navigate on amazon.com/dp/*) is validated against
# parent's scopes using OR semantics - matches parent scope 1
```

---

## Execution Proxying (Zero-Trust Mode)

The `/v1/execute` endpoint enables **zero-trust execution** where the sidecar executes operations on behalf of agents. This prevents "confused deputy" attacks where an agent requests authorization for one resource but accesses another.

```
Traditional (Cooperative):           Zero-Trust (Execution Proxy):
┌─────────┐  authorize  ┌─────────┐  ┌─────────┐  execute   ┌─────────┐
│  Agent  │────────────▶│ Sidecar │  │  Agent  │───────────▶│ Sidecar │
│         │◀────────────│         │  │         │◀───────────│         │
│         │   ALLOWED   │         │  │         │  result    │ (reads  │
│         │             │         │  │         │            │  file)  │
│  reads  │             │         │  └─────────┘            └─────────┘
│  file   │             │         │
│  (could │             │         │  Agent never touches the resource
│  cheat) │             │         │  directly - sidecar is the executor
└─────────┘             └─────────┘
```

**Example: File Read via Execute Proxy**

```bash
# 1. First authorize and get a mandate
curl -X POST http://127.0.0.1:8787/v1/authorize \
  -H "Content-Type: application/json" \
  -d '{"principal":"agent:web","action":"fs.read","resource":"/src/index.ts"}'
# Returns: {"allowed":true,"reason":"allowed","mandate_id":"m_abc123"}

# 2. Execute through the sidecar (agent never reads file directly)
curl -X POST http://127.0.0.1:8787/v1/execute \
  -H "Content-Type: application/json" \
  -d '{
    "mandate_id": "m_abc123",
    "action": "fs.read",
    "resource": "/src/index.ts"
  }'
# Returns: {"success":true,"result":{"type":"file_read","content":"...","size":1234,"content_hash":"sha256:..."}}
```

**Supported Actions:**

| Action | Payload | Result |
|--------|---------|--------|
| `fs.read` | None | `FileRead { content, size, content_hash }` |
| `fs.write` | `{ type: "file_write", content, create?, append? }` | `FileWrite { bytes_written, content_hash }` |
| `fs.list` | None | `FileList { entries: [{ name, type, size, modified? }], total_entries }` |
| `fs.delete` | `{ type: "file_delete", recursive? }` | `FileDelete { paths_removed }` |
| `cli.exec` | `{ type: "cli_exec", command, args?, cwd?, timeout_ms? }` | `CliExec { exit_code, stdout, stderr, duration_ms }` |
| `http.fetch` | `{ type: "http_fetch", method, headers?, body? }` | `HttpFetch { status_code, headers, body, body_hash }` |
| `env.read` | `{ type: "env_read", keys: ["VAR_NAME"] }` | `EnvRead { values: { "VAR_NAME": "..." } }` |

**Security Guarantees:**

- Mandate must exist and not be expired
- Requested action must match mandate's action
- Requested resource must match mandate's resource scope
- All executions logged to proof ledger with evidence hashes
- `fs.delete` with `recursive: true` requires explicit policy allowlist
- `env.read` only returns values for explicitly authorized keys in the policy

---

## Secret Injection

Policy rules can inject secrets at execution time. Agents never see raw credentials—the sidecar substitutes environment variables when executing actions.

```
┌─────────┐     authorize     ┌──────────────┐     execute      ┌─────────┐
│  Agent  │ ─────────────────▶│   Sidecar    │ ────────────────▶│ Backend │
│         │  (no secrets)     │ inject: $KEY │  (with secrets)  │   API   │
└─────────┘                   └──────────────┘                  └─────────┘
```

**Policy with header injection:**

```json
{
  "rules": [
    {
      "name": "github-api-with-auth",
      "effect": "allow",
      "principals": ["agent:*"],
      "actions": ["http.fetch"],
      "resources": ["https://api.github.com/*"],
      "inject_headers": {
        "Authorization": "Bearer ${GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3+json"
      }
    }
  ]
}
```

**Policy with CLI environment injection:**

```json
{
  "rules": [
    {
      "name": "aws-cli-with-credentials",
      "effect": "allow",
      "principals": ["agent:ops"],
      "actions": ["cli.exec"],
      "resources": ["aws", "aws *"],
      "inject_env": {
        "AWS_ACCESS_KEY_ID": "${AWS_ACCESS_KEY_ID}",
        "AWS_SECRET_ACCESS_KEY": "${AWS_SECRET_ACCESS_KEY}",
        "AWS_DEFAULT_REGION": "${AWS_REGION:-us-east-1}"
      }
    }
  ]
}
```

**Syntax:**
- `${VAR_NAME}` — Substitute from environment (required)
- `${VAR_NAME:-default}` — Use default if not set

**Usage:**

```bash
# Set secrets as environment variables
export GITHUB_TOKEN="ghp_xxxxxxxxxxxx"
export AWS_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE"
export AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# Start sidecar - secrets stay here
./predicate-authorityd --policy-file policy.json run
```

**Security benefits:**
- Agents never see or handle raw secrets
- Policy controls which secrets are injected where
- Even compromised agents cannot exfiltrate credentials
- Works with existing agents without code changes

See [policies/secret-injection.json](policies/secret-injection.json) for a complete example.

---

## Roadmap: Planned Actions

The following actions are planned to support autonomous agent workflows:

### Filesystem Operations

| Action | Priority | Payload | Result | Rationale |
|--------|----------|---------|--------|-----------|
| `fs.stat` | Medium | `{ path }` | `FsStat { size, modified, permissions, is_dir }` | Check file existence/metadata without reading content |
| `fs.copy` | Medium | `{ source, destination, overwrite? }` | `FsCopy { bytes_copied }` | File duplication with policy enforcement |
| `fs.move` | Medium | `{ source, destination, overwrite? }` | `FsMove { success }` | Atomic rename/move operations |

### Environment & Secrets

| Action | Priority | Payload | Result | Rationale |
|--------|----------|---------|--------|-----------|
| `env.list` | Low | `{ pattern? }` | `EnvList { keys: ["VAR1", "VAR2"] }` | List available env vars (names only, not values) |

### Process Management

| Action | Priority | Payload | Result | Rationale |
|--------|----------|---------|--------|-----------|
| `process.list` | Low | `{ filter? }` | `ProcessList { processes: [{ pid, name, cpu, memory }] }` | Visibility into running processes |
| `process.kill` | Low | `{ pid, signal? }` | `ProcessKill { success }` | Governed process termination |

### Network Operations

| Action | Priority | Payload | Result | Rationale |
|--------|----------|---------|--------|-----------|
| `net.dns` | Low | `{ hostname }` | `NetDns { addresses: ["1.2.3.4"] }` | DNS resolution for network diagnostics |
| `net.ping` | Low | `{ host, count? }` | `NetPing { reachable, latency_ms }` | Network connectivity checks |

**Note:** All planned actions will follow the same mandate validation flow as existing actions

---

## Performance

| Metric | Target | Actual |
|--------|--------|--------|
| Authorization latency | < 1ms p99 | 0.2-0.8ms |
| Delegation issuance | < 10ms p99 | ~5ms |
| Revocation check | < 1μs | O(1) HashSet |
| Memory footprint | < 50MB | ~15MB idle |

---

## Configuration

Configuration via CLI args, environment variables, or TOML file:

```toml
[server]
host = "127.0.0.1"
port = 8787
mode = "local_only"

[policy]
file = "policy.json"
hot_reload = true

[logging]
level = "info"
format = "compact"
```

See [User Manual](docs/sidecar-user-manual.md) for full configuration reference.

---

## CLI Reference

**Important:** CLI arguments go **before** the subcommand.

```bash
# Correct
./predicate-authorityd --port 9000 --policy-file policy.json run

# Wrong
./predicate-authorityd run --port 9000
```

<details>
<summary>Full CLI options</summary>

```
GLOBAL OPTIONS:
  -c, --config <FILE>           TOML config file [env: PREDICATE_CONFIG]
      --host <HOST>             Bind host [default: 127.0.0.1]
      --port <PORT>             Bind port [default: 8787]
      --mode <MODE>             local_only or cloud_connected
      --policy-file <PATH>      Policy file (JSON/YAML)
      --log-level <LEVEL>       trace/debug/info/warn/error

IDENTITY OPTIONS:
      --identity-mode <MODE>    local/local-idp/oidc/entra/okta
      --idp-token-ttl-s <SECS>  Token TTL [default: 300]
      --mandate-ttl-s <SECS>    Mandate TTL [default: 300]

OKTA OPTIONS:
      --okta-issuer <URL>       Okta issuer URL
      --okta-client-id <ID>     Client ID
      --okta-audience <AUD>     Expected audience
      --okta-required-scopes    Required scopes (comma-separated)

CONTROL PLANE OPTIONS:
      --control-plane-url <URL> Control plane URL
      --tenant-id <ID>          Tenant ID
      --project-id <ID>         Project ID
      --predicate-api-key <KEY> API key
      --sync-enabled            Enable sync
```

</details>

---

## Development

```bash
cargo test                    # Run tests
cargo test --test integration_test  # Integration tests
cargo bench                   # Run benchmarks
cargo clippy                  # Lints
```

---

## License

MIT

---

**Built for engineers who don't trust their agents.**
