# Policy Templates

This directory contains ready-to-use policy templates for `predicate-authorityd`. Copy and customize these for your agent deployment.

## Supported Formats

The sidecar supports both **JSON** and **YAML** policy files. Format is auto-detected by file extension:
- `.json` - JSON format
- `.yaml` or `.yml` - YAML format

## Quick Start

```bash
# Start with the strict policy (recommended for production)
./predicate-authorityd --policy-file policies/strict.json run

# Or use environment variable
export PREDICATE_POLICY_FILE=policies/strict.json
./predicate-authorityd run
```

## Available Templates

| Policy | Use Case | Filesystem | Shell | Network | Browser |
|--------|----------|------------|-------|---------|---------|
| **[strict.json](strict.json)** | Production default | Workspace only | Safe commands | HTTPS only | Full (with labels) |
| **[read-only.json](read-only.json)** | Code review, analysis | READ only | Read-only commands | HTTPS GET only | Read-only |
| **[strict-web-only.json](strict-web-only.json)** | Browser automation | BLOCKED | BLOCKED | HTTPS allowlist | Full (with labels) |
| **[ci-cd.json](ci-cd.json)** | CI/CD pipelines | Workspace R/W | Build commands | BLOCKED | BLOCKED |
| **[data-analysis.json](data-analysis.json)** | Data science | READ data files | Analysis tools | HTTPS GET | BLOCKED |
| **[permissive.json](permissive.json)** | Development | Full access | Full access | Full access | Full access |
| **[audit-only.json](audit-only.json)** | Agent profiling | Logged | Logged | Logged | Logged |
| **[minimal.json](minimal.json)** | Starting point | BLOCKED | BLOCKED | BLOCKED | HTTPS only |
| **[secret-injection.json](secret-injection.json)** | API + CLI with secrets | Safe commands | With injected creds | API auth headers | BLOCKED |

---

## Policy Descriptions

### strict.json - Recommended Default

**Purpose:** Balanced production policy with workspace isolation.

**Allows:**
- Filesystem read everywhere, write only in workspace directories
- Safe shell commands (ls, cat, grep, git, npm, cargo, etc.)
- HTTPS requests to any domain
- Full browser interactions (with verification labels)

**Blocks:**
- Access to sensitive files (`.env`, `.ssh/`, credentials)
- Writes outside workspace directories
- Dangerous shell commands (`rm -rf`, `sudo`, pipe to bash)
- Non-HTTPS protocols

```bash
./predicate-authorityd --policy-file policies/strict.json run
```

### read-only.json

**Purpose:** Allow context gathering without modification capabilities.

**Allows:**
- Filesystem read operations (except credentials)
- Safe shell commands (cat, grep, git status/log/diff)
- HTTPS GET requests
- Browser read operations (screenshot, extract)

**Blocks:**
- ALL filesystem writes/deletes
- Mutating shell commands (rm, mv, git push)
- HTTP mutations (POST, PUT, DELETE)
- Browser form interactions

**Best for:** Code review agents, documentation generators, codebase analysis.

### strict-web-only.json

**Purpose:** Lock down agents to browser-only operations.

**Allows:**
- Browser navigation to allowlisted HTTPS domains
- Browser interactions (click, type, read) with snapshot verification
- Screenshot and DOM extraction

**Blocks:**
- ALL filesystem operations
- ALL shell/system execution
- Non-HTTPS protocols
- Sensitive form field interactions (password, credit card)

**Best for:** Web scraping bots, form-filling agents, UI testing automation.

### ci-cd.json

**Purpose:** Secure policy for CI/CD pipeline agents.

**Allows:**
- Workspace read/write operations
- Build commands (npm, cargo, go, make, etc.)
- Test commands (jest, pytest, cargo test)
- Git operations

**Blocks:**
- Network access (prevents data exfiltration)
- Sensitive file access
- System modification commands

**Best for:** Automated code review, test runners, build agents.

### data-analysis.json

**Purpose:** Read-only access for data analysis workflows.

**Allows:**
- Reading data files (CSV, JSON, Parquet, SQL, etc.)
- Python/Jupyter analysis tools
- Database query tools (sqlite3, psql, mysql)
- HTTPS GET requests for data fetching

**Blocks:**
- ALL filesystem writes
- HTTP mutations
- Package installation

**Best for:** Data science agents, report generators, analytics tools.

### permissive.json

**Purpose:** Minimal restrictions for trusted development environments.

**Allows:**
- Full filesystem access (except critical credentials)
- Full shell access (except catastrophic commands)
- Full HTTP and browser access

**Blocks:**
- Only catastrophic commands (rm -rf /, fork bombs)
- Only critical credential files (.ssh/id_*, /etc/shadow)

**Best for:** Trusted development environments, internal tools.

### audit-only.json

**Purpose:** Profile agent behavior before writing restrictive policies.

**Allows:**
- ALL actions (requires `audit_enabled` label to confirm logging is active)

**Blocks:**
- Only catastrophic commands (rm -rf /, fork bombs)

**Best for:** Initial agent onboarding, understanding action patterns.

> **WARNING:** Audit-only provides NO security protection. Use only in development or with fully trusted agents.

### minimal.json

**Purpose:** Minimal starting point - browser HTTPS only.

**Allows:**
- Browser actions on HTTPS URLs only

**Blocks:**
- Everything else

**Best for:** Starting point for building custom policies.

### secret-injection.json

**Purpose:** Demonstrate policy-driven secret injection for API calls and CLI commands.

**Features:**
- Auto-inject auth headers for GitHub, OpenAI, Anthropic APIs
- Auto-inject AWS/kubectl/database credentials for CLI commands
- Secrets stay on the sidecar, agent never sees them

**Example rules:**
```json
{
  "name": "github-api-with-auth",
  "effect": "allow",
  "principals": ["agent:*"],
  "actions": ["http.fetch"],
  "resources": ["https://api.github.com/*"],
  "inject_headers": {
    "Authorization": "Bearer ${GITHUB_TOKEN}"
  }
}
```

**Best for:** Demonstrating zero-trust secret handling where agents cannot access raw credentials.

---

## Policy Schema

Each policy file contains a `rules` array. Rules are evaluated in order.

```json
{
  "rules": [
    {
      "name": "rule-identifier",
      "effect": "allow",
      "principals": ["agent:*"],
      "actions": ["fs.read", "browser.*"],
      "resources": ["https://example.com*", "/home/*/projects/*"],
      "required_labels": ["mfa_verified"]
    }
  ]
}
```

### Fields

| Field | Required | Type | Description |
|-------|----------|------|-------------|
| `name` | Yes | string | Unique identifier for logging |
| `effect` | Yes | `"allow"` or `"deny"` | Action when rule matches |
| `principals` | Yes | string[] | WHO can perform the action |
| `actions` | Yes | string[] | WHAT actions are covered |
| `resources` | Yes | string[] | ON WHAT resources |
| `required_labels` | No | string[] | Verification labels required (default: `[]`) |
| `max_delegation_depth` | No | number | Max delegation chain depth |
| `inject_headers` | No | object | Headers to inject for `http.fetch` actions |
| `inject_env` | No | object | Environment variables to inject for `cli.exec` actions |

### Secret Injection

Policy rules can specify headers or environment variables to inject when actions are executed through `/v1/execute`. Values support environment variable substitution:

| Syntax | Description |
|--------|-------------|
| `${VAR_NAME}` | Substitute with environment variable value |
| `${VAR_NAME:-default}` | Use default if variable not set |

**Example: Inject auth header for API calls**

```json
{
  "name": "api-with-auth",
  "effect": "allow",
  "principals": ["agent:*"],
  "actions": ["http.fetch"],
  "resources": ["https://api.example.com/*"],
  "inject_headers": {
    "Authorization": "Bearer ${API_TOKEN}",
    "X-Api-Key": "${API_KEY}"
  }
}
```

**Example: Inject credentials for CLI**

```json
{
  "name": "aws-cli",
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
```

See the [sidecar user manual](../docs/sidecar-user-manual.md#secret-injection) for more details.

### Evaluation Order

1. **DENY rules checked first** - Any matching DENY immediately blocks
2. **ALLOW rules checked** - Must match AND have all required_labels
3. **Default DENY** - If no rules match, action is blocked (fail-closed)

### Pattern Matching

Patterns use glob-style matching:

| Pattern | Matches |
|---------|---------|
| `*` | Anything |
| `agent:*` | Any agent identity |
| `fs.*` | fs.read, fs.write, fs.delete, etc. |
| `https://*` | Any HTTPS URL |
| `/home/*/projects/**` | Any file under any user's projects dir |

#### Glob `**` Directory Matching Footgun

**Common mistake:** Using `**` to match a directory itself.

```json
{
  "resources": ["model-eval/**"]   // WRONG: matches files INSIDE model-eval, not the directory
}
```

The pattern `model-eval/**` matches `model-eval/file.txt` and `model-eval/sub/file.txt`, but it does **NOT** match the directory `model-eval` itself.

**To match both the directory and its contents:**

```json
{
  "resources": ["model-eval", "model-eval/**"]   // CORRECT: matches directory AND contents
}
```

Or use multiple patterns:
- `model-eval` - matches the directory itself
- `model-eval/*` - matches direct children
- `model-eval/**` - matches all descendants recursively

### SSRF Whitelist (Policy-Driven)

You can include an optional `ssrf_whitelist` field in your policy file to allow specific local endpoints to bypass SSRF protection. This is useful for local LLMs (Ollama), databases, or other services running on private IPs.

```json
{
  "ssrf_whitelist": ["172.30.192.1:11434", "127.0.0.1:9200"],
  "rules": [...]
}
```

**Key points:**
- Whitelist uses exact `host:port` matching for security
- If CLI `--ssrf-allow` is also provided, entries are merged
- Defaults to empty (full SSRF enforcement) if omitted

**YAML example:**
```yaml
ssrf_whitelist:
  - "172.30.192.1:11434"  # Local Ollama on WSL2
  - "127.0.0.1:9200"      # Local Elasticsearch

rules:
  - name: allow-llm-calls
    effect: allow
    # ...
```

---

## Creating Custom Policies

1. **Start with audit-only** to understand your agent's behavior:
   ```bash
   ./predicate-authorityd --policy-file policies/audit-only.json run
   # Run your agent workflows, review logs
   ```

2. **Copy the closest template**:
   ```bash
   cp policies/strict.json policies/my-agent.json
   ```

3. **Customize rules** based on observed behavior

4. **Test before deploying**:
   ```bash
   ./predicate-authorityd --policy-file policies/my-agent.json --log-level debug run
   ```

## Hot Reload

Policies can be reloaded without restart:

```bash
curl -X POST http://127.0.0.1:8787/policy/reload \
  -H "Content-Type: application/json" \
  -d @policies/strict.json
```
