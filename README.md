# predicate-authorityd (Rust)

A high-performance Rust implementation of the Predicate Authority sidecar daemon.

## Overview

This sidecar enforces policy rules for agent actions, providing:
- Policy-based authorization decisions
- Audit logging with proof ledger
- Wire-compatible with TypeScript and Python SDKs

## Quick Start

```bash
# Build
cargo build --release

# Run with default settings
./target/release/predicate-authorityd

# Run with custom port and policy file
./target/release/predicate-authorityd --port 8787 --policy-file policy.json
```

## CLI Options

```
Options:
  --host <HOST>                Host to bind to [default: 127.0.0.1]
  --port <PORT>                Port to bind to [default: 8787]
  --mode <MODE>                Operating mode: local_only or cloud_connected [default: local_only]
  --policy-file <POLICY_FILE>  Path to policy JSON file
  --log-level <LOG_LEVEL>      Log level: trace, debug, info, warn, error [default: info]
  -h, --help                   Print help
  -V, --version                Print version
```

Environment variables are also supported (e.g., `PREDICATE_PORT=8787`).

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/v1/authorize` | POST | Core authorization check |
| `/authorize` | POST | Legacy alias |
| `/health` | GET | Health check |
| `/status` | GET | Detailed status with stats |
| `/metrics` | GET | Prometheus-format metrics |
| `/policy/reload` | POST | Hot-reload policy rules |

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
    }
  ]
}
```

## Development

```bash
# Run tests
cargo test

# Run with verbose logging
cargo run -- --log-level debug

# Check formatting
cargo fmt --check

# Run lints
cargo clippy
```

## Architecture

See [DESIGN.md](DESIGN.md) for detailed architecture documentation.

## License

MIT
