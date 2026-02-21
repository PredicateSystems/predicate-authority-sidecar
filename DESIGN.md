# Rust Sidecar for Predicate Authority - Design Document

## Executive Summary

**Feasibility: HIGH** - A Rust-based sidecar is technically feasible and provides significant benefits. The current Python implementation is well-architected with clean boundaries, making it portable. The TypeScript SDK already communicates via HTTP/JSON, so it works immediately with a Rust sidecar.

**Status**: Phase 5 Complete (Production Ready) - All phases implemented

---

## Current Architecture Analysis

### Python Sidecar (`predicate-authorityd`)

| Component | Lines | Complexity | Rust Equivalent |
|-----------|-------|------------|-----------------|
| `daemon.py` | ~1,400 | High | `axum` + `tokio` |
| `local_identity.py` | ~513 | Medium | `serde_json` + file I/O |
| `control_plane.py` | ~350 | High | `reqwest` async client |
| `bridge.py` | ~600 | High | `jsonwebtoken` + JWKS |
| `mandate.py` | ~250 | High | `ring` or `ed25519-dalek` |
| `policy.py` | ~135 | Low | `glob` crate |
| `sidecar.py` | ~283 | Medium | Orchestration struct |
| `guard.py` | ~82 | Low | Simple wrapper |
| `proof.py` | ~96 | Low | In-memory vec |
| `revocation.py` | ~150 | Medium | `HashSet` + persistence |
| **Total** | ~3,850 | | **~4,000-5,000 Rust** |

### HTTP API Surface (13 endpoints)

**All endpoints implemented:**
- `POST /v1/authorize` - Core authorization ✅ (with token validation)
- `GET /health`, `/status`, `/metrics` - Operations ✅
- `POST /policy/reload` - Hot-reload ✅
- `POST /revoke/{principal,intent,mandate}` - Revocation ✅
- `POST /identity/task`, `/identity/revoke` - Local identity ✅
- `GET /identity/list` - Identity listing ✅
- `POST /ledger/flush-ack`, `/ledger/flush-now`, `/ledger/requeue` - Queue ops ✅
- `GET /ledger/flush-queue`, `/ledger/dead-letter` - Queue inspection ✅

### Wire Protocol (Frozen Contract)

The sidecar contract is already language-agnostic JSON:

```json
// Request
{"principal": "agent:web", "action": "browser.click", "resource": "https://...", "intent_hash": "..."}

// Response
{"allowed": true, "reason": "allowed", "mandate_id": "m_abc123", "violated_rule": null, "missing_labels": []}
```

**No changes needed to TypeScript SDK** - it uses native `fetch()` and works immediately.

---

## Benefits of Rust Sidecar

### 1. Single Binary Distribution
- **Current**: TypeScript users must `pip install predicate-authority` then run Python daemon
- **Rust**: Download single ~5MB binary, run immediately
- No Python runtime dependency for TypeScript/Node.js users

### 2. Performance
- ~10-100x faster startup (no interpreter)
- Lower memory footprint (~20MB vs ~80MB)
- True parallelism without GIL
- Predictable latency (no GC pauses)

### 3. Cross-Platform Binaries
- Compile for: `x86_64-linux`, `aarch64-linux`, `x86_64-darwin`, `aarch64-darwin`, `x86_64-windows`
- GitHub Actions matrix build
- No platform-specific Python issues

### 4. Operational Benefits
- Static binary = simpler container images
- No virtualenv management
- Better signal handling (graceful shutdown)
- Native systemd integration

---

## Implementation Plan

### Phase 1: Core Authorization ✅ COMPLETE

**Goal**: Minimal sidecar that can authorize requests

1. ✅ Project setup with `cargo new predicate-authorityd`
2. ✅ Data models with `serde` (mirror `predicate_contracts`)
3. ✅ Policy engine with pattern matching
4. ✅ HTTP server with `/v1/authorize` endpoint
5. ✅ In-memory proof ledger

**Deliverable**: TypeScript SDK can authorize against Rust sidecar

### Phase 2: Mandate Signing ✅ COMPLETE

1. ✅ JWT signing with ES256/HS256
2. ✅ Delegation chain validation
3. ✅ Key management (stage/activate/retire)
4. ✅ Mandate TTL enforcement

**Deliverable**: Full mandate issuance parity

### Phase 3: Operations & Persistence ✅ COMPLETE

1. ✅ Local identity registry (JSON file)
2. ✅ Queue management (flush, dead-letter, requeue)
3. ✅ TTL-based expiration
4. ✅ Payload redaction
5. ✅ Health/status/metrics endpoints

**Deliverable**: Operational parity with Python sidecar

### Phase 4: Control Plane & IdP ✅ COMPLETE

1. ✅ Control plane HTTP client
2. ✅ Long-poll sync
3. ✅ Revocation cache
4. ✅ Okta/OIDC/Entra bridges with HTTP handler integration
5. ✅ JWKS caching and validation
6. ✅ Authorization header extraction and token validation

**Deliverable**: Enterprise feature parity

### Phase 5: Polish & Release ✅ COMPLETE

1. ✅ CLI argument parsing (`clap`) with IdP options
2. ✅ Configuration file support (TOML with IdP sections)
3. ✅ Cross-platform builds (GitHub Actions)
4. ✅ Integration tests (54 tests including token validation)
5. ✅ Documentation and migration guide

**Deliverable**: Production-ready release

---

## Rust Crate Dependencies

```toml
[dependencies]
# HTTP server
axum = "0.7"
tokio = { version = "1", features = ["full"] }
tower = { version = "0.4", features = ["util"] }
tower-http = { version = "0.5", features = ["cors", "trace"] }

# HTTP client (for control-plane)
reqwest = { version = "0.12", features = ["json", "rustls-tls"] }

# Serialization
serde = { version = "1", features = ["derive"] }
serde_json = "1"

# Cryptography
jsonwebtoken = "9"
sha2 = "0.10"
hmac = "0.12"
base64 = "0.22"

# Pattern matching
glob = "0.3"

# CLI
clap = { version = "4", features = ["derive", "env"] }

# Utilities
chrono = { version = "0.4", features = ["serde"] }
uuid = { version = "1", features = ["v4"] }
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter", "json"] }
tempfile = "3"
thiserror = "1"
anyhow = "1"
parking_lot = "0.12"
```

---

## Distribution Strategy

### npm Package (for TypeScript users)

```json
{
  "name": "@predicatesystems/authorityd",
  "bin": {
    "predicate-authorityd": "./bin/predicate-authorityd"
  },
  "optionalDependencies": {
    "@predicatesystems/authorityd-darwin-arm64": "1.0.0",
    "@predicatesystems/authorityd-darwin-x64": "1.0.0",
    "@predicatesystems/authorityd-linux-x64": "1.0.0",
    "@predicatesystems/authorityd-win32-x64": "1.0.0"
  }
}
```

This pattern (used by esbuild, swc, turbo) allows:
```bash
npm install @predicatesystems/authorityd
npx predicate-authorityd --port 8787
```

### Python Package (maintains compatibility)

Keep `pip install predicate-authority` working by bundling Rust binary:
```python
# predicate_authority/__init__.py
def get_sidecar_binary() -> Path:
    """Return path to bundled Rust sidecar binary."""
    return Path(__file__).parent / "bin" / f"predicate-authorityd-{platform}"
```

### Standalone Binaries

GitHub releases with platform-specific binaries:
- `predicate-authorityd-x86_64-unknown-linux-gnu`
- `predicate-authorityd-aarch64-apple-darwin`
- `predicate-authorityd-x86_64-pc-windows-msvc.exe`

---

## Migration Path

### For TypeScript Users

**Before (Python required):**
```bash
pip install predicate-authority predicate-contracts
predicate-authorityd --port 8787
```

**After (no Python):**
```bash
npm install @predicatesystems/authorityd
npx predicate-authorityd --port 8787
```

### For Python Users

**No change required** - Python SDK can use either:
1. Python sidecar (existing)
2. Rust sidecar (new, via bundled binary)

---

## Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Crypto implementation bugs | LOW | HIGH | Use audited crates (ring), comprehensive tests |
| Behavior drift from Python | MEDIUM | MEDIUM | Shared test suite, contract tests |
| IdP edge cases | MEDIUM | MEDIUM | Port Python tests, add integration tests |
| Build complexity | LOW | LOW | GitHub Actions matrix, cargo-dist |
| Maintenance burden | LOW | MEDIUM | Rust's strong type system reduces bugs |

---

## Verification Plan

1. **Unit tests**: Port Python test cases to Rust
2. **Integration tests**: Run TypeScript SDK against both sidecars, compare
3. **Contract tests**: JSON request/response snapshots must match
4. **Load tests**: Verify Rust performance meets expectations
5. **Platform tests**: CI matrix for all target platforms

---

## Post-Migration Cleanup

### Phase 6: AgentIdentity SDK Cleanup (Future)

**Prerequisites**: Rust sidecar confirmed working in production

After the Rust sidecar is validated and stable, remove the embedded Python sidecar code from the AgentIdentity SDK:

1. **Remove Python sidecar dependencies** from `AgentIdentity/`:
   - Remove `predicate-authority` Python package dependency
   - Remove any bundled sidecar code or wrappers

2. **Update SDK documentation**:
   - Point to Rust sidecar binary downloads
   - Update installation instructions to use standalone binary

3. **Remove deprecated code paths**:
   - Remove any Python subprocess spawning for sidecar
   - Remove Python sidecar health check code
   - Clean up any Python-specific configuration handling

4. **Verify SDK tests pass** with Rust sidecar only

**Note**: This cleanup should only proceed after:
- [ ] Rust sidecar passes all integration tests
- [ ] Rust sidecar deployed successfully in staging environment
- [ ] At least 2 weeks of production validation with no issues
- [ ] SDK team sign-off on migration readiness
