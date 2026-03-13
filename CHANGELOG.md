# Changelog

All notable changes to predicate-authorityd will be documented in this file.

## [0.7.1] - 2026-03-12

### Security Fixes

#### Policy Reload Authentication (Issue #26)
- **Bearer token authentication**: `/policy/reload` endpoint now supports `--policy-reload-secret` to require `Authorization: Bearer <token>`
- **Disable endpoint option**: `--disable-policy-reload` returns 404, requiring sidecar restart for policy changes
- **Configuration sources**: CLI flag, environment variable (`PREDICATE_POLICY_RELOAD_SECRET`), and TOML config file

#### SSRF Whitelist for Local Services (Issue #27)
- **Policy-driven whitelist**: Add `ssrf_whitelist` array to policy JSON/YAML to bypass SSRF protection for specific `host:port` endpoints
- **Multiple configuration sources**: CLI (`--ssrf-allow`), env var (`PREDICATE_SSRF_ALLOW`), TOML config, and policy file
- **Merging behavior**: Entries from all sources are combined; exact `host:port` matching limits exemption surface

### Added

#### Secret Injection (Policy-Driven)
- **`inject_headers` rule field**: Auto-inject auth headers for HTTP requests (e.g., `Authorization: Bearer ${GITHUB_TOKEN}`)
- **`inject_env` rule field**: Auto-inject environment variables for CLI commands (e.g., AWS credentials)
- **Environment variable substitution**: Supports `${VAR}` and `${VAR:-default}` syntax
- **Zero-trust pattern**: Secrets stay on sidecar; agents never see raw credentials
- **New policy template**: `policies/secret-injection.json` demonstrates API and CLI credential injection

### Documentation
- Added "Glob `**` Directory Matching Footgun" section to policy README
- Added SSRF whitelist configuration to user manual and UI docs
- Added policy reload security options to CLI help and documentation

## [0.5.7] - 2026-03-05

### Added

#### Path Normalization in Policy Evaluation
- **Path traversal prevention**: Added `normalize_path()` function in policy engine that resolves `.` and `..` components before matching against policy rules
- **Home directory expansion**: Paths starting with `~` are expanded to the user's home directory
- **Automatic normalization for fs.* actions**: File system actions (`fs.read`, `fs.write`, etc.) now have their resource paths normalized before policy evaluation

### Security
- **Defense in depth**: Path normalization now happens in both SDK (before sending to sidecar) and sidecar (during policy evaluation), providing layered protection against path traversal attacks
- **Adversarial input handling**: Inputs like `./workspace/../../../etc/passwd` are now correctly resolved to `/etc/passwd` and matched against deny rules

### Tests
- Added `path_normalization_tests` module with tests for:
  - Path traversal removal
  - Redundant slash handling
  - Dot component resolution
  - Parent directory at root handling

## [0.5.0] - 2026-02-27

### Added

#### Chain Delegation Support (Phase 1)
- **POST /v1/delegate endpoint**: Issue derived mandates with cryptographic provenance linking child mandates to parent authorization
- **Scope subset validation**: Enforce scope narrowing in delegation chains - child mandates must request equal or narrower scope than parent
- **Delegation depth limits**: Configurable maximum chain depth (default: 5) to prevent unbounded delegation
- **TTL capping**: Derived mandate expiration automatically capped to parent's remaining TTL
- **Delegation chain hash**: Cryptographic verification of delegation chain integrity

#### Mandate Revocation Cache (Phase 2)
- **O(1) mandate revocation lookups**: HashSet-based revocation cache for instant mandate ID checks
- **Sync snapshot extension**: `revoked_mandate_ids` field in control-plane sync for cascade revocation support
- **Revocation cache stats**: Extended statistics including mandate revocation counts

### New Files
- `src/models/delegation.rs` - DelegateRequest, DelegateResponse, DelegateError types
- `src/policy/subset.rs` - Scope subset validation (is_action_subset, is_resource_subset, is_scope_subset)
- `src/http/delegate.rs` - Delegation endpoint handler and DelegationState

### Changed
- `AppState` now supports optional `DelegationState` for delegation-enabled deployments
- `RevocationCache` extended with `by_mandate_id` field and mandate-level revocation methods
- `AuthoritySyncSnapshot` extended with `revoked_mandate_ids` for control-plane cascade revocation

## [0.4.1] - Previous Release

See git history for earlier changes.
