# Changelog

All notable changes to predicate-authorityd will be documented in this file.

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
