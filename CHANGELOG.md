# Changelog

All notable changes to predicate-authorityd will be documented in this file.

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
