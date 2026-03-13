# Multi-Scope Mandate Support

**Status**: Implemented
**Author**: Claude
**Date**: 2026-03-08
**Version**: 1.0

## Problem Statement

The current mandate model supports only a single `action` and `resource` pair per mandate. This creates problems for orchestrator agents that need to delegate multiple types of operations to child agents.

### Current Workaround

Orchestrators must request **separate root mandates** for each scope they intend to delegate:

```python
# Browser scope mandate
browser_mandate = await client.authorize_root(
    principal="agent:orchestrator",
    action="browser.*",
    resource="https://www.amazon.com/*",
)

# Filesystem scope mandate
fs_mandate = await client.authorize_root(
    principal="agent:orchestrator",
    action="fs.*",
    resource="**/workspace/data/**",
)
```

### Problems with Current Approach

1. **No unified audit trail** - Multiple mandate chains for what's logically one orchestration
2. **Cascade revocation doesn't work** - Revoking one mandate doesn't revoke related delegations
3. **Multiple auth requests** - N scopes = N authorization calls (latency, overhead)
4. **Scope tracking complexity** - Orchestrator must track which mandate to use for each delegation
5. **Policy fragmentation** - Hard to express "orchestrator can do browser+fs" as single policy rule

## Proposed Solution

### Option A: Multi-Scope ActionSpec (Recommended)

Extend `ActionSpec` to support arrays of action/resource pairs:

```rust
// Current (single scope)
pub struct ActionSpec {
    pub action: String,
    pub resource: String,
    pub intent: String,
}

// Proposed (multi-scope)
pub struct ActionSpec {
    pub scopes: Vec<ScopeSpec>,  // One or more scopes
    pub intent: String,
}

pub struct ScopeSpec {
    pub action: String,
    pub resource: String,
}
```

#### Wire Format

```json
{
  "principal": "agent:orchestrator",
  "scopes": [
    { "action": "browser.*", "resource": "https://www.amazon.com/*" },
    { "action": "fs.*", "resource": "**/workspace/data/**" }
  ],
  "intent_hash": "orchestrate:ecommerce:run-123"
}
```

#### Scope Narrowing for Delegation

When delegating from a multi-scope parent, the child scope must be a subset of **at least one** parent scope (OR semantics):

```
Parent: [browser.*, fs.*]
Child request: browser.navigate → ALLOWED (matches browser.*)
Child request: fs.write → ALLOWED (matches fs.*)
Child request: network.* → DENIED (matches none)
```

### Option B: Scope Bundle Token

Alternative: Keep single-scope mandates but issue a "bundle token" that references multiple mandates:

```json
{
  "bundle_id": "bundle-abc123",
  "mandate_tokens": ["mandate-browser-xyz", "mandate-fs-xyz"],
  "unified_revocation": true
}
```

**Pros**: Backward compatible, simpler initial implementation
**Cons**: Still multiple mandates internally, complex revocation logic

### Recommendation

**Option A (Multi-Scope ActionSpec)** is cleaner long-term:
- Single mandate = single audit entry
- Natural cascade revocation
- Simpler mental model for orchestrators
- Better aligns with "one task = one authorization"

## Implementation Status

### Phase 1: Sidecar Changes ✅ COMPLETE

1. **Extended `ActionSpec` model** (`src/models/mod.rs`)
   - Added `ScopeSpec` struct with `action` and `resource` fields
   - Modified `ActionSpec` to include `scopes: Vec<ScopeSpec>`
   - Added helper methods: `ActionSpec::single()`, `ActionSpec::multi()`, `all_scopes()`, `is_multi_scope()`
   - Backward compatible: single action/resource still works

2. **Updated `MandateClaims`** (`src/models/mod.rs`)
   - Added `scopes: Vec<ScopeSpec>` field to JWT claims
   - Added `all_scopes()` and `is_multi_scope()` helper methods

3. **Updated authorization logic** (`src/http/mod.rs`)
   - `authorize_handler` now evaluates each scope against policy rules
   - All scopes must be allowed for request to succeed
   - Returns `scopes_authorized` array in response

4. **Updated mandate issuance** (`src/mandate/mod.rs`)
   - `LocalMandateSigner::issue()` encodes all scopes in JWT claims

5. **Updated delegation validation** (`src/http/delegate.rs`, `src/policy/subset.rs`)
   - Added `is_scope_subset_of_any()` for multi-scope parent validation
   - Child scope must match at least one parent scope (OR semantics)

6. **Updated HTTP request/response** (`src/models/mod.rs`)
   - `SidecarAuthorizeRequest` accepts `scopes` array
   - `SidecarAuthorizeResponse` includes `scopes_authorized` array

### Phase 2: SDK Changes (TODO)

1. **Python SDK** (`sdk-python`)
   - `authorize()` accepts `scopes: List[Dict]` parameter
   - Backward compatible: `action`/`resource` params still work

2. **TypeScript SDK** (`sdk-ts`)
   - Same pattern as Python

### Phase 3: Demo Updates (TODO)

1. **CrewAI E-commerce Demo** (`predicate-secure/examples/crewai-ecommerce-demo`)
   - Update `main.py` to use single multi-scope authorization
   - Remove workaround of multiple root mandates

## API Changes

### `/v1/authorize` Request

**Current (backward compatible)**:
```json
{
  "principal": "agent:orchestrator",
  "action": "browser.*",
  "resource": "https://example.com/*"
}
```

**New multi-scope**:
```json
{
  "principal": "agent:orchestrator",
  "scopes": [
    { "action": "browser.*", "resource": "https://example.com/*" },
    { "action": "fs.*", "resource": "**/workspace/**" }
  ],
  "intent_hash": "orchestrate:run-123"
}
```

### `/v1/authorize` Response

```json
{
  "allowed": true,
  "reason": "all scopes authorized",
  "mandate_id": "mandate-abc123",
  "mandate_token": "eyJ...",
  "scopes_authorized": [
    { "action": "browser.*", "resource": "https://example.com/*", "matched_rule": "allow-browser" },
    { "action": "fs.*", "resource": "**/workspace/**", "matched_rule": "allow-fs" }
  ]
}
```

### `/v1/delegate` Request

No change - child requests single scope, validated against parent's multi-scope mandate.

## Backward Compatibility

1. **Single scope requests**: Continue to work unchanged
2. **Existing mandates**: Single-scope mandates remain valid
3. **SDK versions**: Old SDKs work with single-scope; new SDKs support both
4. **Wire format**: `action`/`resource` fields deprecated but supported

## Migration Path

1. Release sidecar with multi-scope support (backward compatible)
2. Update SDKs with optional `scopes` parameter
3. Update demos to use multi-scope where beneficial
4. Deprecation warnings for single-scope in future version

---

## Changes Required in CrewAI Demo

Once multi-scope mandates are implemented, the CrewAI e-commerce demo should be updated:

### Current Workaround (`main.py`)

```python
# Current: Multiple separate root mandates (workaround)
browser_root_mandate = await _delegation_client.authorize_root(
    principal="agent:orchestrator",
    action="browser.*",
    resource="https://www.amazon.com/*",
    intent_hash=f"orchestrate:browser:{run_id}",
)

fs_root_mandate = await _delegation_client.authorize_root(
    principal="agent:orchestrator",
    action="fs.*",
    resource="**/workspace/data/**",
    intent_hash=f"orchestrate:fs:{run_id}",
)

# Must track which mandate to use for which delegation
scraper_mandate = await _delegation_client.delegate(
    parent_mandate_token=browser_root_mandate.mandate_token,
    child_principal="agent:scraper",
    ...
)

analyst_mandate = await _delegation_client.delegate(
    parent_mandate_token=fs_root_mandate.mandate_token,  # Different parent!
    child_principal="agent:analyst",
    ...
)
```

### Future: Multi-Scope Implementation

```python
# Future: Single multi-scope root mandate
orchestrator_mandate = await _delegation_client.authorize_root(
    principal="agent:orchestrator",
    scopes=[
        {"action": "browser.*", "resource": "https://www.amazon.com/*"},
        {"action": "fs.*", "resource": "**/workspace/data/**"},
    ],
    intent_hash=f"orchestrate:ecommerce:{run_id}",
)

# Single mandate used for all delegations
scraper_mandate = await _delegation_client.delegate(
    parent_mandate_token=orchestrator_mandate.mandate_token,  # Same parent
    child_principal="agent:scraper",
    action="browser.navigate",
    resource="https://www.amazon.com/s?k=laptop",
)

analyst_mandate = await _delegation_client.delegate(
    parent_mandate_token=orchestrator_mandate.mandate_token,  # Same parent
    child_principal="agent:analyst",
    action="fs.write",
    resource="/workspace/data/analysis.json",
)
```

### Demo Files to Update

1. **`main.py`**
   - Replace multiple `authorize_root()` calls with single multi-scope call
   - Remove mandate tracking logic (no need to match mandate to scope)
   - Update docstrings and comments

2. **`delegation_client.py`** (if exists)
   - Add `scopes` parameter to `authorize_root()`
   - Keep backward compatibility with `action`/`resource` params

3. **`policies/monitoring.yaml`**
   - Update policy rules to allow multi-scope authorization
   - Example:
     ```yaml
     rules:
       - name: allow-orchestrator-multi-scope
         principal: "agent:orchestrator"
         actions: ["browser.*", "fs.*"]  # Multiple actions
         resources: ["https://*.amazon.com/*", "**/workspace/**"]
         effect: allow
     ```

4. **`README.md`**
   - Document multi-scope authorization usage
   - Update architecture diagram showing single mandate chain

### Benefits for Demo

- **Cleaner code**: One mandate, one delegation chain
- **Better observability**: Single audit trail per orchestration run
- **Simpler error handling**: One authorization to check, not N
- **Proper revocation**: Revoking orchestrator mandate revokes all child delegations

---

## Open Questions

1. **Scope limit**: Should there be a max number of scopes per mandate? (Suggested: 10)
2. **Partial authorization**: If 2/3 scopes allowed, should we issue partial mandate or deny?
3. **Scope intersection**: Can child request scope that spans multiple parent scopes?

## References

- [Chain Delegation Documentation](./sidecar-user-manual.md#delegation-chains)
- [CrewAI Demo](../../predicate-secure/examples/crewai-ecommerce-demo/)
- [Scope Narrowing Rules](../src/delegation/scope.rs)
