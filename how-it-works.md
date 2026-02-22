# How IdP + Sidecar + Mandates Work Together

---

## The Problem: Static Scopes Cannot Secure Non-Deterministic Agents

When you connect an AI agent to an Identity Provider (IdP) like Okta or Entra, it receives an access token. That token is a **passport**—it proves the agent's identity and carries static scopes (like `database:write`) to get it through the front door of your API.

However, IdP scopes are broad and coarse-grained. If a prompt injection tricks your agent into calling `drop_database` instead of `update_record`, your API will execute the attack because the agent's token legitimately holds the `database:write` scope. The IdP cannot evaluate the context of the action.

---

## The Solution: The Per-Action Work Visa

To stop rogue actions, agents need a **work visa**—a real-time, deterministic permission slip evaluated just milliseconds before a specific action executes.

This is how Predicate Authority works:

1. **The Passport:** The AI agent gets its standard token from your IdP (Okta/Entra).
2. **The Border Check:** Before executing a tool, the agent shows its token to the local Predicate Sidecar.
3. **The Visa (Mandate):** The sidecar validates the token, checks the deterministic policy, and if the action is safe, issues a cryptographic **Mandate** (the visa).
4. **Execution:** The agent passes the Mandate to the backend API, which verifies it and executes the action.

---

## Architecture Flow

```
┌─────────────┐     ┌─────────┐     ┌──────────────────────┐     ┌─────────┐
│  AI Agent   │────▶│  Okta   │────▶│  predicate-authority │────▶│ Backend │
│             │     │  (IdP)  │     │      (Sidecar)       │     │   API   │
└─────────────┘     └─────────┘     └──────────────────────┘     └─────────┘
      │                  │                     │                      │
      │ 1. Get access    │                     │                      │
      │    token         │                     │                      │
      │─────────────────▶│                     │                      │
      │◀─────────────────│                     │                      │
      │  access_token    │                     │                      │
      │  (The Passport)  │                     │                      │
      │                                        │                      │
      │ 2. Request to execute action           │                      │
      │───────────────────────────────────────▶│                      │
      │    POST /v1/authorize                  │                      │
      │    Authorization: Bearer <token>       │                      │
      │                                        │                      │
      │                     3. Validate token  │                      │
      │                        & Check Policy  │                      │
      │                                        │                      │
      │◀───────────────────────────────────────│                      │
      │  {allowed: true, mandate_id: "m_123"}  │                      │
      │  (The Visa)                            │                      │
      │                                        │                      │
      │ 4. Call backend with Mandate           │                      │
      │───────────────────────────────────────────────────────────────▶│
      │    X-Predicate-Mandate: m_123          │                      │
      │                                        │                      │
```

The key insight: **the sidecar does NOT issue or refresh IdP tokens**. Instead:

1. **The AI agent obtains tokens from the IdP directly** (e.g., Okta)
2. **The sidecar validates those tokens** before issuing mandates
3. **Mandates are short-lived authorization tokens** that the agent uses for specific actions

---

## Step-by-Step Example

### Step 1: Start the Sidecar with Okta Identity Mode

```bash
# Set Okta configuration
export OKTA_ISSUER="https://your-org.okta.com/oauth2/default"
export OKTA_CLIENT_ID="0oa1234567890abcdef"
export OKTA_AUDIENCE="api://predicate-authority"

# Start sidecar
./predicate-authorityd \
  --host 127.0.0.1 \
  --port 8787 \
  --mode cloud_connected \
  --policy-file policy.json \
  --identity-mode okta \
  --okta-issuer "$OKTA_ISSUER" \
  --okta-client-id "$OKTA_CLIENT_ID" \
  --okta-audience "$OKTA_AUDIENCE" \
  --okta-required-scopes "authority:check" \
  --idp-token-ttl-s 300 \
  --mandate-ttl-s 300 \
  run
```

The sidecar will:
- Fetch JWKS (JSON Web Key Set) from `${OKTA_ISSUER}/.well-known/jwks.json`
- Cache the keys for token validation
- Require valid Okta tokens on `/v1/authorize` requests

### Step 2: AI Agent Gets Token from Okta

The agent (or its orchestrator) obtains an access token directly from Okta:

```python
# Example: Agent gets Okta token using client credentials
import httpx

async def get_okta_token():
    response = await httpx.post(
        "https://your-org.okta.com/oauth2/default/v1/token",
        data={
            "grant_type": "client_credentials",
            "client_id": "agent-client-id",
            "client_secret": "agent-client-secret",
            "scope": "authority:check"
        }
    )
    data = response.json()
    return data["access_token"], data.get("refresh_token")

access_token, refresh_token = await get_okta_token()
```

**The agent holds the refresh_token**, not the sidecar.

### Step 3: Agent Requests Authorization with Okta Token

```python
# Agent calls sidecar with Okta token
async def authorize_action(access_token: str, action: str, resource: str):
    response = await httpx.post(
        "http://127.0.0.1:8787/v1/authorize",
        headers={
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json"
        },
        json={
            "principal": "agent:payments",
            "action": action,
            "resource": resource,
            "intent_hash": "intent_abc123"
        }
    )
    return response.json()

# Example usage
decision = await authorize_action(
    access_token,
    action="http.post",
    resource="https://api.vendor.com/transfers"
)

if decision["allowed"]:
    mandate_id = decision["mandate_id"]  # e.g., "m_7f3a2b1c"
    # Use mandate_id for the actual API call
else:
    raise AuthorizationError(decision["reason"])
```

### Step 4: What the Sidecar Does

When the sidecar receives this request:

1. **Extracts** the bearer token from the `Authorization` header
2. **Validates** the JWT against Okta's JWKS:
   - Verifies signature using Okta's public keys
   - Checks `iss` (issuer) matches configured `--okta-issuer`
   - Checks `aud` (audience) matches configured `--okta-audience`
   - Checks token is not expired (`exp`)
   - Checks required scopes are present
3. **Evaluates** the policy rules
4. **Issues** a short-lived mandate if allowed
5. **Returns** the decision with mandate_id

```rust
// From src/http/mod.rs - what happens internally
async fn authorize_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<SidecarAuthorizeRequest>,
) -> impl IntoResponse {
    // 1. Validate bearer token if IdP bridge is configured
    if let Some(ref bridge) = state.idp_bridge {
        if bridge.requires_token() {
            let token = extract_bearer_token(&headers)?;

            // 2. Validate against Okta JWKS
            match bridge.validate_token(&token).await {
                Ok(Some(identity)) => {
                    // Token valid - identity.subject contains Okta sub claim
                }
                Err(e) => {
                    return (StatusCode::UNAUTHORIZED, "INVALID_TOKEN");
                }
            }
        }
    }

    // 3. Evaluate policy
    let result = state.policy_engine.evaluate(&request);

    // 4. Issue mandate if allowed (signed by sidecar)
    // ...
}
```

### Step 5: Token Refresh Flow

**The sidecar does NOT hold refresh tokens.** Here's how refresh works:

```python
class AgentAuthManager:
    def __init__(self):
        self.access_token = None
        self.refresh_token = None
        self.token_expiry = None

    async def ensure_valid_token(self):
        """Refresh Okta token if needed (agent manages this)"""
        if self.token_expiry and datetime.now() < self.token_expiry - timedelta(minutes=5):
            return self.access_token

        # Refresh from Okta
        response = await httpx.post(
            "https://your-org.okta.com/oauth2/default/v1/token",
            data={
                "grant_type": "refresh_token",
                "client_id": "agent-client-id",
                "refresh_token": self.refresh_token
            }
        )
        data = response.json()
        self.access_token = data["access_token"]
        self.refresh_token = data.get("refresh_token", self.refresh_token)
        self.token_expiry = datetime.now() + timedelta(seconds=data["expires_in"])
        return self.access_token

    async def authorize(self, action: str, resource: str):
        """Get fresh token, then authorize action"""
        token = await self.ensure_valid_token()
        return await authorize_action(token, action, resource)
```

---

## Key Architecture Points

### What the Sidecar DOES:
1. **Validates IdP tokens** (via JWKS, not by calling IdP token endpoint)
2. **Caches JWKS keys** (with TTL, auto-refreshes on key rotation)
3. **Issues mandates** (short-lived, signed by sidecar's own key)
4. **Enforces TTL constraints** (`idp-token-ttl-s >= mandate-ttl-s`)

### What the Sidecar DOES NOT DO:
1. **Does not obtain tokens** from IdP
2. **Does not hold refresh tokens**
3. **Does not refresh IdP tokens**
4. **Does not act as an OAuth client**

### Why This Design?

```
Security principle: Separation of concerns

┌─────────────────────────────────────────────────────────────────┐
│                        AI Agent Runtime                         │
│  ┌──────────────┐                                               │
│  │ Token Manager│ ← Holds refresh_token, manages lifecycle      │
│  └──────────────┘                                               │
└─────────────────────────────────────────────────────────────────┘
         │ access_token
         ▼
┌─────────────────────────────────────────────────────────────────┐
│                    predicate-authorityd                         │
│  - Validates tokens (stateless, via JWKS)                       │
│  - Issues mandates (short-lived, action-scoped)                 │
│  - No secrets from IdP needed (only public keys)                │
└─────────────────────────────────────────────────────────────────┘
```

This design means:
- **Sidecar doesn't need IdP secrets** (client_secret) - only validates with public keys
- **Token lifecycle is agent's responsibility** - fits various orchestration patterns
- **Sidecar can be stateless** - easier to scale, restart, deploy

---

## Complete End-to-End Example

```python
import httpx
from datetime import datetime, timedelta

class PredicateAuthorityAgent:
    """AI Agent with Okta + Predicate Authority integration"""

    def __init__(self, okta_config: dict, sidecar_url: str):
        self.okta_config = okta_config
        self.sidecar_url = sidecar_url
        self.access_token = None
        self.refresh_token = None
        self.token_expiry = None

    async def _get_okta_token(self):
        """Get initial token from Okta"""
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.okta_config['issuer']}/v1/token",
                data={
                    "grant_type": "client_credentials",
                    "client_id": self.okta_config["client_id"],
                    "client_secret": self.okta_config["client_secret"],
                    "scope": "authority:check"
                }
            )
            data = response.json()
            self.access_token = data["access_token"]
            self.refresh_token = data.get("refresh_token")
            self.token_expiry = datetime.now() + timedelta(seconds=data["expires_in"])

    async def _ensure_valid_token(self):
        """Refresh token if needed"""
        if not self.access_token or datetime.now() >= self.token_expiry - timedelta(minutes=1):
            await self._get_okta_token()
        return self.access_token

    async def authorize_and_execute(self, action: str, resource: str, execute_fn):
        """
        1. Ensure valid Okta token
        2. Get mandate from sidecar
        3. Execute action with mandate
        """
        # Step 1: Get valid Okta token
        token = await self._ensure_valid_token()

        # Step 2: Authorize with sidecar
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.sidecar_url}/v1/authorize",
                headers={
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json"
                },
                json={
                    "principal": "agent:payments",
                    "action": action,
                    "resource": resource,
                    "intent_hash": f"intent_{hash(resource)}"
                }
            )
            decision = response.json()

        if not decision["allowed"]:
            raise PermissionError(f"Action denied: {decision['reason']}")

        # Step 3: Execute with mandate
        mandate_id = decision.get("mandate_id")
        return await execute_fn(mandate_id)


# Usage
async def main():
    agent = PredicateAuthorityAgent(
        okta_config={
            "issuer": "https://your-org.okta.com/oauth2/default",
            "client_id": "agent-client-id",
            "client_secret": "agent-client-secret"
        },
        sidecar_url="http://127.0.0.1:8787"
    )

    async def transfer_funds(mandate_id):
        async with httpx.AsyncClient() as client:
            return await client.post(
                "https://api.vendor.com/transfers",
                headers={"X-Predicate-Mandate": mandate_id},
                json={"amount": 100, "to": "account_xyz"}
            )

    result = await agent.authorize_and_execute(
        action="http.post",
        resource="https://api.vendor.com/transfers",
        execute_fn=transfer_funds
    )
```

---

## Summary

| Component | Responsibility |
|-----------|---------------|
| **Okta (IdP)** | Issues access_token and refresh_token to the agent |
| **AI Agent** | Holds tokens, refreshes them, passes to sidecar |
| **Sidecar** | Validates tokens via JWKS, issues mandates, enforces policy |
| **Backend API** | Validates mandate, executes action |

The sidecar is a **stateless validator** that:
- Validates IdP tokens using cached public keys (JWKS)
- Issues short-lived mandates for authorized actions
- Does NOT manage IdP token lifecycle (that's the agent's job)

---

## Local IDP Mode: Sidecar as Token Issuer

In **local-idp mode**, the sidecar works differently - it acts as both token issuer AND validator. This is useful for development, air-gapped environments, and ephemeral task isolation.

### Local IDP Architecture

```
┌─────────────┐                    ┌──────────────────┐     ┌─────────┐
│  AI Agent   │───────────────────▶│ predicate-authorityd │────▶│ Backend │
│             │                    │    (Sidecar)     │     │   API   │
└─────────────┘                    └──────────────────┘     └─────────┘
      │                                    │                    │
      │ 1. POST /identity/task             │                    │
      │    {principal_id, task_id, ttl}    │                    │
      │───────────────────────────────────▶│                    │
      │◀───────────────────────────────────│                    │
      │  {token: "eyJ...", expires_at}     │                    │
      │                                    │                    │
      │ 2. POST /v1/authorize              │                    │
      │    Authorization: Bearer <token>   │                    │
      │───────────────────────────────────▶│                    │
      │                   Validate token   │                    │
      │                   (self-signed)    │                    │
      │◀───────────────────────────────────│                    │
      │  {allowed: true, mandate_id}       │                    │
      │                                    │                    │
```

### Key Differences: External IdP vs Local IDP

| Aspect | Okta/OIDC/Entra Mode | Local IDP Mode |
|--------|----------------------|----------------|
| **Token issuer** | External IdP (Okta, etc.) | Sidecar itself |
| **Token endpoint** | IdP's `/v1/token` | Sidecar's `/identity/task` |
| **Signing keys** | IdP's keys (fetched via JWKS) | Local signing key (`LOCAL_IDP_SIGNING_KEY`) |
| **Refresh tokens** | IdP manages | No refresh tokens (request new task identity) |
| **Use case** | Enterprise SSO, production | Development, CI/CD, air-gapped environments |

### Step 1: Start Sidecar with Local IDP

```bash
export LOCAL_IDP_SIGNING_KEY="your-secret-signing-key"

./predicate-authorityd \
  --host 127.0.0.1 \
  --port 8787 \
  --mode local_only \
  --policy-file policy.json \
  --identity-file ./local-identities.json \
  --identity-mode local-idp \
  --local-idp-issuer "http://localhost/predicate-local-idp" \
  --local-idp-audience "api://predicate-authority" \
  run
```

### Step 2: Agent Requests Task Identity (Token from Sidecar)

```python
import httpx

async def get_task_identity(principal_id: str, task_id: str, ttl_seconds: int = 300):
    """Get a short-lived token from the sidecar itself"""
    response = await httpx.post(
        "http://127.0.0.1:8787/identity/task",
        json={
            "principal_id": principal_id,
            "task_id": task_id,
            "ttl_seconds": ttl_seconds
        }
    )
    data = response.json()
    return data["token"], data["expires_at"]

# Example: Get token for a specific task
token, expires_at = await get_task_identity(
    principal_id="agent:payments",
    task_id="transfer-task-123",
    ttl_seconds=120  # 2 minutes
)
```

### Step 3: Agent Authorizes with Token (Same as External IdP)

```python
async def authorize_action(token: str, action: str, resource: str):
    """Same flow as Okta - pass token to sidecar"""
    response = await httpx.post(
        "http://127.0.0.1:8787/v1/authorize",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        },
        json={
            "principal": "agent:payments",
            "action": action,
            "resource": resource,
            "intent_hash": "intent_abc123"
        }
    )
    return response.json()

decision = await authorize_action(
    token,
    action="http.post",
    resource="https://api.vendor.com/transfers"
)
```

### No Refresh Tokens - Just Request New Identity

Unlike external IdPs, local-idp doesn't use refresh tokens. When a token expires, simply request a new task identity:

```python
from datetime import datetime, timedelta

class LocalIdpAgent:
    """Agent using local-idp mode"""

    def __init__(self, sidecar_url: str, principal_id: str):
        self.sidecar_url = sidecar_url
        self.principal_id = principal_id
        self.token = None
        self.token_expiry = None

    async def ensure_valid_token(self, task_id: str):
        """Get new token if expired (no refresh - just request new)"""
        if self.token and datetime.now() < self.token_expiry - timedelta(seconds=30):
            return self.token

        # Request new task identity from sidecar
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.sidecar_url}/identity/task",
                json={
                    "principal_id": self.principal_id,
                    "task_id": task_id,
                    "ttl_seconds": 300
                }
            )
            data = response.json()
            self.token = data["token"]
            self.token_expiry = datetime.fromisoformat(data["expires_at"])

        return self.token

    async def authorize(self, task_id: str, action: str, resource: str):
        """Ensure valid token, then authorize"""
        token = await self.ensure_valid_token(task_id)

        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.sidecar_url}/v1/authorize",
                headers={
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json"
                },
                json={
                    "principal": self.principal_id,
                    "action": action,
                    "resource": resource,
                    "intent_hash": f"intent_{hash(resource)}"
                }
            )
            return response.json()
```

### When to Use Local IDP vs External IdP

| Use Case | Recommended Mode |
|----------|-----------------|
| Enterprise production with SSO | `okta`, `entra`, or `oidc` |
| Local development | `local` (no tokens) or `local-idp` |
| Air-gapped environments | `local-idp` |
| Ephemeral task isolation | `local-idp` |
| CI/CD pipelines | `local-idp` |
| Multi-tenant production | `okta` or `entra` |

### Local IDP Summary

**Local IDP mode = Sidecar issues AND validates tokens**

- No external IdP dependency
- Sidecar signs tokens with `LOCAL_IDP_SIGNING_KEY`
- Tokens are short-lived (configurable TTL)
- No refresh tokens - just request new task identity
- Same `/v1/authorize` flow as external IdP mode (token in `Authorization` header)

The authorization flow after getting the token is identical to external IdP - the only difference is where the token comes from.

---

## Related Documentation

- [README.md](README.md) - Installation and CLI reference
- [AgentIdentity/docs/authorityd-operations.md](https://github.com/PredicateSystems/predicate-authority/blob/main/docs/authorityd-operations.md) - Production operations guide
