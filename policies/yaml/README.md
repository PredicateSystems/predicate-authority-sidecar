# YAML Policy Templates

This directory contains YAML versions of the policy templates. YAML format offers:
- Better readability with comments
- Cleaner syntax for lists and nested structures
- Easier manual editing

## Available Templates

| Policy | Description |
|--------|-------------|
| [strict.yaml](strict.yaml) | Production default - workspace isolation, safe commands, HTTPS only |
| [read-only.yaml](read-only.yaml) | Code review - read-only access, no mutations |
| [permissive.yaml](permissive.yaml) | Development - minimal restrictions |
| [secret-injection.yaml](secret-injection.yaml) | API + CLI with automatic secret injection |

## Usage

```bash
# Start sidecar with YAML policy
./predicate-authorityd --policy-file policies/yaml/strict.yaml run

# Or use environment variable
export PREDICATE_POLICY_FILE=policies/yaml/secret-injection.yaml
./predicate-authorityd run
```

## Format Auto-Detection

The sidecar auto-detects format by file extension:
- `.yaml` or `.yml` → YAML format
- `.json` → JSON format

## Secret Injection Example

The `secret-injection.yaml` policy demonstrates how to inject secrets at execution time:

```yaml
- name: github-api-with-auth
  effect: allow
  principals: ["agent:*"]
  actions: ["http.fetch"]
  resources: ["https://api.github.com/*"]
  inject_headers:
    Authorization: "Bearer ${GITHUB_TOKEN}"
    Accept: "application/vnd.github.v3+json"
```

Set the environment variable before starting the sidecar:

```bash
export GITHUB_TOKEN="ghp_xxxxxxxxxxxx"
./predicate-authorityd --policy-file policies/yaml/secret-injection.yaml run
```

The agent never sees the token - the sidecar injects it at execution time.

## See Also

- [JSON policies](../) - JSON versions of these policies
- [Policy README](../README.md) - Full policy documentation
- [Sidecar User Manual](../../docs/sidecar-user-manual.md) - Complete sidecar documentation
