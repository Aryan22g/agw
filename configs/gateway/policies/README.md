# Gateway policies

One YAML file per tenant. The `tenant:` field binds the policy; the filename is
for humans.

## Rules

| Field | Meaning |
|---|---|
| `id` | Stable rule identifier. Appears in audit detail. Must be unique within the policy. |
| `effect` | `allow` or `deny`. A matching `deny` always wins. |
| `agents` | Agent ids, or `*` for any agent in the tenant. |
| `actions` | Route actions. `github.issue.*` matches on the dot boundary. `*` matches any. |
| `resources` | Resource ids. `acme/*` matches on the slash boundary. Omit to leave the rule unscoped by resource. |
| `max_risk_class` | Caps route risk: `read` < `write` < `privileged` < `destructive`. |
| `not_before` / `not_after` | RFC 3339 timestamps bounding a time-limited delegation. |

## Guarantees worth knowing

- **Default deny.** A request that matches no `allow` rule is refused.
- **A tenant with no policy file is denied everything.** Adding a tenant does
  not open routes to it.
- **`deny` cannot be overridden.** Adding a broader `allow` later cannot
  re-enable something a `deny` rule refuses, so a guardrail stays a guardrail.
- **Unknown keys are a load error.** A misspelled `resource:` would otherwise
  parse to nothing and silently widen a rule from one resource to all of them.

Policies are validated at startup. A malformed policy fails the deploy rather
than denying live traffic.
