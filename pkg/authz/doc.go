// Package authz decides whether an agent may perform an action on a resource.
//
// Policies are YAML, one per tenant: default deny, a deny rule overrides any
// allow, actions match on dot boundaries ("github.issue.*"), and a rule can cap
// the risk class it permits. NativeEngine evaluates them in process with no
// network dependency; OPAEngine delegates to an Open Policy Agent server. agw
// mcp uses this package for MCP tool calls.
//
// This is a public package of github.com/Aryan22g/agw, at v0: a breaking
// change is possible between minor releases and is listed in CHANGELOG.md.
package authz
