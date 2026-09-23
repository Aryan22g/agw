# RFC-0002: AGS1 Request Signing Profile

## Status
**Frozen — AGS1 v1.**

Normative behaviour is implemented in `pkg/ags1`, which is the single source
of truth for both the gateway and every language SDK. Changing any normative
value in this document is a wire-breaking change requiring a new profile
version and a new `tag`, never an edit in place.

### Amendments applied when the profile was frozen

1. **Body-less requests (resolves a contradiction).** Section 1 fixed an
   11-component list while section 3 made `Content-Type` and `Content-Digest`
   conditional on the request carrying a body. Both cannot hold for a `GET`.
   AGS1 v1 defines **two closed profiles** instead of one list: 11 components
   for a body-bearing request, and the same list minus `content-digest` and
   `content-type` (9 components) for a body-less one. A verifier MUST reject
   any request whose declared component list is not exactly one of these two,
   in order — that closure is the property that matters, not a single list.

2. **`created` is the only timestamp.** `expires` is not part of AGS1 v1.
   Freshness is bounded by `created` plus the fixed age and skew windows in
   section 10, so a signer cannot widen its own acceptance window.

3. **Nonce length is bounded.** 22–64 characters is normative, not advisory
   (section 11), because the nonce becomes part of a replay-store key.

4. **Replay TTL raised from 360s to 900s (corrects a zero-margin race).** The
   original 360s was exactly equal to the acceptance window
   (`MaxRequestAge` 300s + `MaxClockSkew` 60s), so a nonce reservation could
   lapse at the very moment its request was still acceptable — leaving a
   window in which a captured request could be replayed. The TTL MUST exceed
   the acceptance window by a real margin, since clocks drift between nodes
   and key expiry is not instantaneous. This is a server-side storage policy,
   not a wire value, so the change is not profile-breaking.

## Owners
Platform Security / Identity Gateway

## Purpose
Define the Stage 1 request-signing profile for autonomous agent requests.

AGS1 is a strict application profile over RFC 9421 HTTP Message Signatures, RFC 9530 Content-Digest, RFC 9651 Structured Fields, RFC 7638 JWK thumbprints, and Ed25519/EdDSA.

## Scope
This RFC defines:
- required request headers
- canonical request components
- header normalization rules
- body hashing rules
- JSON canonicalization rules
- signature input format
- timestamp and nonce policy
- replay-protection semantics

This RFC does not define:
- authorization policy
- approvals
- connector execution logic
- federation
- human SSO
- long-lived session management

## Profile Name
AGS1

## Design Goals
- deterministic wire semantics
- proxy safety
- replay resistance
- cryptographic attribution
- multi-language SDK compatibility
- transport-agnostic verification
- future compatibility with federation and proof-of-possession tokens

## Normative Requirements

### 1. Canonical Covered Components
AGS1 MUST sign the following components in exactly this order:

1. `@method`
2. `@authority`
3. `@path`
4. `@query`
5. `content-digest`;sf
6. `content-type`
7. `x-agent-id`
8. `x-tenant-id`
9. `x-request-id`
10. `x-agent-signature-version`
11. `traceparent`

For body-less requests the covered list is items 1–4 and 7–11, preserving this
relative order.

### 2. Canonical Component Semantics
- `@authority` MUST be used instead of `Host`.
- `@path` MUST be the absolute path without query.
- `@query` MUST be the raw query string including the leading `?`, or exactly `?` when absent.
  Signing a bare empty string for "no query" would make an absent query and an
  empty one produce the same signature base, so a request signed with neither
  could be replayed with `?` appended.
- Component identifiers MUST be lowercase.
- AGS1 MUST reject duplicate values for required signed headers.

### 3. Required Request Headers
The following headers are required:

- `X-Agent-Id`
- `X-Tenant-Id`
- `X-Request-Id`
- `X-Agent-Signature-Version`
- `traceparent`
- `Content-Type` for body-bearing requests
- `Content-Digest` for body-bearing requests
- `Signature-Input`
- `Signature`

### 4. Header Normalization Rules
- Header names are case-insensitive, but component names in AGS1 MUST be lowercase.
- Leading and trailing optional whitespace MUST be trimmed.
- obs-fold MUST be removed if present on HTTP/1.1 input.
- For AGS1 required headers, duplicate instances MUST be rejected.
- Structured Fields MUST be serialized strictly.
- If a multi-instance fallback is ever required, values would combine with `", "`, but AGS1 MUST NOT rely on that fallback for required headers.

### 5. Query and URI Normalization Rules
- The verifier MUST sign the entire `@query` component.
- The verifier MUST NOT parse and re-emit query parameters for signing.
- The SDK MAY normalize safe URI forms before sending.
- The verifier MUST NOT normalize query semantics after receipt.
- Reserved characters MUST NOT be decoded during verification.

### 6. JSON and Unicode Rules
- For JSON bodies, SDKs MUST canonicalize using RFC 8785 JCS.
- JSON output MUST be UTF-8 encoded.
- JCS MUST preserve Unicode strings as-is.
- The canonicalizer MUST NOT apply NFC or NFKC normalization.
- Duplicate JSON keys, NaN, and Infinity MUST be rejected by the SDK or build pipeline.

### 7. Body Hashing Rules
For body-bearing requests:
- the exact transmitted request body bytes MUST be hashed
- JSON bodies MUST use JCS output bytes
- non-JSON bodies MUST use raw transmitted bytes

The digest header format MUST be:

`Content-Digest: sha-256=:BASE64(STANDARD_SHA256(body_bytes)):`

`content-digest` MUST carry the `;sf` component parameter in `Signature-Input`,
and the verifier MUST re-serialize it as a strict structured field before
comparison so that whitespace introduced by an intermediary does not invalidate
an otherwise correct signature.

### 8. Key Type and Identifier Rules
- AGS1 MUST use Ed25519.
- Public keys MUST be represented as JWK with:
  - `kty: "OKP"`
  - `crv: "Ed25519"`
  - `x: "..."`
- `kid` MUST be derived from the RFC 7638 thumbprint over `crv`, `kty`, and `x`.
- The thumbprint MUST be encoded as base64url **without padding**.
- The thumbprint input MUST be exactly the following, with no whitespace and
  members in this (lexicographic) order:

  ```json
  {"crv":"Ed25519","kty":"OKP","x":"<x>"}
  ```

- A `kid` presented alongside a JWK MUST match this derivation. `kid` is the
  lookup key for a credential, so a `kid` naming a key whose material hashes to
  something else would let a signature resolve against the wrong credential.
- **Conformance vector.** The RFC 8037 Appendix A.3 key
  `11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo` MUST produce the thumbprint
  `kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k`. Every AGS1 SDK MUST pass this
  vector before it is considered conformant.

### 9. Signature Input Rules
The `Signature-Input` header MUST use this structure:

```text
sig1=("@method" "@authority" "@path" "@query"
 "content-digest";sf "content-type"
 "x-agent-id" "x-tenant-id" "x-request-id"
 "x-agent-signature-version" "traceparent");
 created=<unix-seconds>;
 keyid="<kid>";
 nonce="<nonce>";
 tag="agw-sig-v1"
````

AGS1 MUST allow only:

* `created`
* `keyid`
* `nonce`
* `tag`

AGS1 MUST NOT include `alg`. A verifier MUST reject any `Signature-Input`
carrying it, and MUST reject any parameter outside the four listed above. The
algorithm is resolved from the registered credential, never from the request:
a wire-supplied algorithm lets a caller steer the verifier toward a weaker
primitive.

The `tag` MUST equal `agw-sig-v1`. A verifier MUST reject any other value, so a
signature minted under a different profile cannot be replayed into an AGS1
verifier.

### 10. Timestamp Rules

* `created` MUST be Unix seconds.
* The accepted age window MUST be 300 seconds.
* The future skew allowance MUST be 60 seconds.

### 11. Nonce Rules

* Nonces MUST be unique per request.
* Minimum nonce entropy MUST be 128 bits. SDKs SHOULD emit 256 bits.
* Nonce charset MUST be base64url without padding.
* Nonce length MUST be 22–64 characters. A verifier MUST reject values outside
  this range before they reach the replay store, since the nonce is
  attacker-controlled input that becomes part of a storage key.
* The replay store MUST hold only `base64url(SHA-256(nonce))`, never the raw
  nonce, so that a dump of the store does not yield a set of usable nonces.

### 12. Replay Protection Rules

Replay protection MUST use a Redis reservation key of the form:

`replay:v1:{tenant_id}:{credential_id}:{sha256b64u(nonce)}`

The key is scoped to the credential rather than the agent so that rotating a
key begins a clean reservation namespace. Identifier components MUST have `:`
replaced with `_` so a crafted identifier cannot shift the key's meaning into
another tenant's namespace.

The reservation value MAY be the hashed signature base or a placeholder value.

Reservation MUST use `SET <key> <value> NX EX <ttl>`, where `<ttl>` is
`ReplayTTLSeconds` (900):

`SET <key> <value> NX EX 900`

The reservation MUST be atomic. A check-then-set leaves a window in which two
concurrent copies of the same request both observe the nonce as unused, which
is exactly the race a replay attacker runs.

`ReplayTTLSeconds` MUST be strictly greater than
`MaxRequestAgeSeconds + MaxClockSkewSeconds`. If it were not, a captured
request could be replayed between its reservation expiring and the request
itself ageing out of the acceptance window.

If reservation fails, the request MUST be rejected as a replay.

Replay protection MUST fail closed if Redis capacity or freshness cannot be trusted.

### 13. Verification Order

The verifier MUST process requests in this order:

1. parse the raw request and canonicalize it
2. parse `Signature-Input` and `Signature`; reject malformed or non-conforming input
3. resolve tenant, agent and credential from `keyid`
4. confirm the credential belongs to the tenant and agent the request claims
5. check credential lifecycle: revoked, inactive, expired
6. validate the timestamp window
7. validate `Content-Digest` against the body
8. verify the signature
9. reserve the nonce
10. emit an audit record
11. allow the request

Two ordering constraints are normative, not stylistic:

- **Nonce reservation MUST come after signature verification.** Reserving
  first lets an unauthenticated observer burn the nonce of a request they
  merely captured, turning replay protection into a denial-of-service
  primitive against the legitimate sender.
- **The credential-to-claimed-identity check (step 4) MUST precede
  authorization.** Without it a valid credential from tenant A could be
  presented on a request asserting tenant B, and policy, rate limiting and
  audit would all attribute the call to B.

Authorization is explicitly NOT part of this sequence. It is a separate
decision, made by the verifier after authentication succeeds.

### 14. Failure Semantics

The verifier MUST fail closed if:

* signature verification fails
* key lookup fails
* nonce reservation fails
* timestamp is outside the accepted window
* revocation state cannot be trusted
* duplicate required headers are present
* canonicalization cannot be performed deterministically

## Non-Goals

This RFC does not define:

* authorization rules
* capability scopes
* approvals
* connector trust
* federation
* token exchange
* session refresh

## Security Rationale

AGS1 intentionally avoids bespoke signing formats and uses a strict standards-based profile to reduce ambiguity, enable proxy-safe verification, and keep room for future federation and proof-of-possession support.

## Acceptance Criteria

This RFC is complete only when:

* the exact covered components are fixed
* the header rules are fixed
* canonicalization is deterministic
* replay semantics are fixed
* JSON canonicalization rules are fixed
* Ed25519/JWK/thumbprint rules are fixed
* test vectors exist for all normative behaviors

## Test Matrix

* valid signed request → accepted
* body tampered after signing → rejected
* query tampered after signing → rejected
* header duplicate present → rejected
* expired request → rejected
* future-dated request beyond skew → rejected
* replayed nonce → rejected
* missing Content-Digest on body request → rejected
* invalid `keyid` / thumbprint → rejected
* unsupported algorithm hint present → rejected
* Redis reservation failure → rejected

## Open Questions

* Should later profiles add sender-constrained tokens in addition to request signatures?
* Should multi-region replay be handled by regional reservation plus central revocation, or by a globally shared replay service?
* Should AGS2 allow additional covered components for delegated authorization?
