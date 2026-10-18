# @openid-federation/core

## 1.0.0

### Major Changes

- 8e30ac3: Apply metadata policies as described in Section 6.1 of OpenID Federation 1.0.

  - `subset_of`, `superset_of` and `one_of` have no effect when the metadata parameter is absent. Before, `subset_of` and `superset_of` rejected the chain.
  - `superset_of` checks that the metadata parameter contains every operator value. Before, the check was reversed, so `superset_of: ["a"]` rejected `["a", "b"]` and accepted `[]`.
  - `subset_of` may leave an empty array, which stays the value of the metadata parameter, also when `essential` is `true` (Table 1). Before, the parameter was removed, and `essential` rejected an empty array. Merging two `subset_of` without common values results in `[]` instead of a policy error; `one_of` still requires common values.
  - `essential` values are merged with a logical OR. Before, the superior's value was kept, so a subordinate could not make a parameter essential. `MetadataMergeStrategy.SuperiorFollowsIfTrue` is replaced by `LogicalOr`; `subset_of` uses the new `IntersectionMayBeEmpty`.
  - Operators are applied only to entity types the metadata has, and the `metadata` of the superior's subordinate statement only to entity types of the subject's entity configuration (Section 3.1.1). Before, `add`, `default` and `value` and the superior's `metadata` created an entity type the subject does not have.
  - `scope` is processed as a string array and written back as a space-separated string, so `subset_of`, `superset_of`, `add` and `default` work on it. Before, `subset_of` and `superset_of` rejected the chain.
  - `value` may be combined with `add`, `default`, `one_of`, `subset_of` and `superset_of`. The conditions of Section 6.1.3.1 on combinations are checked for each policy and for the merged policy, for example that the values of `add` are a subset of `subset_of`. A `value` of `null` counts as no values. Additional operators that are not understood no longer count as a disallowed combination.

  `resolveTrustChains` also checks the claims of each statement against its kind (Section 3.2): entity configurations with `metadata_policy`, `metadata_policy_crit`, `constraints` or `source_endpoint`, or with an empty `authority_hints` array, and subordinate statements with `authority_hints`, `trust_marks`, `trust_mark_issuers` or `trust_mark_owners` are rejected. As no additional policy operators are supported, a subordinate statement with `metadata_policy_crit` is rejected (Section 3.1.3). Before, an operator listed there was ignored unless the same statement used it.

- f76671c: Validate trust chains as described in Section 10 of OpenID Federation 1.0.

  `resolveTrustChains` now:

  - uses `fetchCallback` for every request, so callers can apply their outbound request policy;
  - rejects an entity configuration whose `sub` is not the requested entity. Before, any URL in `authority_hints` could serve an entity configuration claiming to be a trust anchor, with its own keys and fetch endpoint, and the chain was accepted;
  - checks signatures as Section 10.2 requires: the leaf's entity configuration with a key of the subordinate statement about it, each subordinate statement with a key the next statement lists for its issuer, and the last one with the trust anchor's keys. Before, a subordinate statement was checked with the keys the intermediate published itself. Each subordinate statement must have the requested `iss` and `sub`;
  - checks `iat` and `exp` of every statement, including the leaf and intermediate entity configurations (`currentDate`, `clockSkewSeconds`);
  - rejects statements with `crit` claims that are not in `understoodCriticalClaims`;
  - applies the `max_path_length` and `allowed_entity_types` constraints (entity types are removed before the metadata policies are applied, and a policy can not add them back);
  - compares entity identifiers exactly (Section 16);
  - takes the trust anchors as `trustAnchors`, each with optional pinned `jwks` (out-of-band trust anchor keys); `trustAnchorEntityIds` is removed. Only with `jwks` is the trust anchor's entity configuration checked against keys of the trust anchor as Section 10.2 requires; without them it is trusted on its own signature, as before;
  - bounds the resolution with `maxDepth` (default 8), `maxRequests` (default 64, also the number of entity visits) and `maxAuthorityHints` (default 10, duplicates ignored), so repeated or converging `authority_hints` can not cause exponential work;
  - rejects chains with `naming_constraints`, which are not evaluated yet, and statements whose `iat` or `exp` is not a valid date;
  - returns `jwtChain` (the trust chain as compact JWTs, leaf first) and `expiresAt` (earliest `exp` of the chain) for each chain.

  `resolveTrustChainsWithFailures` also returns why each failed path was rejected (#12). A leaf whose entity configuration can not be used is now reported as a failure instead of rejecting the promise.

  Other fixes:

  - `fetchEntityConfiguration` checks that `sub` is the requested entity, `fetchEntityStatement` that `iss` and `sub` are the requested ones.
  - `fetchEntityConfigurationChains` and `fetchEntityStatementChain` are removed: they checked subordinate statements against the keys an intermediate published itself, not as Section 10.2 requires. Use `resolveTrustChains`. `EntityStatementChain` is still exported.
  - Fetch endpoint requests send only `sub` (Section 8.1.1), not `iss`.
  - Requests reject non-2xx responses, compare the content-type without parameters such as `charset` (#17), and no longer append an empty `?` to URLs.
  - `OpenIdFederationError` and `PolicyErrorStage` are exported.

- 8a4846f: Read and write entity statements of OpenID Federation 1.0 final only; support for earlier drafts is removed.

  - Trust marks use `trust_mark_type` (Sections 3.1.2 and 7.1). The draft `id` is no longer read: a trust mark without `trust_mark_type` is rejected. The `trust_mark_type` of a `trust_marks` entry must be the one of its trust mark JWT.
  - `iat`, `exp` and the other date claims must be NumericDate values (seconds since the epoch, RFC 7519) when statements are parsed and created. ISO strings and `Date` objects are rejected; parsed claims still return `Date` objects (#23).
  - Decoded JWTs, such as `trust_marks[].trust_mark`, keep the compact JWT in `jwt`, so a trust mark can be verified.
  - Metadata keeps parameters and entity types the schemas do not define. Before, for example, `token_endpoint` of `oauth_authorization_server` and every unknown entity type were dropped, also from `resolvedLeafMetadata`.
  - `client_registration_types` and `client_registration_types_supported` are optional for all entity types (RECOMMENDED in Sections 5.1.2 and 5.1.3) and accept values other than `automatic` and `explicit`.

## 0.2.1

### Patch Changes

- fab3ff1: fix: Align x5c schema type with RFC 7517 specification

## 0.2.0

### Minor Changes

- 2e2d609: feat: add support for policies

### Patch Changes

- 17ff76b: chore: prepare for release at openwallet foundation
