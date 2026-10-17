---
"@openid-federation/core": minor
---

Validate trust chains as described in Section 10 of OpenID Federation 1.0.

`resolveTrustChains` now:

- uses `fetchCallback` for every request, so callers can apply their outbound request policy;
- rejects an entity configuration whose `sub` is not the requested entity. Before, any URL in `authority_hints` could serve an entity configuration claiming to be a trust anchor, with its own keys and fetch endpoint, and the chain was accepted;
- checks signatures as Section 10.2 requires: the leaf's entity configuration with a key of the subordinate statement about it, each subordinate statement with a key the next statement lists for its issuer, and the last one with the trust anchor's keys. Before, a subordinate statement was checked with the keys the intermediate published itself. Each subordinate statement must have the requested `iss` and `sub`;
- checks `iat` and `exp` of every statement, including the leaf and intermediate entity configurations (`currentDate`, `clockSkewSeconds`);
- rejects statements with `crit` claims that are not in `understoodCriticalClaims`;
- applies the `max_path_length` and `allowed_entity_types` constraints (entity types are removed before the metadata policies are applied, and a policy can not add them back);
- compares entity identifiers exactly (Section 16);
- accepts `trustAnchors` with optional pinned `jwks` (out-of-band trust anchor keys); `trustAnchorEntityIds` is deprecated. Only with `jwks` is the trust anchor's entity configuration checked against keys of the trust anchor as Section 10.2 requires; without them it is trusted on its own signature, as before;
- bounds the resolution with `maxDepth` (default 8), `maxRequests` (default 64, also the number of entity visits) and `maxAuthorityHints` (default 10, duplicates ignored), so repeated or converging `authority_hints` can not cause exponential work;
- rejects chains with `naming_constraints`, which are not evaluated yet, and statements whose `iat` or `exp` is not a valid date;
- returns `jwtChain` (the trust chain as compact JWTs, leaf first) and `expiresAt` (earliest `exp` of the chain) for each chain.

`resolveTrustChainsWithFailures` also returns why each failed path was rejected (#12). A leaf whose entity configuration can not be used is now reported as a failure instead of rejecting the promise.

Other fixes:

- `fetchEntityConfiguration` checks that `sub` is the requested entity, `fetchEntityStatement` that `iss` and `sub` are the requested ones.
- `fetchEntityStatementChain` accepts `fetchCallback`.
- Fetch endpoint requests send only `sub` (Section 8.1.1), not `iss`.
- Requests reject non-2xx responses, compare the content-type without parameters such as `charset` (#17), and no longer append an empty `?` to URLs.
- `OpenIdFederationError` and `PolicyErrorStage` are exported.
