---
"@openid-federation/core": minor
---

Apply metadata policies as described in Section 6.1 of OpenID Federation 1.0.

- `subset_of`, `superset_of` and `one_of` have no effect when the metadata parameter is absent. Before, `subset_of` and `superset_of` rejected the chain.
- `superset_of` checks that the metadata parameter contains every operator value. Before, the check was reversed, so `superset_of: ["a"]` rejected `["a", "b"]` and accepted `[]`.
- `subset_of` may leave an empty array, which stays the value of the metadata parameter, also when `essential` is `true` (Table 1). Before, the parameter was removed, and `essential` rejected an empty array. Merging two `subset_of` without common values results in `[]` instead of a policy error; `one_of` still requires common values.
- `essential` values are merged with a logical OR. Before, the superior's value was kept, so a subordinate could not make a parameter essential. `MetadataMergeStrategy.SuperiorFollowsIfTrue` is deprecated in favour of `LogicalOr`; `subset_of` uses the new `IntersectionMayBeEmpty`.
- Operators are applied only to entity types the metadata has, and the `metadata` of the superior's subordinate statement only to entity types of the subject's entity configuration (Section 3.1.1). Before, `add`, `default` and `value` and the superior's `metadata` created an entity type the subject does not have.
- `scope` is processed as a string array and written back as a space-separated string, so `subset_of`, `superset_of`, `add` and `default` work on it. Before, `subset_of` and `superset_of` rejected the chain.
- `value` may be combined with `add`, `default`, `one_of`, `subset_of` and `superset_of`. The conditions of Section 6.1.3.1 on combinations are checked for each policy and for the merged policy, for example that the values of `add` are a subset of `subset_of`. A `value` of `null` counts as no values. Additional operators that are not understood no longer count as a disallowed combination.

`resolveTrustChains` also checks the claims of each statement against its kind (Section 3.2): entity configurations with `metadata_policy`, `metadata_policy_crit`, `constraints` or `source_endpoint`, or with an empty `authority_hints` array, and subordinate statements with `authority_hints`, `trust_marks`, `trust_mark_issuers` or `trust_mark_owners` are rejected. As no additional policy operators are supported, a subordinate statement with `metadata_policy_crit` is rejected (Section 3.1.3). Before, an operator listed there was ignored unless the same statement used it.
