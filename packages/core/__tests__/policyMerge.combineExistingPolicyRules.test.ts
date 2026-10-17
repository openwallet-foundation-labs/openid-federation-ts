import assert from 'node:assert/strict'
import { describe, it } from 'node:test'
import { combineExistingMetadataPolicyOperators } from '../src/resolveTrustChains/policies/combineExistingMetadataPolicyOperators'

describe('policy merge', () => {
  // add

  it('it should combine the add policy rules', () => {
    const superiorPolicyRule = {
      add: ['one', 'two'],
    } as const

    const policyRule = {
      add: ['three'],
    } as const

    const combinedPolicyRules = combineExistingMetadataPolicyOperators({
      contextPath: 'openid_relying_party.contacts',
      existingPolicyRules: superiorPolicyRule,
      newPolicyRules: policyRule,
    })

    assert.deepStrictEqual(combinedPolicyRules, {
      add: ['one', 'two', 'three'],
    })
  })

  // essential

  it('it should still be true with essential from superior true', () => {
    const superiorPolicyRule = {
      essential: true,
    } as const

    const policyRule = {
      essential: false,
    } as const

    const combinedPolicyRules = combineExistingMetadataPolicyOperators({
      contextPath: 'openid_relying_party.contacts',
      existingPolicyRules: superiorPolicyRule,
      newPolicyRules: policyRule,
    })

    assert.deepStrictEqual(combinedPolicyRules, {
      essential: true,
    })
  })

  // subset_of

  it('it should combine the subset_of policy rules', () => {
    const superiorPolicyRule = {
      subset_of: ['one', 'two'],
    } as const

    const policyRule = {
      subset_of: ['two', 'three'],
    } as const

    const combinedPolicyRules = combineExistingMetadataPolicyOperators({
      contextPath: 'openid_relying_party.contacts',
      existingPolicyRules: superiorPolicyRule,
      newPolicyRules: policyRule,
    })

    assert.deepStrictEqual(combinedPolicyRules, {
      subset_of: ['two'],
    })
  })

  // Section 6.1.3.1.5 subset_of: "Note that the resulting intersection may thus be an empty array []."
  it('it should combine subset_of policy rules without common values to an empty array', () => {
    const superiorPolicyRule = {
      subset_of: ['one', 'two'],
    } as const

    const policyRule = {
      subset_of: ['three'],
    } as const

    const combinedPolicyRules = combineExistingMetadataPolicyOperators({
      contextPath: 'openid_relying_party.contacts',
      existingPolicyRules: superiorPolicyRule,
      newPolicyRules: policyRule,
    })

    assert.deepStrictEqual(combinedPolicyRules, {
      subset_of: [],
    })
  })

  // superset_of

  it('it should combine the superset_of policy rules', () => {
    const superiorPolicyRule = {
      superset_of: ['one', 'two'],
    } as const

    const policyRule = {
      superset_of: ['two', 'three'],
    } as const

    const combinedPolicyRules = combineExistingMetadataPolicyOperators({
      contextPath: 'openid_relying_party.contacts',
      existingPolicyRules: superiorPolicyRule,
      newPolicyRules: policyRule,
    })

    assert.deepStrictEqual(combinedPolicyRules, {
      superset_of: ['one', 'two', 'three'],
    })
  })

  // default

  it('it should fail the default policy rules', () => {
    const superiorPolicyRule = {
      default: 'one',
    } as const

    const policyRule = {
      default: 'two',
    } as const

    assert.throws(() =>
      combineExistingMetadataPolicyOperators({
        contextPath: 'openid_relying_party.contacts',
        existingPolicyRules: superiorPolicyRule,
        newPolicyRules: policyRule,
      })
    )
  })

  it('it should combine the default policy rules', () => {
    const superiorPolicyRule = {
      default: 'one',
    } as const

    const policyRule = {
      default: 'one',
    } as const

    const combinedPolicyRules = combineExistingMetadataPolicyOperators({
      contextPath: 'openid_relying_party.contacts',
      existingPolicyRules: superiorPolicyRule,
      newPolicyRules: policyRule,
    })

    assert.deepStrictEqual(combinedPolicyRules, {
      default: 'one',
    })
  })

  // value

  it('it should fail the value policy rules', () => {
    const superiorPolicyRule = {
      value: 'one',
    } as const

    const policyRule = {
      value: 'two',
    } as const

    assert.throws(() =>
      combineExistingMetadataPolicyOperators({
        contextPath: 'openid_relying_party.contacts',
        existingPolicyRules: superiorPolicyRule,
        newPolicyRules: policyRule,
      })
    )
  })

  it('it should combine the value policy rules', () => {
    const superiorPolicyRule = {
      value: 'one',
    } as const

    const policyRule = {
      value: 'one',
    } as const

    const combinedPolicyRules = combineExistingMetadataPolicyOperators({
      contextPath: 'openid_relying_party.contacts',
      existingPolicyRules: superiorPolicyRule,
      newPolicyRules: policyRule,
    })

    assert.deepStrictEqual(combinedPolicyRules, {
      value: 'one',
    })
  })

  // one_of

  it('it should combine the one_of policy rules', () => {
    const superiorPolicyRule = {
      one_of: ['one', 'two'],
    } as const

    const policyRule = {
      one_of: ['two', 'three'],
    } as const

    const combinedPolicyRules = combineExistingMetadataPolicyOperators({
      contextPath: 'openid_relying_party.contacts',
      existingPolicyRules: superiorPolicyRule,
      newPolicyRules: policyRule,
    })

    assert.deepStrictEqual(combinedPolicyRules, {
      one_of: ['two'],
    })
  })

  // all supported policies (without the logic of that they can be together only the merge)

  it('it should combine all supported policies', () => {
    const superiorPolicyRule = {
      add: ['one', 'two'],
      default: 'one',
      essential: true,
      one_of: ['one', 'two'],
      subset_of: ['one', 'two'],
      superset_of: ['one', 'two'],
      value: 'one',
    } as const

    const policyRule = {
      add: ['three'],
      default: 'one',
      essential: false,
      one_of: ['one', 'two', 'three', 'four'],
      subset_of: ['one', 'two', 'three', 'four'],
      superset_of: ['one', 'two', 'three', 'four'],
      value: 'one',
    } as const

    const combinedPolicyRules = combineExistingMetadataPolicyOperators({
      contextPath: 'openid_relying_party.contacts',
      existingPolicyRules: superiorPolicyRule,
      newPolicyRules: policyRule,
    })

    assert.deepStrictEqual(combinedPolicyRules, {
      add: ['one', 'two', 'three'],
      default: 'one',
      essential: true,
      one_of: ['one', 'two'],
      subset_of: ['one', 'two'],
      superset_of: ['one', 'two', 'three', 'four'],
      value: 'one',
    })
  })
})
