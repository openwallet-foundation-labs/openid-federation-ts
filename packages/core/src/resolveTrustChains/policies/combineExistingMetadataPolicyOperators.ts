import { type MetadataPolicyOperator, allSupportedPolicies, isExistingPolicyKey } from '../../metadata'
import { MetadataMergeStrategy } from '../../metadata/operator/MetadataMergeStrategy'
import { objectToEntries } from '../../utils/data'
import { PolicyOperatorMergeError } from './errors'
import { intersect, union } from './utils'

// TODO: Add support for objects (they are optional in the spec)

export function combineExistingMetadataPolicyOperators({
  contextPath,
  existingPolicyRules,
  newPolicyRules,
}: {
  contextPath: string
  existingPolicyRules: MetadataPolicyOperator
  newPolicyRules: MetadataPolicyOperator
}) {
  const combinedPolicyRules = { ...existingPolicyRules }

  for (const [policyPropertyKey, policyRuleValue] of objectToEntries(newPolicyRules)) {
    // When we don't know the policy key we can skip it because we already know it's not critical
    if (!isExistingPolicyKey(policyPropertyKey)) continue

    if (combinedPolicyRules[policyPropertyKey] === undefined) {
      combinedPolicyRules[policyPropertyKey] = policyRuleValue
      continue
    }

    const existingPolicyRuleValue = combinedPolicyRules[policyPropertyKey]
    const operator = allSupportedPolicies[policyPropertyKey]

    // Check if the new policy rule value is correctly used
    const operatorInputResult = operator.operatorSchema.safeParse(policyRuleValue)
    if (!operatorInputResult.success) throw operatorInputResult.error
    const newPolicyRuleValue = operatorInputResult.data

    switch (operator.mergeStrategy) {
      case MetadataMergeStrategy.OperatorValuesEqual:
        if (Array.isArray(existingPolicyRuleValue) && Array.isArray(newPolicyRuleValue)) {
          if (existingPolicyRuleValue.length !== newPolicyRuleValue.length)
            throw new PolicyOperatorMergeError('Policy rule values are not equal', {
              path: contextPath,
              operatorA: existingPolicyRules,
              operatorB: newPolicyRules,
            })

          if (existingPolicyRuleValue.some((value, i) => value !== newPolicyRuleValue[i]))
            throw new PolicyOperatorMergeError('Policy rule values are not equal', {
              path: contextPath,
              operatorA: existingPolicyRules,
              operatorB: newPolicyRules,
            })
        } else if (existingPolicyRuleValue !== newPolicyRuleValue) {
          throw new PolicyOperatorMergeError('Policy rule values are not equal', {
            path: contextPath,
            operatorA: existingPolicyRules,
            operatorB: newPolicyRules,
          })
        }

        // Don't have to do anything because it is already there by the existing policy rule
        break
      case MetadataMergeStrategy.Union:
        if (!Array.isArray(existingPolicyRuleValue) || !Array.isArray(newPolicyRuleValue)) {
          throw new PolicyOperatorMergeError('Operator values are not an array', {
            path: contextPath,
            operatorA: existingPolicyRules,
            operatorB: newPolicyRules,
          })
        }

        combinedPolicyRules[policyPropertyKey] = union(existingPolicyRuleValue, newPolicyRuleValue)
        break
      case MetadataMergeStrategy.Intersection:
      case MetadataMergeStrategy.IntersectionMayBeEmpty: {
        if (!Array.isArray(existingPolicyRuleValue) || !Array.isArray(newPolicyRuleValue)) {
          throw new PolicyOperatorMergeError('Existing policy rule value is not an array', {
            path: contextPath,
            operatorA: existingPolicyRules,
            operatorB: newPolicyRules,
          })
        }
        const intersection = intersect(existingPolicyRuleValue, newPolicyRuleValue)
        if (intersection.length === 0 && operator.mergeStrategy === MetadataMergeStrategy.Intersection) {
          throw new PolicyOperatorMergeError('Intersection is empty', {
            path: contextPath,
            operatorA: existingPolicyRules,
            operatorB: newPolicyRules,
          })
        }

        combinedPolicyRules[policyPropertyKey] = intersection

        break
      }
      case MetadataMergeStrategy.LogicalOr:
        if (typeof existingPolicyRuleValue !== 'boolean' || typeof newPolicyRuleValue !== 'boolean') {
          throw new PolicyOperatorMergeError('Existing policy rule value is not a boolean', {
            path: contextPath,
            operatorA: existingPolicyRules,
            operatorB: newPolicyRules,
          })
        }
        combinedPolicyRules[policyPropertyKey] = existingPolicyRuleValue || newPolicyRuleValue
        break

      default:
        throw new PolicyOperatorMergeError(`Unknown merge strategy: ${operator.mergeStrategy}`, {
          path: contextPath,
          operatorA: existingPolicyRules,
          operatorB: newPolicyRules,
        })
    }
  }

  return combinedPolicyRules
}
