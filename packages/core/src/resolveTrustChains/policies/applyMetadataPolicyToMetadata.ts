import { immutable, isNullOrUndefined, objectToEntries } from '../../utils/data'

import {
  type Metadata,
  type MetadataPolicyOperator,
  type SupportedPolicyKey,
  allSupportedPolicies,
  isExistingPolicyKey,
} from '../../metadata'
import { MetadataHelper } from './MetadataHelper'
import { PolicyValidationError } from './errors/PolicyValidationError'
import { type PolicyValue, union } from './utils'

export function applyMetadataPolicyToMetadata({
  leafMetadata,
  policyMetadata,
}: { leafMetadata: Metadata; policyMetadata: Record<string, Record<string, MetadataPolicyOperator>> }) {
  const resolvedLeafMetadata = new MetadataHelper(immutable(leafMetadata))

  for (const [serviceKey, service] of objectToEntries(policyMetadata)) {
    // Section 6.1.4.2: policies apply to the entity types the metadata has, operators do not add an entity type
    if (!resolvedLeafMetadata.hasEntityType(serviceKey)) continue

    for (const [servicePropertyKey, policyValue] of objectToEntries(service)) {
      const policies = objectToEntries(policyValue)
        .filter(([key]) => isExistingPolicyKey(key))
        .sort(
          ([policyKeyA], [policyKeyB]) =>
            allSupportedPolicies[policyKeyA as SupportedPolicyKey].orderOfApplication -
            allSupportedPolicies[policyKeyB as SupportedPolicyKey].orderOfApplication
        )

      const path = `${serviceKey}.${servicePropertyKey}`

      // Section 6.1.3.1.8: scope, a string of space-separated values, is processed as a string array
      const isScope = servicePropertyKey === 'scope'
      const scope = resolvedLeafMetadata.getPropertyValue(serviceKey, servicePropertyKey)
      if (isScope && typeof scope === 'string') {
        resolvedLeafMetadata.setPropertyValue(serviceKey, servicePropertyKey, splitScope(scope))
      }

      for (const [policyPropertyKey, rawValueFromPolicy] of policies) {
        const valueFromPolicy =
          isScope && typeof rawValueFromPolicy === 'string' ? splitScope(rawValueFromPolicy) : rawValueFromPolicy

        switch (policyPropertyKey) {
          case 'value':
            if (valueFromPolicy === null) {
              // When the policy value is null, we delete the property
              resolvedLeafMetadata.deleteProperty(serviceKey, servicePropertyKey)
              break
            }

            resolvedLeafMetadata.setPropertyValue(serviceKey, servicePropertyKey, valueFromPolicy)
            break
          case 'add': {
            const targetValue = resolvedLeafMetadata.getPropertyValue<PolicyValue>(serviceKey, servicePropertyKey) ?? []
            if (!Array.isArray(targetValue))
              throw new PolicyValidationError('Cannot apply add policy because the target is not an array', {
                path,
                policyValue: valueFromPolicy,
                targetValue,
              })

            const newValue = union(targetValue, valueFromPolicy)
            resolvedLeafMetadata.setPropertyValue(serviceKey, servicePropertyKey, newValue)
            break
          }
          case 'one_of': {
            const targetValue = resolvedLeafMetadata.getPropertyValue<PolicyValue>(serviceKey, servicePropertyKey)
            // With one_of it's allowed to not have a value and can be enforced with essential
            if (isNullOrUndefined(targetValue)) break

            if (!Array.isArray(valueFromPolicy))
              throw new PolicyValidationError('Cannot apply one_of policy because the value is not an array', {
                path,
                policyValue: valueFromPolicy,
                targetValue,
              })

            if (!valueFromPolicy.some((value) => value === targetValue))
              throw new PolicyValidationError('Cannot apply one_of policy because the intersection is empty', {
                path,
                policyValue: valueFromPolicy,
                targetValue,
              })
            break
          }
          case 'default':
            if (resolvedLeafMetadata.hasProperty(serviceKey, servicePropertyKey)) continue

            resolvedLeafMetadata.setPropertyValue(serviceKey, servicePropertyKey, valueFromPolicy)
            break
          case 'subset_of': {
            const targetValue = resolvedLeafMetadata.getPropertyValue<PolicyValue>(serviceKey, servicePropertyKey)
            // Only applies when the metadata parameter is present, essential enforces its presence
            if (isNullOrUndefined(targetValue)) break
            if (!Array.isArray(targetValue))
              throw new PolicyValidationError('Cannot apply subset_of policy because the target is not an array', {
                path,
                policyValue: valueFromPolicy,
                targetValue,
              })
            if (!Array.isArray(valueFromPolicy))
              throw new PolicyValidationError('Cannot apply subset_of policy because the value is not an array', {
                path,
                policyValue: valueFromPolicy,
                targetValue,
              })

            // The intersection may be an empty array, which stays the value of the metadata parameter
            const newValue = targetValue.filter((value) => valueFromPolicy.includes(value))
            resolvedLeafMetadata.setPropertyValue(serviceKey, servicePropertyKey, newValue)
            break
          }
          case 'superset_of': {
            const targetValue = resolvedLeafMetadata.getPropertyValue<PolicyValue>(serviceKey, servicePropertyKey)
            // Only applies when the metadata parameter is present, essential enforces its presence
            if (isNullOrUndefined(targetValue)) break
            if (!Array.isArray(targetValue))
              throw new PolicyValidationError('Cannot apply superset_of policy because the target is not an array', {
                path,
                policyValue: valueFromPolicy,
                targetValue,
              })
            if (!Array.isArray(valueFromPolicy))
              throw new PolicyValidationError('Cannot apply superset_of policy because the value is not an array', {
                path,
                policyValue: valueFromPolicy,
                targetValue,
              })

            if (!valueFromPolicy.every((value) => targetValue.includes(value)))
              throw new PolicyValidationError('The target does not contain all the values from the policy superset', {
                path,
                policyValue: valueFromPolicy,
                targetValue,
              })
            break
          }
          case 'essential': {
            if (!valueFromPolicy) break

            const targetValue = resolvedLeafMetadata.getPropertyValue<PolicyValue>(serviceKey, servicePropertyKey)
            if (isNullOrUndefined(targetValue))
              throw new PolicyValidationError('The policy is required to have a value', {
                path,
                policyValue: valueFromPolicy,
                targetValue,
              })
            // An empty array, for example after subset_of, is present (Section 6.1.3.1.8, Table 1)
            break
          }
        }
      }

      const resolvedScope = resolvedLeafMetadata.getPropertyValue(serviceKey, servicePropertyKey)
      if (isScope && Array.isArray(resolvedScope)) {
        resolvedLeafMetadata.setPropertyValue(serviceKey, servicePropertyKey, resolvedScope.join(' '))
      }
    }
  }

  return {
    resolvedLeafMetadata: resolvedLeafMetadata.asMetadata(),
  }
}

const splitScope = (scope: string) => scope.split(' ').filter((value) => value !== '')
