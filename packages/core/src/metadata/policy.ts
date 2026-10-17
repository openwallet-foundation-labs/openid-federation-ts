import { z } from 'zod'
import {
  addOperator,
  defaultOperator,
  essentialOperator,
  oneOfOperator,
  subsetOfOperator,
  supersetOfOperator,
  valueOperator,
} from './operator'

export const allSupportedPolicies = {
  [addOperator.key]: addOperator,
  [defaultOperator.key]: defaultOperator,
  [essentialOperator.key]: essentialOperator,
  [oneOfOperator.key]: oneOfOperator,
  [subsetOfOperator.key]: subsetOfOperator,
  [supersetOfOperator.key]: supersetOfOperator,
  [valueOperator.key]: valueOperator,
} as const

export type SupportedPolicyKey = keyof typeof allSupportedPolicies

export const isExistingPolicyKey = (key: string): key is SupportedPolicyKey => key in allSupportedPolicies

const isSubset = (values: unknown, of: unknown) =>
  Array.isArray(values) && Array.isArray(of) && values.every((value) => of.includes(value))

/**
 * The conditions that Section 6.1.3.1 sets on combinations of the standard operators.
 */
const conditionalCombinationErrors = (policy: Record<string, unknown>): Array<string> => {
  const errors: Array<string> = []
  const has = (key: SupportedPolicyKey) => policy[key] !== undefined
  const { value, add, one_of, subset_of, superset_of, essential } = policy

  if (has('value')) {
    // A null value removes the metadata parameter, so it has no values for add, subset_of and superset_of
    const values = value === null ? [] : value
    if (value === null && has('default')) errors.push("'value' null can not be combined with 'default'")
    if (value === null && essential === true) errors.push("'value' null can not be combined with 'essential' true")
    if (has('add') && !isSubset(add, values))
      errors.push("the values of 'add' must be a subset of the values of 'value'")
    if (has('one_of') && !(Array.isArray(one_of) && value !== null && one_of.includes(value)))
      errors.push("the value of 'value' must be among the 'one_of' values")
    if (has('subset_of') && !isSubset(values, subset_of))
      errors.push("the values of 'value' must be a subset of the values of 'subset_of'")
    if (has('superset_of') && !isSubset(superset_of, values))
      errors.push("the values of 'value' must be a superset of the values of 'superset_of'")
  }
  if (has('add') && has('subset_of') && !isSubset(add, subset_of))
    errors.push("the values of 'add' must be a subset of the values of 'subset_of'")
  if (has('subset_of') && has('superset_of') && !isSubset(superset_of, subset_of))
    errors.push("the values of 'subset_of' must be a superset of the values of 'superset_of'")

  return errors
}

export const metadataPolicySchema = z
  .object(
    Object.entries(allSupportedPolicies).reduce(
      // biome-ignore lint/performance/noAccumulatingSpread: In this case we want to use the spread operator
      (acc, [key, policy]) => ({ ...acc, [key]: policy.operatorSchema }),
      {} as {
        [key in keyof typeof allSupportedPolicies]: (typeof allSupportedPolicies)[key]['operatorSchema']
      }
    )
  )
  .and(z.record(z.string(), z.any()))
  .superRefine((data, ctx) => {
    const dataKeys = Object.keys(data)

    for (const dataKey of dataKeys) {
      if (!isExistingPolicyKey(dataKey)) continue
      const { operator } = allSupportedPolicies[dataKey]

      // Additional operators that are not understood are ignored (Section 6.1.3.2), so they do not restrict combinations
      if (
        dataKeys.some(
          (key) => key !== operator.key && isExistingPolicyKey(key) && !operator.canBeCombinedWith.includes(key)
        )
      ) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: `policy operator '${
            operator.key
          }' can only be combined with one of: [${operator.canBeCombinedWith.join(
            ', '
          )}]. keys: [${Object.keys(data).join(',')}]`,
        })
      }
    }

    for (const message of conditionalCombinationErrors(data)) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, message })
    }

    return data
  })

export type MetadataPolicyOperator = z.input<typeof metadataPolicySchema>
