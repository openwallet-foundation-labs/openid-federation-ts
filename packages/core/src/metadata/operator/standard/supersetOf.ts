import { z } from 'zod'
import { MetadataMergeStrategy } from '../MetadataMergeStrategy'
import { MetadataOrderOfApplication } from '../MetadataOrderOfApplication'
import { createPolicyOperatorSchema } from '../utils'

export const supersetOfOperator = createPolicyOperatorSchema({
  key: 'superset_of',
  parameterJsonValues: [
    z.array(z.string()),
    // TODO: See how we want to we handle the comparison of objects
    // z.array(z.record(z.string().or(z.number()), z.unknown())),
    z.array(z.number()),
  ],
  operatorJsonValues: [
    z.array(z.string()),
    // TODO: See how we want to we handle the comparison of objects
    // z.array(z.record(z.string().or(z.number()), z.unknown())),
    z.array(z.number()),
  ],
  canBeCombinedWith: ['value', 'add', 'default', 'subset_of', 'essential'],
  orderOfApplication: MetadataOrderOfApplication.AfterSubsetOf,
  mergeStrategy: MetadataMergeStrategy.Union,
})
