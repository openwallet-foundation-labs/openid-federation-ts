import { z } from 'zod'
import { MetadataMergeStrategy } from '../MetadataMergeStrategy'
import { MetadataOrderOfApplication } from '../MetadataOrderOfApplication'
import { createPolicyOperatorSchema } from '../utils'

export const addOperator = createPolicyOperatorSchema({
  key: 'add',
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
  canBeCombinedWith: ['value', 'default', 'subset_of', 'superset_of', 'essential'],
  orderOfApplication: MetadataOrderOfApplication.AfterValue,
  mergeStrategy: MetadataMergeStrategy.Union,
})
