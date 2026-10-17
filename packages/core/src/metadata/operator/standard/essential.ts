import { z } from 'zod'
import { MetadataMergeStrategy } from '../MetadataMergeStrategy'
import { MetadataOrderOfApplication } from '../MetadataOrderOfApplication'
import { createPolicyOperatorSchema } from '../utils'

export const essentialOperator = createPolicyOperatorSchema({
  key: 'essential',
  parameterJsonValues: [
    z.string(),
    z.number(),
    z.boolean(),
    z.record(z.string().or(z.number())),
    z.unknown(),
    z.array(z.unknown()),
  ],
  operatorJsonValues: [z.boolean()],
  canBeCombinedWith: ['add', 'default', 'one_of', 'subset_of', 'superset_of', 'value'],
  orderOfApplication: MetadataOrderOfApplication.Last,
  mergeStrategy: MetadataMergeStrategy.LogicalOr,
})
