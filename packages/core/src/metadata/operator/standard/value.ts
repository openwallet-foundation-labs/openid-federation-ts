import { z } from 'zod'
import { MetadataMergeStrategy } from '../MetadataMergeStrategy'
import { MetadataOrderOfApplication } from '../MetadataOrderOfApplication'
import { createPolicyOperatorSchema } from '../utils'

export const valueOperator = createPolicyOperatorSchema({
  key: 'value',
  parameterJsonValues: [
    z.string(),
    z.number(),
    z.boolean(),
    z.record(z.string().or(z.number()), z.unknown()),
    z.array(z.unknown()),
  ],
  operatorJsonValues: [
    z.string(),
    z.number(),
    z.boolean(),
    z.record(z.string().or(z.number()), z.unknown()),
    z.array(z.unknown()),
    z.null(),
  ],
  canBeCombinedWith: ['add', 'default', 'one_of', 'subset_of', 'superset_of', 'essential'],
  orderOfApplication: MetadataOrderOfApplication.First,
  mergeStrategy: MetadataMergeStrategy.OperatorValuesEqual,
})
