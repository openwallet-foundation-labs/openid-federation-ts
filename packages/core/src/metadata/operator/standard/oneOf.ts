import { z } from 'zod'
import { MetadataMergeStrategy } from '../MetadataMergeStrategy'
import { MetadataOrderOfApplication } from '../MetadataOrderOfApplication'
import { createPolicyOperatorSchema } from '../utils'

export const oneOfOperator = createPolicyOperatorSchema({
  key: 'one_of',
  parameterJsonValues: [
    z.string(),
    // TODO: See how we want to we handle the comparison of objects
    // z.record(z.string().or(z.number()), z.unknown()),
    z.number(),
  ],
  operatorJsonValues: [
    z.array(z.string()),
    // TODO: See how we want to we handle the comparison of objects
    // z.array(z.record(z.string().or(z.number()), z.unknown())),
    z.array(z.number()),
  ],
  canBeCombinedWith: ['value', 'default', 'essential'],
  orderOfApplication: MetadataOrderOfApplication.AfterDefault,
  mergeStrategy: MetadataMergeStrategy.Intersection,
})
