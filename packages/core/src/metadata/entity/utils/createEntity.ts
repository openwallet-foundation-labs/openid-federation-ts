import type { z } from 'zod'
import { commonMetadataSchema } from '../../common'
import { swapValidators } from '../../operator'
import { metadataPolicySchema } from '../../policy'

export const createEntity = <T extends string, S extends z.ZodRawShape>({
  identifier,
  additionalValidation = {} as S,
  passThroughUnknownProperties = true,
}: {
  identifier: T
  additionalValidation?: S
  /**
   * Keep metadata parameters the schema does not define, for example the protocol specific
   * parameters of `oauth_authorization_server`. Dropping them would remove them from the resolved metadata.
   *
   * @default true
   */
  passThroughUnknownProperties?: boolean
}) => {
  const schema = commonMetadataSchema.extend(additionalValidation)
  return {
    identifier,
    schema: passThroughUnknownProperties ? schema.passthrough() : schema,
    policySchema: swapValidators(schema, metadataPolicySchema.optional()),
  }
}
