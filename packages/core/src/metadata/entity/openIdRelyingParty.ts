import { z } from 'zod'
import { createEntity } from './utils'

/**
 *
 * {@link https://openid.net/specs/openid-federation-1_0.html#section-5.1.2-1 | openID Relying Party }
 *
 */
export const openidRelyingPartyEntityMetadata = createEntity({
  identifier: 'openid_relying_party',
  passThroughUnknownProperties: true,
  additionalValidation: {
    client_registration_types: z.array(z.string()).optional(),
  },
})

export type OpenIdRelyingPartyMetadata = z.input<(typeof openidRelyingPartyEntityMetadata)['schema']>
