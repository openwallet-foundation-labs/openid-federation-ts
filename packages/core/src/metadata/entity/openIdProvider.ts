import { z } from 'zod'
import { createEntity } from './utils'

/**
 *
 * {@link https://openid.net/specs/openid-federation-1_0.html#section-5.1.3-1 | openID Provider}
 *
 */
export const openIdProviderEntityMetadata = createEntity({
  identifier: 'openid_provider',
  passThroughUnknownProperties: true,
  additionalValidation: {
    client_registration_types_supported: z.array(z.string()).optional(),
    federation_registration_endpoint: z.string().url().optional(),
    request_authentication_methods_supported: z
      .object({
        authorization_endpoint: z.array(z.string()).optional(),
        pushed_authorization_request_endpoint: z.array(z.string()).optional(),
      })
      .optional(),
    request_authentication_signing_alg_values_supported: z.array(z.string()).optional(),
  },
})

export type OpenIdProviderMetadata = z.input<(typeof openIdProviderEntityMetadata)['schema']>
