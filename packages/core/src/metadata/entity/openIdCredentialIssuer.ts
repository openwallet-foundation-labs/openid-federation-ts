import { z } from 'zod'
import { createEntity } from './utils'

/**
 *
 * {@link https://openid.github.io/federation-wallet/main.html#name-wallet-architecture-entity- | OpenID Credential Issuer}
 *
 */
export const openIdCredentialIssuerEntityMetadata = createEntity({
  identifier: 'openid_credential_issuer',
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

export type OpenIdCredentialIssuerMetadata = z.input<(typeof openIdCredentialIssuerEntityMetadata)['schema']>
