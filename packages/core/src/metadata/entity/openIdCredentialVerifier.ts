import { z } from 'zod'
import { createEntity } from './utils'

/**
 *
 * {@link https://openid.github.io/federation-wallet/main.html#name-wallet-architecture-entity- | OpenID Credential Verifier }
 *
 */
export const openidCredentialVerifierEntityMetadata = createEntity({
  identifier: 'openid_credential_verifier',
  passThroughUnknownProperties: true,
  additionalValidation: {
    client_registration_types: z.array(z.string()).optional(),
  },
})

export type OpenIdCredentialVerifierMetadata = z.input<(typeof openidCredentialVerifierEntityMetadata)['schema']>
