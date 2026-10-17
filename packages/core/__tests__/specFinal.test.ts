import assert from 'node:assert/strict'
import { Buffer } from 'node:buffer'
import { describe, it } from 'node:test'
import { createEntityConfiguration, entityConfigurationClaimsSchema } from '../src/entityConfiguration'
import { metadataSchema } from '../src/metadata'
import { trustMarkSchema } from '../src/trustMark'
import type { SignCallback } from '../src/utils'
import { validate } from '../src/utils/validate'

const encode = (value: Record<string, unknown>) => Buffer.from(JSON.stringify(value)).toString('base64url')
const unsignedJwt = (header: Record<string, unknown>, claims: Record<string, unknown>) =>
  `${encode(header)}.${encode(claims)}.c2lnbmF0dXJl`

describe('OpenID Federation 1.0 final', () => {
  const signJwtCallback: SignCallback = () => Promise.resolve(new Uint8Array(8).fill(1))

  it('should read trust marks with trust_mark_type and keep the compact trust mark', () => {
    const trustMarkJwt = unsignedJwt(
      { typ: 'trust-mark+jwt', alg: 'ES256', kid: 'tm' },
      {
        iss: 'https://tm-issuer.example.org',
        sub: 'https://leaf.example.org',
        trust_mark_type: 'https://tm.example.org/certified',
        iat: 1700000000,
      }
    )

    const trustMark = validate({
      schema: trustMarkSchema,
      data: { trust_mark_type: 'https://tm.example.org/certified', trust_mark: trustMarkJwt },
    })

    assert.strictEqual(trustMark.trust_mark_type, 'https://tm.example.org/certified')
    assert.strictEqual(trustMark.trust_mark.claims.trust_mark_type, 'https://tm.example.org/certified')
    assert.strictEqual(trustMark.trust_mark.jwt, trustMarkJwt)
  })

  it('should map the draft id of a trust mark to trust_mark_type', () => {
    const trustMarkJwt = unsignedJwt(
      { typ: 'trust-mark+jwt', alg: 'ES256', kid: 'tm' },
      { iss: 'https://tm-issuer.example.org', sub: 'https://leaf.example.org', id: 'https://tm.example.org/a', iat: 1 }
    )

    const trustMark = validate({
      schema: trustMarkSchema,
      data: { id: 'https://tm.example.org/a', trust_mark: trustMarkJwt },
    })

    assert.strictEqual(trustMark.trust_mark_type, 'https://tm.example.org/a')
    assert.strictEqual(trustMark.trust_mark.claims.trust_mark_type, 'https://tm.example.org/a')
  })

  it('should reject a trust mark without a type', () => {
    const trustMarkJwt = unsignedJwt(
      { typ: 'trust-mark+jwt', alg: 'ES256', kid: 'tm' },
      { iss: 'https://tm-issuer.example.org', sub: 'https://leaf.example.org', iat: 1 }
    )

    assert.throws(() => validate({ schema: trustMarkSchema, data: { trust_mark: trustMarkJwt } }))
  })

  it('should reject a trust mark whose type differs from the type in its JWT', () => {
    const trustMarkJwt = unsignedJwt(
      { typ: 'trust-mark+jwt', alg: 'ES256', kid: 'tm' },
      {
        iss: 'https://tm-issuer.example.org',
        sub: 'https://leaf.example.org',
        trust_mark_type: 'https://tm.example.org/b',
        iat: 1,
      }
    )

    assert.throws(() =>
      validate({
        schema: trustMarkSchema,
        data: { trust_mark_type: 'https://tm.example.org/a', trust_mark: trustMarkJwt },
      })
    )
  })

  it('should keep protocol parameters and entity types the schema does not define', () => {
    const metadata = validate({
      schema: metadataSchema,
      data: {
        oauth_authorization_server: {
          issuer: 'https://as.example.org',
          token_endpoint: 'https://as.example.org/token',
        },
        federation_entity: { organization_name: 'Example', display_name: 'Example AS' },
        wallet_provider: { aal_values_supported: ['https://example.org/aal/high'] },
      },
    })

    assert.deepStrictEqual(metadata, {
      oauth_authorization_server: {
        issuer: 'https://as.example.org',
        token_endpoint: 'https://as.example.org/token',
      },
      federation_entity: { organization_name: 'Example', display_name: 'Example AS' },
      wallet_provider: { aal_values_supported: ['https://example.org/aal/high'] },
    })
  })

  it('should accept credential issuer and verifier metadata without client registration types', () => {
    assert.doesNotThrow(() =>
      validate({
        schema: metadataSchema,
        data: {
          openid_credential_issuer: { credential_issuer: 'https://issuer.example.org' },
          openid_credential_verifier: { client_name: 'Verifier' },
        },
      })
    )
  })

  it('should sign iat and exp given as dates as NumericDate values', async () => {
    const jwt = await createEntityConfiguration({
      signJwtCallback,
      claims: {
        iss: 'https://example.org',
        sub: 'https://example.org',
        iat: new Date(1700000000500),
        exp: new Date(1700086400000),
        jwks: { keys: [{ kid: 'a', kty: 'EC' }] },
      },
      header: { kid: 'a', typ: 'entity-statement+jwt' },
    })

    const claims = JSON.parse(Buffer.from(jwt.split('.')[1]!, 'base64url').toString())
    assert.strictEqual(claims.iat, 1700000000)
    assert.strictEqual(claims.exp, 1700086400)

    const parsed = validate({ schema: entityConfigurationClaimsSchema, data: claims })
    assert.deepStrictEqual(parsed.iat, new Date(1700000000000))
  })
})
