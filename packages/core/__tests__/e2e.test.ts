import assert from 'node:assert/strict'
import { subtle } from 'node:crypto'
import { describe, it } from 'node:test'

import nock from 'nock'

import { createEntityConfiguration, fetchEntityConfiguration } from '../src/entityConfiguration'
import { createEntityStatement, fetchEntityStatement } from '../src/entityStatement'
import type { SignCallback, VerifyCallback } from '../src/utils'
import { dateInSeconds } from './utils/dateInSeconds'

describe('End To End', async () => {
  const key = await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])
  const exportedKey = await subtle.exportKey('jwk', key.publicKey)
  const publicKeyJwk = {
    kid: 'some-id',
    kty: 'EC',
    key_ops: exportedKey.key_ops,
    x: exportedKey.x,
    y: exportedKey.y,
    crv: exportedKey.crv,
  }

  const signJwtCallback: SignCallback = async ({ toBeSigned }) =>
    new Uint8Array(await subtle.sign({ hash: 'SHA-256', name: 'ECDSA' }, key.privateKey, toBeSigned))

  const verifyJwtCallback: VerifyCallback = async ({ signature, data, jwk }) => {
    const publicKey = await subtle.importKey('jwk', jwk, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['verify'])

    return subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, publicKey, signature, data)
  }

  it('should fetch an entity configuration', async () => {
    const iss = 'https://example.org'

    const claims = {
      iss,
      sub: iss,
      exp: dateInSeconds(),
      iat: dateInSeconds(),
      jwks: {
        keys: [publicKeyJwk],
      },
    }

    const entityConfigurationJwt = await createEntityConfiguration({
      signJwtCallback,
      claims,
      header: {
        kid: 'some-id',
        typ: 'entity-statement+jwt',
      },
    })

    const scope = nock(iss).get('/.well-known/openid-federation').reply(200, entityConfigurationJwt, {
      'content-type': 'application/entity-statement+jwt',
    })

    const fetchedEntityConfigurationClaims = await fetchEntityConfiguration({
      entityId: iss,
      verifyJwtCallback,
    })

    assert.deepStrictEqual(fetchedEntityConfigurationClaims, claims)

    scope.done()
  })

  it('should fetch an entity statement', async () => {
    const iss = 'https://example.org'
    const sub = 'https://sub.example.org'

    const entityConfigurationJwt = await createEntityConfiguration({
      signJwtCallback,
      claims: {
        iss,
        sub: iss,
        exp: dateInSeconds(),
        iat: dateInSeconds(),
        jwks: {
          keys: [publicKeyJwk],
        },
        metadata: {
          federation_entity: {
            federation_fetch_endpoint: `${iss}/fetch`,
          },
        },
      },
      header: {
        kid: 'some-id',
        typ: 'entity-statement+jwt',
      },
    })

    const entityStamentClaims = {
      iss,
      sub,
      exp: dateInSeconds(),
      iat: dateInSeconds(),
      jwks: {
        keys: [],
      },
      authority_hints: [iss],
      metadata: {
        federation_entity: {
          organization_name: 'my org!',
        },
      },
    }

    const entityStatementJwt = await createEntityStatement({
      signJwtCallback,
      claims: entityStamentClaims,
      header: {
        kid: 'some-id',
        typ: 'entity-statement+jwt',
      },
      jwk: publicKeyJwk,
    })

    const scope = nock(iss)
      .get('/.well-known/openid-federation')
      .reply(200, entityConfigurationJwt, {
        'content-type': 'application/entity-statement+jwt',
      })
      .get('/fetch')
      .query({ sub })
      .reply(200, entityStatementJwt, {
        'content-type': 'application/entity-statement+jwt',
      })

    const fetchedEntityConfigurationClaims = await fetchEntityConfiguration({
      entityId: iss,
      verifyJwtCallback,
    })

    const fetchedEntityStatementClaims = await fetchEntityStatement({
      iss,
      sub,
      issEntityConfiguration: fetchedEntityConfigurationClaims,
      verifyJwtCallback,
    })

    assert.deepStrictEqual(fetchedEntityStatementClaims, entityStamentClaims)

    scope.done()
  })
})
