import { describe, it } from 'node:test'
import {
  type EntityConfigurationClaimsOptions,
  createEntityConfiguration,
  fetchEntityConfiguration,
} from '../src/entityConfiguration'
import type { SignCallback, VerifyCallback } from '../src/utils'

import assert from 'node:assert/strict'
import nock from 'nock'
import { dateInSeconds } from './utils/dateInSeconds'

describe('fetch entity configuration', () => {
  const verifyJwtCallback: VerifyCallback = () => Promise.resolve(true)

  const signJwtCallback: SignCallback = () => Promise.resolve(new Uint8Array(10).fill(42))

  it('should fetch a simple entity configuration', async () => {
    const entityId = 'https://example.org'

    const claims = {
      iss: entityId,
      sub: entityId,
      iat: dateInSeconds(),
      exp: dateInSeconds(),
      jwks: { keys: [{ kid: 'a', kty: 'EC' }] },
    }

    const entityConfiguration = await createEntityConfiguration({
      header: { kid: 'a', typ: 'entity-statement+jwt' },
      claims,
      signJwtCallback,
    })

    const scope = nock(entityId).get('/.well-known/openid-federation').reply(200, entityConfiguration, {
      'content-type': 'application/entity-statement+jwt',
    })

    const fetchedEntityConfiguration = await fetchEntityConfiguration({
      entityId,
      verifyJwtCallback,
    })

    assert.deepStrictEqual(fetchedEntityConfiguration, claims)

    scope.done()
  })

  it('should fetch an entity configuration with metadata and unknown properties', async () => {
    const entityId = 'https://example.org'

    const claims = {
      iss: entityId,
      sub: entityId,
      iat: dateInSeconds(),
      exp: dateInSeconds(),
      metadata: {
        openid_relying_party: {
          client_name: 'bakfiets',
          client_registration_types: ['automatic'],
        },
      },
      jwks: { keys: [{ kid: 'a', kty: 'EC' }] },
    } satisfies EntityConfigurationClaimsOptions

    const entityConfiguration = await createEntityConfiguration({
      header: { kid: 'a', typ: 'entity-statement+jwt' },
      claims,
      signJwtCallback,
    })

    const scope = nock(entityId).get('/.well-known/openid-federation').reply(200, entityConfiguration, {
      'content-type': 'application/entity-statement+jwt',
    })

    const fetchedEntityConfiguration = await fetchEntityConfiguration({
      entityId,
      verifyJwtCallback,
    })

    assert.deepStrictEqual(fetchedEntityConfiguration, claims)

    scope.done()
  })

  it('should not fetch an entity configuration when the content-type is invalid', async () => {
    const entityId = 'https://exampletwo.org'

    const claims = {
      iss: entityId,
      sub: entityId,
      iat: dateInSeconds(),
      exp: dateInSeconds(),
      jwks: { keys: [{ kid: 'a', kty: 'EC' }] },
    }

    const entityConfiguration = await createEntityConfiguration({
      header: { kid: 'a', typ: 'entity-statement+jwt' },
      claims,
      signJwtCallback,
    })

    const scope = nock(entityId).get('/.well-known/openid-federation').reply(200, entityConfiguration, {
      'content-type': 'invalid-type',
    })

    await assert.rejects(fetchEntityConfiguration({ entityId, verifyJwtCallback }))

    scope.done()
  })

  it('should not fetch an entity configuration when there is no entity configuration', async () => {
    const entityId = 'https://examplethree.org'

    await assert.rejects(fetchEntityConfiguration({ entityId, verifyJwtCallback }))
  })
})
