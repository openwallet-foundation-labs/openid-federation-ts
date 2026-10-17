import assert from 'node:assert/strict'
import { describe, it } from 'node:test'
import nock from 'nock'
import { createEntityConfiguration, fetchEntityConfiguration } from '../src/entityConfiguration'
import { createEntityStatement } from '../src/entityStatement/createEntityStatement'
import { fetchEntityStatement } from '../src/entityStatement/fetchEntityStatement'
import type { SignCallback, VerifyCallback } from '../src/utils'
import { dateInSeconds } from './utils/dateInSeconds'

describe('fetch entity statement', () => {
  const signJwtCallback: SignCallback = () => Promise.resolve(new Uint8Array(10).fill(42))
  const verifyJwtCallback: VerifyCallback = () => Promise.resolve(true)

  it('should fetch a basic entity statement', async () => {
    const iss = 'https://example.org'
    const sub = 'https://one.example.org'

    const issEntityConfigurationJwt = await createEntityConfiguration({
      signJwtCallback,
      claims: {
        jwks: {
          keys: [{ kid: 'a', kty: 'EC' }],
        },
        sub: iss,
        iss,
        metadata: {
          federation_entity: {
            federation_fetch_endpoint: `${iss}/fetch`,
          },
        },
        iat: 1,
        exp: 1,
      },
      header: {
        kid: 'a',
        typ: 'entity-statement+jwt',
      },
    })

    const entityStatementClaims = {
      exp: dateInSeconds(),
      iat: dateInSeconds(),
      iss,
      sub,
      jwks: { keys: [{ kty: 'EC', kid: 'b' }] },
    }

    const entityStatementJwt = await createEntityStatement({
      jwk: { kty: 'EC', kid: 'a' },
      claims: entityStatementClaims,
      header: {
        kid: 'a',
        typ: 'entity-statement+jwt',
      },
      signJwtCallback,
    })

    const scope = nock('https://example.org')
      .get('/.well-known/openid-federation')
      .reply(200, issEntityConfigurationJwt, {
        'content-type': 'application/entity-statement+jwt',
      })
      .get('/fetch')
      .query({ iss, sub })
      .reply(200, entityStatementJwt, {
        'content-type': 'application/entity-statement+jwt',
      })

    const fetchedEntityConfiguration = await fetchEntityConfiguration({
      entityId: iss,
      verifyJwtCallback,
    })

    const fetchedEntityStatement = await fetchEntityStatement({
      verifyJwtCallback,
      iss,
      sub,
      issEntityConfiguration: fetchedEntityConfiguration,
    })

    assert.deepStrictEqual(fetchedEntityStatement, entityStatementClaims)

    scope.done()
  })

  it('should fetch a basic entity statement without providing iss entity configuration', async () => {
    const iss = 'https://example.org'
    const sub = 'https://one.example.org'

    const issEntityConfigurationJwt = await createEntityConfiguration({
      signJwtCallback,
      claims: {
        jwks: {
          keys: [{ kid: 'a', kty: 'EC' }],
        },
        sub: iss,
        iss,
        metadata: {
          federation_entity: {
            federation_fetch_endpoint: `${iss}/fetch`,
          },
        },
        iat: 1,
        exp: 1,
      },
      header: {
        kid: 'a',
        typ: 'entity-statement+jwt',
      },
    })

    const entityStatementClaims = {
      exp: dateInSeconds(),
      iat: dateInSeconds(),
      iss,
      sub,
      jwks: { keys: [{ kty: 'EC', kid: 'b' }] },
    }

    const entityStatementJwt = await createEntityStatement({
      jwk: { kty: 'EC', kid: 'a' },
      claims: entityStatementClaims,
      header: {
        kid: 'a',
        typ: 'entity-statement+jwt',
      },
      signJwtCallback,
    })

    const scope = nock('https://example.org')
      .get('/.well-known/openid-federation')
      .reply(200, issEntityConfigurationJwt, {
        'content-type': 'application/entity-statement+jwt',
      })
      .get('/fetch')
      .query({ iss, sub })
      .reply(200, entityStatementJwt, {
        'content-type': 'application/entity-statement+jwt',
      })

    const fetchedEntityStatement = await fetchEntityStatement({
      verifyJwtCallback,
      iss,
      sub,
    })

    assert.deepStrictEqual(fetchedEntityStatement, entityStatementClaims)

    scope.done()
  })

  it('should fetch a basic entity statement with providing the endpoint manually', async () => {
    const iss = 'https://example.org'
    const sub = 'https://one.example.org'

    const issEntityConfigurationJwt = await createEntityConfiguration({
      signJwtCallback,
      claims: {
        jwks: {
          keys: [{ kid: 'a', kty: 'EC' }],
        },
        sub: iss,
        iss,
        metadata: {
          federation_entity: {
            federation_fetch_endpoint: `${iss}/fetch`,
          },
        },
        iat: 1,
        exp: 1,
      },
      header: {
        kid: 'a',
        typ: 'entity-statement+jwt',
      },
    })

    const entityStatementClaims = {
      exp: dateInSeconds(),
      iat: dateInSeconds(),
      iss,
      sub,
      jwks: { keys: [{ kty: 'EC', kid: 'b' }] },
    }

    const entityStatementJwt = await createEntityStatement({
      jwk: { kty: 'EC', kid: 'a' },
      claims: entityStatementClaims,
      header: {
        kid: 'a',
        typ: 'entity-statement+jwt',
      },
      signJwtCallback,
    })

    const scope = nock('https://example.org')
      .get('/.well-known/openid-federation')
      .reply(200, issEntityConfigurationJwt, {
        'content-type': 'application/entity-statement+jwt',
      })
      .get('/fetch')
      .query({ iss, sub })
      .reply(200, entityStatementJwt, {
        'content-type': 'application/entity-statement+jwt',
      })

    const fetchedEntityStatement = await fetchEntityStatement({
      verifyJwtCallback,
      iss,
      sub,
      endpoint: `${iss}/fetch`,
    })

    assert.deepStrictEqual(fetchedEntityStatement, entityStatementClaims)

    scope.done()
  })

  it('should not fetch an entity statement without a fetch endpoint', async () => {
    const iss = 'https://example.org'
    const sub = 'https://one.example.org'

    const issEntityConfigurationJwt = await createEntityConfiguration({
      signJwtCallback,
      claims: {
        jwks: {
          keys: [{ kid: 'a', kty: 'EC' }],
        },
        sub: iss,
        iss,
        iat: 1,
        exp: 1,
      },
      header: {
        kid: 'a',
        typ: 'entity-statement+jwt',
      },
    })

    const scope = nock('https://example.org')
      .get('/.well-known/openid-federation')
      .reply(200, issEntityConfigurationJwt, {
        'content-type': 'application/entity-statement+jwt',
      })

    await assert.rejects(
      fetchEntityStatement({
        verifyJwtCallback,
        iss,
        sub,
      })
    )

    scope.done()
  })

  it('should not fetch an entity statement without anything hosted on the fetch endpoint', async () => {
    const iss = 'https://example.org'
    const sub = 'https://one.example.org'

    const issEntityConfigurationJwt = await createEntityConfiguration({
      signJwtCallback,
      claims: {
        jwks: {
          keys: [{ kid: 'a', kty: 'EC' }],
        },
        sub: iss,
        iss,
        iat: 1,
        exp: 1,
        metadata: {
          federation_entity: {
            federation_fetch_endpoint: `${iss}/fetch`,
          },
        },
      },
      header: {
        kid: 'a',
        typ: 'entity-statement+jwt',
      },
    })

    const scope = nock('https://example.org')
      .get('/.well-known/openid-federation')
      .reply(200, issEntityConfigurationJwt, {
        'content-type': 'application/entity-statement+jwt',
      })
      .get('/fetch')
      .query({ iss, sub })
      .reply(404)

    await assert.rejects(
      fetchEntityStatement({
        verifyJwtCallback,
        iss,
        sub,
      })
    )

    scope.done()
  })

  it('should not fetch an entity statement with an invalid content-type', async () => {
    const iss = 'https://example.org'
    const sub = 'https://one.example.org'

    const issEntityConfigurationJwt = await createEntityConfiguration({
      signJwtCallback,
      claims: {
        jwks: {
          keys: [{ kid: 'a', kty: 'EC' }],
        },
        sub: iss,
        iss,
        metadata: {
          federation_entity: {
            federation_fetch_endpoint: `${iss}/fetch`,
          },
        },
        iat: 1,
        exp: 1,
      },
      header: {
        kid: 'a',
        typ: 'entity-statement+jwt',
      },
    })

    const entityStatementClaims = {
      exp: dateInSeconds(),
      iat: dateInSeconds(),
      iss,
      sub,
      jwks: { keys: [{ kty: 'EC', kid: 'b' }] },
    }

    const entityStatementJwt = await createEntityStatement({
      jwk: { kty: 'EC', kid: 'a' },
      claims: entityStatementClaims,
      header: {
        kid: 'a',
        typ: 'entity-statement+jwt',
      },
      signJwtCallback,
    })

    const scope = nock('https://example.org')
      .get('/.well-known/openid-federation')
      .reply(200, issEntityConfigurationJwt, {
        'content-type': 'application/entity-statement+jwt',
      })
      .get('/fetch')
      .query({ iss, sub })
      .reply(200, entityStatementJwt, {
        'content-type': 'invalid-content',
      })

    await assert.rejects(
      fetchEntityStatement({
        verifyJwtCallback,
        iss,
        sub,
      })
    )

    scope.done()
  })
})
