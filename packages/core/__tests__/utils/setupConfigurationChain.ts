import nock from 'nock'
import {
  type EntityConfigurationClaimsOptions,
  type EntityConfigurationHeaderOptions,
  createEntityConfiguration,
} from '../../src/entityConfiguration'
import { type EntityStatementClaimsOptions, createEntityStatement } from '../../src/entityStatement'
import type { JsonWebKeySetOptions } from '../../src/jsonWeb'
import type { SignCallback } from '../../src/utils'
import { dateInSeconds } from './dateInSeconds'

type SubordinateOptions = {
  entityId: string
  claims: Partial<EntityStatementClaimsOptions>
}

type ChainConfigurationOptions = {
  entityId: string
  authorityHints?: Array<string>
  subordinates?: Array<string | SubordinateOptions>
  jwks?: JsonWebKeySetOptions
  kid?: string
  includeSourceEndpoint?: boolean

  claims?: Partial<EntityConfigurationClaimsOptions>
}

export const setupConfigurationChain = async <MockEndpoints extends boolean>(
  chainOptions: Array<ChainConfigurationOptions>,
  {
    signJwtCallback,
    mockEndpoints = false as MockEndpoints,
  }: {
    signJwtCallback: SignCallback
    /**
     * @default false
     */
    mockEndpoints?: MockEndpoints
  }
) => {
  if (mockEndpoints) {
    nock.cleanAll()
  }

  const chainData: Array<{
    claims: EntityConfigurationClaimsOptions
    jwt: string
    entityId: string
    subordinateStatements?: Array<{ entityId: string; jwt: string; claims: EntityStatementClaimsOptions }>
  }> = []
  const nockScopes: Array<nock.Scope> = []
  for (const {
    entityId,
    authorityHints,
    jwks,
    kid,
    subordinates,
    includeSourceEndpoint = true,
    claims: givenClaims = {},
  } of chainOptions) {
    const claims: EntityConfigurationClaimsOptions = {
      iss: entityId,
      sub: entityId,
      exp: dateInSeconds(1000 * 60 * 60 * 24 * 30), // 30 days
      iat: dateInSeconds(),
      jwks: jwks ?? { keys: [{ kid: 'a', kty: 'EC' }] },
      authority_hints: authorityHints,
      ...givenClaims,
      metadata: {
        federation_entity: {
          federation_fetch_endpoint: `${entityId}/fetch`,
        },
        ...(givenClaims.metadata ?? {}),
      },
    }

    // fix so `undefined` is not in the expected claims
    if (!authorityHints) delete claims.authority_hints
    if (!includeSourceEndpoint) delete claims.source_endpoint

    const header: EntityConfigurationHeaderOptions = {
      kid: kid ?? 'a',
      typ: 'entity-statement+jwt',
    }

    const jwt = await createEntityConfiguration({
      claims,
      header,
      signJwtCallback,
    })

    if (mockEndpoints) {
      const scope = nock(entityId).get('/.well-known/openid-federation').reply(200, jwt, {
        'content-type': 'application/entity-statement+jwt',
      })

      nockScopes.push(scope)
    }

    const subordinateStatements: Array<{ entityId: string; jwt: string; claims: EntityStatementClaimsOptions }> = []
    for (const sub of subordinates ?? []) {
      const givenClaims = typeof sub === 'string' ? { sub } : { sub: sub.entityId, ...sub.claims }

      const subordinateClaims = {
        jwks: { keys: [] },
        iss: entityId,
        exp: dateInSeconds(1000 * 60 * 60 * 24 * 30), // 30 days
        iat: dateInSeconds(),
        ...givenClaims,
      }

      const entityStatementJwt = await createEntityStatement({
        signJwtCallback,
        jwk: claims.jwks.keys[0]!,
        claims: subordinateClaims,
      })

      if (mockEndpoints && claims.metadata?.federation_entity?.federation_fetch_endpoint) {
        const scope = nock(claims.metadata.federation_entity.federation_fetch_endpoint)
          .get('')
          .query({
            sub: subordinateClaims.sub,
            iss: entityId,
          })
          .reply(200, entityStatementJwt, {
            'content-type': 'application/entity-statement+jwt',
          })

        nockScopes.push(scope)
      }

      subordinateStatements.push({
        entityId: subordinateClaims.sub,
        jwt: entityStatementJwt,
        claims: subordinateClaims,
      })
    }

    chainData.push({
      claims,
      jwt,
      entityId,
      subordinateStatements,
    })
  }

  return {
    chainData,
    nockScopes: (mockEndpoints ? nockScopes : undefined) as MockEndpoints extends true ? typeof nockScopes : never,
  } as const
}
