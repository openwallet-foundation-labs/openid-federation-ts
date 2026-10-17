import assert from 'node:assert/strict'
import { webcrypto } from 'node:crypto'
import { afterEach, beforeEach, describe, it } from 'node:test'
import { createEntityConfiguration } from '../src/entityConfiguration'
import { createEntityStatement } from '../src/entityStatement'
import type { JsonWebKey } from '../src/jsonWeb'
import {
  type ResolveTrustChainsOptions,
  resolveTrustChains,
  resolveTrustChainsWithFailures,
} from '../src/resolveTrustChains'
import type { FetchCallback, SignCallback, VerifyCallback } from '../src/utils'
import { dateInSeconds } from './utils/dateInSeconds'

const { subtle } = webcrypto
const ALGORITHM = { name: 'ECDSA', namedCurve: 'P-256' } as const
const SIGNATURE = { name: 'ECDSA', hash: 'SHA-256' } as const
const DAY = 1000 * 60 * 60 * 24

const privateKeys = new Map<string, webcrypto.CryptoKey>()

const createKey = async (kid: string): Promise<JsonWebKey> => {
  const pair = await subtle.generateKey(ALGORITHM, true, ['sign', 'verify'])
  privateKeys.set(kid, pair.privateKey)
  const { kty, crv, x, y } = await subtle.exportKey('jwk', pair.publicKey)
  return { kid, kty: kty as string, crv, x, y, alg: 'ES256', use: 'sig' } as JsonWebKey
}

const signJwtCallback: SignCallback = async ({ toBeSigned, jwk }) => {
  const key = privateKeys.get(jwk.kid)
  if (!key) throw new Error(`no private key for ${jwk.kid}`)
  return new Uint8Array(await subtle.sign(SIGNATURE, key, toBeSigned))
}

const verifyJwtCallback: VerifyCallback = async ({ data, signature, jwk }) => {
  const key = await subtle.importKey('jwk', jwk as webcrypto.JsonWebKey, ALGORITHM, false, ['verify'])
  return subtle.verify(SIGNATURE, key, signature, data)
}

type Entity = {
  id: string
  key: JsonWebKey
  /** Keys published in the entity configuration, defaults to `[key]` */
  jwks?: Array<JsonWebKey>
  authorityHints?: Array<string>
  /** Claims added to the entity configuration */
  claims?: Record<string, unknown>
  metadata?: Record<string, Record<string, unknown>>
}

type Statement = {
  issuer: Entity
  subject: Entity
  /** Keys listed for the subject, defaults to the subject's keys */
  jwks?: Array<JsonWebKey>
  /** Key used to sign, defaults to the issuer's key */
  signingKey?: JsonWebKey
  claims?: Record<string, unknown>
}

/**
 * An in-memory federation, served by a fetch callback.
 */
class Federation {
  readonly responses = new Map<string, { status: number; body: string; contentType: string }>()
  readonly requested: Array<string> = []

  async addEntity(entity: Entity) {
    const jwt = await createEntityConfiguration({
      signJwtCallback,
      header: { kid: entity.key.kid, typ: 'entity-statement+jwt', alg: 'ES256' },
      claims: {
        iss: entity.id,
        sub: entity.id,
        iat: dateInSeconds(),
        exp: dateInSeconds(DAY),
        jwks: { keys: entity.jwks ?? [entity.key] },
        authority_hints: entity.authorityHints,
        metadata: {
          federation_entity: { federation_fetch_endpoint: `${entity.id}/fetch` },
          ...entity.metadata,
        },
        ...entity.claims,
      },
    })
    this.serve(`${entity.id}/.well-known/openid-federation`, jwt)
    return jwt
  }

  async addStatement({ issuer, subject, jwks, signingKey, claims }: Statement) {
    const key = signingKey ?? issuer.key
    const jwt = await createEntityStatement({
      signJwtCallback,
      jwk: key,
      header: { kid: key.kid, typ: 'entity-statement+jwt', alg: 'ES256' },
      claims: {
        iss: issuer.id,
        sub: subject.id,
        iat: dateInSeconds(),
        exp: dateInSeconds(DAY),
        jwks: { keys: jwks ?? subject.jwks ?? [subject.key] },
        ...claims,
      },
    })
    this.serve(`${issuer.id}/fetch?${new URLSearchParams({ sub: subject.id })}`, jwt)
    return jwt
  }

  serve(url: string, body: string, status = 200, contentType = 'application/entity-statement+jwt') {
    this.responses.set(url, { status, body, contentType })
  }

  fetchCallback: FetchCallback = async (input) => {
    const url = String(input)
    this.requested.push(url)
    const response = this.responses.get(url)
    if (!response) return new Response('not found', { status: 404 })
    return new Response(response.body, { status: response.status, headers: { 'content-type': response.contentType } })
  }

  options(overrides: Partial<ResolveTrustChainsOptions> & { entityId: string }): ResolveTrustChainsOptions {
    return {
      verifyJwtCallback,
      fetchCallback: this.fetchCallback,
      trustAnchors: [{ entityId: 'https://ta.example.org' }],
      ...overrides,
    }
  }
}

describe('resolve trust chains with validation', () => {
  let federation: Federation
  let trustAnchor: Entity
  let intermediate: Entity
  let leaf: Entity
  const originalFetch = globalThis.fetch

  beforeEach(async () => {
    // Every request must go through the fetch callback
    globalThis.fetch = () => Promise.reject(new Error('global fetch must not be used'))

    federation = new Federation()
    trustAnchor = { id: 'https://ta.example.org', key: await createKey('ta') }
    intermediate = {
      id: 'https://intermediate.example.org',
      key: await createKey('intermediate'),
      authorityHints: [trustAnchor.id],
    }
    leaf = {
      id: 'https://leaf.example.org',
      key: await createKey('leaf'),
      authorityHints: [intermediate.id],
      metadata: { openid_credential_issuer: { credential_issuer: 'https://leaf.example.org' } },
    }
    await federation.addEntity(trustAnchor)
    await federation.addEntity(intermediate)
    await federation.addEntity(leaf)
    await federation.addStatement({ issuer: trustAnchor, subject: intermediate })
    await federation.addStatement({ issuer: intermediate, subject: leaf })
  })

  afterEach(() => {
    globalThis.fetch = originalFetch
  })

  it('should resolve leaf -> intermediate -> trust anchor through the fetch callback', async () => {
    const { trustChains, failures } = await resolveTrustChainsWithFailures(federation.options({ entityId: leaf.id }))

    assert.deepStrictEqual(failures, [])
    assert.strictEqual(trustChains.length, 1)
    const [trustChain] = trustChains
    assert.strictEqual(trustChain?.jwtChain.length, 4)
    assert.strictEqual(trustChain?.chain.length, 3)
    assert.deepStrictEqual(trustChain?.resolvedLeafMetadata?.openid_credential_issuer, {
      credential_issuer: 'https://leaf.example.org',
    })
    assert.ok(trustChain && trustChain.expiresAt.getTime() <= Date.now() + DAY)
    assert.ok(federation.requested.length > 0)
  })

  it('should resolve when the trust anchor keys are pinned', async () => {
    const trustChains = await resolveTrustChains(
      federation.options({
        entityId: leaf.id,
        trustAnchors: [{ entityId: trustAnchor.id, jwks: { keys: [trustAnchor.key] } }],
      })
    )

    assert.strictEqual(trustChains.length, 1)
  })

  it('should reject a trust anchor entity configuration not signed with the pinned key', async () => {
    const pinned = await createKey('ta')
    const { trustChains, failures } = await resolveTrustChainsWithFailures(
      federation.options({ entityId: leaf.id, trustAnchors: [{ entityId: trustAnchor.id, jwks: { keys: [pinned] } }] })
    )

    assert.strictEqual(trustChains.length, 0)
    assert.match(
      failures[0]?.reason ?? '',
      /trust anchor 'https:\/\/ta.example.org' is not signed with a configured key/
    )
  })

  it('should reject an authority hint whose entity configuration names the trust anchor as subject', async () => {
    // The attacker serves a self-signed entity configuration claiming to be the trust anchor
    const attacker = { id: 'https://attacker.example.net', key: await createKey('ta') }
    const forged = await createEntityConfiguration({
      signJwtCallback,
      header: { kid: attacker.key.kid, typ: 'entity-statement+jwt', alg: 'ES256' },
      claims: {
        iss: trustAnchor.id,
        sub: trustAnchor.id,
        iat: dateInSeconds(),
        exp: dateInSeconds(DAY),
        jwks: { keys: [attacker.key] },
        metadata: { federation_entity: { federation_fetch_endpoint: `${attacker.id}/fetch` } },
      },
    })
    federation.serve(`${attacker.id}/.well-known/openid-federation`, forged)
    const victim = { id: 'https://victim.example.org', key: await createKey('victim'), authorityHints: [attacker.id] }
    await federation.addEntity(victim)

    const { trustChains, failures } = await resolveTrustChainsWithFailures(federation.options({ entityId: victim.id }))

    assert.strictEqual(trustChains.length, 0)
    assert.match(failures[0]?.reason ?? '', /fetched for 'https:\/\/attacker.example.net' has subject/)
  })

  it('should reject a leaf whose entity configuration is not signed with a key its superior lists', async () => {
    // The leaf configuration is replaced by one signed with a key the intermediate never vouched for
    const replaced = { ...leaf, key: await createKey('leaf') }
    await federation.addEntity(replaced)

    const { trustChains, failures } = await resolveTrustChainsWithFailures(federation.options({ entityId: leaf.id }))

    assert.strictEqual(trustChains.length, 0)
    assert.match(
      failures[0]?.reason ?? '',
      /statement about 'https:\/\/leaf.example.org' issued by 'https:\/\/leaf.example.org' is not signed with a key listed by 'https:\/\/intermediate.example.org'/
    )
  })

  it('should accept a statement signed with a key the superior lists, also during an intermediate key rollover', async () => {
    // The trust anchor lists the old and the new intermediate key; the intermediate already publishes only the new
    // one but still signs the statement about the leaf with the old one
    const oldKey = intermediate.key
    const newKey = await createKey('intermediate-2')
    const rolled = { ...intermediate, key: newKey, jwks: [newKey] }
    await federation.addEntity(rolled)
    await federation.addStatement({ issuer: trustAnchor, subject: rolled, jwks: [oldKey, newKey] })
    await federation.addStatement({ issuer: rolled, subject: leaf, signingKey: oldKey })

    const { trustChains, failures } = await resolveTrustChainsWithFailures(federation.options({ entityId: leaf.id }))

    assert.deepStrictEqual(failures, [])
    assert.strictEqual(trustChains.length, 1)
  })

  it('should reject a statement signed with a key the superior does not list', async () => {
    // The intermediate publishes a key in its own entity configuration that the trust anchor never vouched for
    const unvouched = await createKey('intermediate-unvouched')
    const changed = { ...intermediate, key: unvouched, jwks: [unvouched, intermediate.key] }
    await federation.addEntity(changed)
    await federation.addStatement({ issuer: changed, subject: leaf, signingKey: unvouched })

    const { trustChains, failures } = await resolveTrustChainsWithFailures(federation.options({ entityId: leaf.id }))

    assert.strictEqual(trustChains.length, 0)
    assert.match(failures[0]?.reason ?? '', /is not signed with a key listed by 'https:\/\/ta.example.org'/)
  })

  it('should compare entity identifiers exactly', async () => {
    const trustChains = await resolveTrustChains(
      federation.options({ entityId: leaf.id, trustAnchors: [{ entityId: `${trustAnchor.id}/` }] })
    )

    assert.strictEqual(trustChains.length, 0)
  })

  it('should reject a subordinate statement with an invalid signature', async () => {
    await federation.addStatement({ issuer: intermediate, subject: leaf, signingKey: await createKey('intermediate') })

    const { trustChains, failures } = await resolveTrustChainsWithFailures(federation.options({ entityId: leaf.id }))

    assert.strictEqual(trustChains.length, 0)
    assert.match(failures[0]?.reason ?? '', /Signature in the JWT is invalid/)
  })

  it('should reject a subordinate statement about another subject', async () => {
    const other = { id: 'https://other.example.org', key: await createKey('other') }
    const jwt = await federation.addStatement({ issuer: intermediate, subject: other })
    federation.serve(`${intermediate.id}/fetch?${new URLSearchParams({ sub: leaf.id })}`, jwt)

    const { trustChains, failures } = await resolveTrustChainsWithFailures(federation.options({ entityId: leaf.id }))

    assert.strictEqual(trustChains.length, 0)
    assert.match(
      failures[0]?.reason ?? '',
      /has issuer 'https:\/\/intermediate.example.org' and subject 'https:\/\/other.example.org'/
    )
  })

  it('should reject an expired leaf entity configuration', async () => {
    await federation.addEntity({ ...leaf, claims: { exp: dateInSeconds(-1000) } })

    const { trustChains, failures } = await resolveTrustChainsWithFailures(federation.options({ entityId: leaf.id }))

    assert.strictEqual(trustChains.length, 0)
    assert.match(failures[0]?.reason ?? '', /has expired/)
  })

  it('should reject an intermediate entity configuration issued in the future', async () => {
    await federation.addEntity({ ...intermediate, claims: { iat: dateInSeconds(DAY / 2) } })

    const { trustChains, failures } = await resolveTrustChainsWithFailures(federation.options({ entityId: leaf.id }))

    assert.strictEqual(trustChains.length, 0)
    assert.match(failures[0]?.reason ?? '', /iat in the future/)
  })

  it('should accept a clock difference within clockSkewSeconds', async () => {
    await federation.addEntity({ ...intermediate, claims: { iat: dateInSeconds(30_000) } })

    const trustChains = await resolveTrustChains(federation.options({ entityId: leaf.id, clockSkewSeconds: 60 }))

    assert.strictEqual(trustChains.length, 1)
  })

  it('should reject an unknown trust anchor', async () => {
    const trustChains = await resolveTrustChains(
      federation.options({ entityId: leaf.id, trustAnchors: [{ entityId: 'https://other-ta.example.org' }] })
    )

    assert.strictEqual(trustChains.length, 0)
  })

  it('should reject critical claims that are not understood', async () => {
    await federation.addStatement({
      issuer: intermediate,
      subject: leaf,
      claims: { crit: ['profile_claim'], profile_claim: true },
    })

    const rejected = await resolveTrustChainsWithFailures(federation.options({ entityId: leaf.id }))
    assert.strictEqual(rejected.trustChains.length, 0)
    assert.match(rejected.failures[0]?.reason ?? '', /critical claims that are not understood: profile_claim/)

    const accepted = await resolveTrustChains(
      federation.options({ entityId: leaf.id, understoodCriticalClaims: ['profile_claim'] })
    )
    assert.strictEqual(accepted.length, 1)
  })

  it('should apply max_path_length', async () => {
    await federation.addStatement({
      issuer: trustAnchor,
      subject: intermediate,
      claims: { constraints: { max_path_length: 0 } },
    })

    const { trustChains, failures } = await resolveTrustChainsWithFailures(federation.options({ entityId: leaf.id }))

    assert.strictEqual(trustChains.length, 0)
    assert.match(failures[0]?.reason ?? '', /allows 0 intermediates, the chain has 1/)
  })

  it('should remove entity types that allowed_entity_types does not allow', async () => {
    await federation.addEntity({
      ...leaf,
      metadata: {
        openid_credential_issuer: { credential_issuer: leaf.id },
        openid_credential_verifier: { client_name: 'Verifier' },
      },
    })
    await federation.addStatement({
      issuer: trustAnchor,
      subject: intermediate,
      claims: { constraints: { allowed_entity_types: ['openid_credential_issuer'] } },
    })

    const [trustChain] = await resolveTrustChains(federation.options({ entityId: leaf.id }))

    assert.deepStrictEqual(Object.keys(trustChain?.resolvedLeafMetadata ?? {}).sort(), [
      'federation_entity',
      'openid_credential_issuer',
    ])
  })

  it('should not let a metadata policy add an entity type that allowed_entity_types removed', async () => {
    await federation.addStatement({
      issuer: trustAnchor,
      subject: intermediate,
      claims: { constraints: { allowed_entity_types: ['openid_credential_verifier'] } },
    })
    await federation.addStatement({
      issuer: intermediate,
      subject: leaf,
      claims: {
        metadata_policy: { openid_credential_issuer: { credential_issuer: { value: 'https://evil.example.net' } } },
      },
    })

    const [trustChain] = await resolveTrustChains(federation.options({ entityId: leaf.id }))

    assert.strictEqual(trustChain?.resolvedLeafMetadata?.openid_credential_issuer, undefined)
  })

  it('should stop after maxRequests', async () => {
    const hints = Array.from({ length: 20 }, (_, index) => `https://hint-${index}.example.net`)
    await federation.addEntity({ ...leaf, authorityHints: [...hints, intermediate.id] })

    const { trustChains, failures } = await resolveTrustChainsWithFailures(
      federation.options({ entityId: leaf.id, maxRequests: 10 })
    )

    assert.strictEqual(trustChains.length, 0)
    assert.ok(federation.requested.length <= 10)
    assert.ok(failures.some((failure) => /exceeded 10 (requests|entity visits)/.test(failure.reason)))
  })

  it('should visit repeated and converging authority hints a bounded number of times', async () => {
    // Every level lists the next level twice and two entities that both point to the next level
    let next = intermediate.id
    for (let level = 0; level < 6; level++) {
      const a = { id: `https://a${level}.example.net`, key: await createKey(`a${level}`), authorityHints: [next, next] }
      const b = { id: `https://b${level}.example.net`, key: await createKey(`b${level}`), authorityHints: [next, next] }
      await federation.addEntity(a)
      await federation.addEntity(b)
      next = `https://level${level}.example.net`
      await federation.addEntity({ id: next, key: await createKey(next), authorityHints: [a.id, b.id, a.id, b.id] })
    }
    await federation.addEntity({ ...leaf, authorityHints: [next, next, next] })

    const { trustChains, failures } = await resolveTrustChainsWithFailures(
      federation.options({ entityId: leaf.id, maxDepth: 20 })
    )

    assert.strictEqual(trustChains.length, 0)
    assert.ok(failures.some((failure) => /exceeded 64 entity visits/.test(failure.reason)))
  })

  it('should reject naming constraints, which are not evaluated', async () => {
    await federation.addStatement({
      issuer: trustAnchor,
      subject: intermediate,
      claims: { constraints: { naming_constraints: { permitted: ['.example.org'] } } },
    })

    const { trustChains, failures } = await resolveTrustChainsWithFailures(federation.options({ entityId: leaf.id }))

    assert.strictEqual(trustChains.length, 0)
    assert.match(failures[0]?.reason ?? '', /naming_constraints, which are not supported/)
  })

  it('should reject a statement whose exp is not a NumericDate', async () => {
    await federation.addStatement({ issuer: intermediate, subject: leaf, claims: { exp: 'never' } })

    const { trustChains, failures } = await resolveTrustChainsWithFailures(federation.options({ entityId: leaf.id }))

    assert.strictEqual(trustChains.length, 0)
    assert.ok(failures.length > 0)
  })

  it('should not follow superiors beyond maxDepth', async () => {
    const trustChains = await resolveTrustChains(federation.options({ entityId: leaf.id, maxDepth: 1 }))

    assert.strictEqual(trustChains.length, 0)
    assert.ok(!federation.requested.includes(`${trustAnchor.id}/.well-known/openid-federation`))
  })

  it('should reject a failed response and accept a content-type with parameters', async () => {
    const configuration = federation.responses.get(`${intermediate.id}/.well-known/openid-federation`)
    federation.serve(`${intermediate.id}/.well-known/openid-federation`, configuration?.body ?? '', 500)

    const failed = await resolveTrustChainsWithFailures(federation.options({ entityId: leaf.id }))
    assert.strictEqual(failed.trustChains.length, 0)
    assert.match(failed.failures[0]?.reason ?? '', /failed with status 500/)

    federation.serve(
      `${intermediate.id}/.well-known/openid-federation`,
      configuration?.body ?? '',
      200,
      'application/entity-statement+jwt; charset=utf-8'
    )
    const trustChains = await resolveTrustChains(federation.options({ entityId: leaf.id }))
    assert.strictEqual(trustChains.length, 1)
  })

  // Section 3.2: "If the metadata_policy Claim is present, the Entity Statement MUST be a Subordinate Statement."
  it('should reject an entity configuration with metadata_policy', async () => {
    await federation.addEntity({
      ...leaf,
      claims: { metadata_policy: { openid_credential_issuer: { credential_issuer: { essential: true } } } },
    })

    const { trustChains, failures } = await resolveTrustChainsWithFailures(federation.options({ entityId: leaf.id }))

    assert.strictEqual(trustChains.length, 0)
    assert.match(failures[0]?.reason ?? '', /contains metadata_policy, which only subordinate statements may contain/)
  })

  // Section 3.2: "If the constraints Claim is present, the Entity Statement MUST be a Subordinate Statement."
  it('should reject an entity configuration with constraints', async () => {
    await federation.addEntity({ ...intermediate, claims: { constraints: { max_path_length: 1 } } })

    const { trustChains, failures } = await resolveTrustChainsWithFailures(federation.options({ entityId: leaf.id }))

    assert.strictEqual(trustChains.length, 0)
    assert.match(failures[0]?.reason ?? '', /contains constraints, which only subordinate statements may contain/)
  })

  // Section 3.1.2 authority_hints: "Its value MUST contain the Entity Identifiers of its Immediate Superiors and MUST
  // NOT be the empty array []."
  it('should reject an entity configuration with an empty authority_hints array', async () => {
    await federation.addEntity({ ...leaf, authorityHints: [] })

    const { trustChains, failures } = await resolveTrustChainsWithFailures(federation.options({ entityId: leaf.id }))

    assert.strictEqual(trustChains.length, 0)
    assert.match(failures[0]?.reason ?? '', /has an empty authority_hints array/)
  })

  // Section 3.2: "If the authority_hints Claim is present, the Entity Statement MUST be an Entity Configuration."
  it('should reject a subordinate statement with authority_hints', async () => {
    await federation.addStatement({
      issuer: intermediate,
      subject: leaf,
      claims: { authority_hints: [trustAnchor.id] },
    })

    const { trustChains, failures } = await resolveTrustChainsWithFailures(federation.options({ entityId: leaf.id }))

    assert.strictEqual(trustChains.length, 0)
    assert.match(failures[0]?.reason ?? '', /contains authority_hints, which only entity configurations may contain/)
  })

  // Section 3.1.3 metadata_policy_crit: "When included its value MUST NOT be the empty array []."
  it('should reject a subordinate statement with an empty metadata_policy_crit array', async () => {
    await federation.addStatement({ issuer: intermediate, subject: leaf, claims: { metadata_policy_crit: [] } })

    const { trustChains, failures } = await resolveTrustChainsWithFailures(federation.options({ entityId: leaf.id }))

    assert.strictEqual(trustChains.length, 0)
    assert.match(failures[0]?.reason ?? '', /has an empty metadata_policy_crit array/)
  })

  // Section 6.1.3.1.5 subset_of: "If the metadata parameter is present, it is assigned the intersection between the
  // values of the operator and the metadata parameter."
  it('should resolve a chain whose policy checks a metadata parameter the leaf does not have', async () => {
    await federation.addStatement({
      issuer: trustAnchor,
      subject: intermediate,
      claims: {
        metadata_policy: {
          openid_credential_issuer: {
            authorization_servers: { subset_of: ['https://as.example.org'] },
            display: { superset_of: ['x'] },
            credential_issuer: { one_of: [leaf.id] },
          },
        },
      },
    })

    const { trustChains, failures } = await resolveTrustChainsWithFailures(federation.options({ entityId: leaf.id }))

    assert.deepStrictEqual(failures, [])
    assert.deepStrictEqual(trustChains[0]?.resolvedLeafMetadata?.openid_credential_issuer, {
      credential_issuer: leaf.id,
    })
  })

  // Section 6.1.4.2: "for every Entity Type metadata and metadata parameter for which a corresponding metadata
  // parameter policy is present, the included policy operators MUST be applied"
  it('should not add an entity type the leaf metadata does not have', async () => {
    await federation.addStatement({
      issuer: trustAnchor,
      subject: intermediate,
      claims: {
        metadata_policy: {
          openid_relying_party: {
            contacts: { add: ['ops@ta.example.org'] },
            client_name: { default: 'RP' },
            subject_type: { value: 'pairwise' },
          },
        },
      },
    })

    const [trustChain] = await resolveTrustChains(federation.options({ entityId: leaf.id }))

    assert.deepStrictEqual(Object.keys(trustChain?.resolvedLeafMetadata ?? {}).sort(), [
      'federation_entity',
      'openid_credential_issuer',
    ])
  })

  // Section 6.1.3.1.1 value: "MAY be combined with subset_of, in which case the values of value MUST be a subset of the
  // values of subset_of."
  it('should resolve a chain whose merged policy combines value of the trust anchor with subset_of of the intermediate', async () => {
    await federation.addStatement({
      issuer: trustAnchor,
      subject: intermediate,
      claims: {
        metadata_policy: { openid_credential_issuer: { authorization_servers: { value: ['https://as.example.org'] } } },
      },
    })
    await federation.addStatement({
      issuer: intermediate,
      subject: leaf,
      claims: {
        metadata_policy: {
          openid_credential_issuer: {
            authorization_servers: { subset_of: ['https://as.example.org', 'https://as2.example.org'] },
          },
        },
      },
    })

    const { trustChains, failures } = await resolveTrustChainsWithFailures(federation.options({ entityId: leaf.id }))

    assert.deepStrictEqual(failures, [])
    assert.deepStrictEqual(
      (trustChains[0]?.resolvedLeafMetadata?.openid_credential_issuer as Record<string, unknown> | undefined)
        ?.authorization_servers,
      ['https://as.example.org']
    )
  })

  // Section 3.1.3 metadata_policy_crit: "If any of the listed policy operators are not understood and supported, then
  // the Subordinate Statement and thus the Trust Chain that includes it MUST be considered invalid."
  it('should reject a subordinate statement that requires a policy operator that is not supported', async () => {
    await federation.addStatement({
      issuer: trustAnchor,
      subject: intermediate,
      claims: { metadata_policy_crit: ['regexp'] },
    })

    const { trustChains, failures } = await resolveTrustChainsWithFailures(federation.options({ entityId: leaf.id }))

    assert.strictEqual(trustChains.length, 0)
    assert.match(failures[0]?.reason ?? '', /requires policy operators that are not supported: regexp/)
  })

  // Section 3.2: "If the source_endpoint Claim is present, the Entity Statement MUST be a Subordinate Statement."
  it('should reject an entity configuration with source_endpoint', async () => {
    await federation.addEntity({ ...leaf, claims: { source_endpoint: `${intermediate.id}/fetch` } })

    const { trustChains, failures } = await resolveTrustChainsWithFailures(federation.options({ entityId: leaf.id }))

    assert.strictEqual(trustChains.length, 0)
    assert.match(failures[0]?.reason ?? '', /contains source_endpoint, which only subordinate statements may contain/)
  })

  // Section 3.1.1 metadata: "When metadata is used in a Subordinate Statement, it applies only to those Entity Types
  // that are present in the subject's Entity Configuration."
  it('should not add an entity type from the metadata of the subordinate statement', async () => {
    await federation.addStatement({
      issuer: intermediate,
      subject: leaf,
      claims: {
        metadata: {
          openid_credential_issuer: { display: [{ name: 'Issuer' }] },
          openid_provider: { issuer: leaf.id },
        },
      },
    })

    const [trustChain] = await resolveTrustChains(federation.options({ entityId: leaf.id }))

    assert.deepStrictEqual(Object.keys(trustChain?.resolvedLeafMetadata ?? {}).sort(), [
      'federation_entity',
      'openid_credential_issuer',
    ])
    assert.deepStrictEqual(trustChain?.resolvedLeafMetadata?.openid_credential_issuer, {
      credential_issuer: leaf.id,
      display: [{ name: 'Issuer' }],
    })
  })
})
