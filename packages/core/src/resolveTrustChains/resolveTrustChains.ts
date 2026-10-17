import type { EntityConfigurationClaims } from '../entityConfiguration'
import { entityConfigurationJwtSchema } from '../entityConfiguration/entityConfigurationJwt'
import type { EntityStatementChain, EntityStatementClaims } from '../entityStatement'
import { entityStatementJwtSchema } from '../entityStatement/entityStatementJwt'
import { OpenIdFederationError } from '../error/OpenIdFederationError'
import { PolicyErrorStage } from '../error/PolicyErrorStage'
import type { JsonWebKeySetOptions } from '../jsonWeb'
import { verifyJwtSignature } from '../jsonWeb/verifyJsonWebToken'
import type { Metadata } from '../metadata'
import { type FetchCallback, type VerifyCallback, addPaths, fetcher, isSameEntityId } from '../utils'
import { validate } from '../utils/validate'
import { applyMetadataPolicyToMetadata, combineMetadataPolicies } from './policies'
import { mergeMetadata } from './policies/utils'

export type TrustAnchor = {
  entityId: string
  /**
   * The federation keys of the trust anchor, obtained out of band. When given, the trust anchor's entity
   * configuration must be signed with one of them. Without them, the entity configuration fetched from the
   * trust anchor's well-known URL is trusted on its own signature.
   */
  jwks?: JsonWebKeySetOptions
}

export type ResolveTrustChainsOptions = {
  verifyJwtCallback: VerifyCallback
  entityId: string
  /**
   * @deprecated use `trustAnchors`
   */
  trustAnchorEntityIds?: Array<string>
  trustAnchors?: Array<TrustAnchor>
  /**
   * Used for every request. Pass one that applies your outbound request policy (allowed hosts, timeouts,
   * response size), as entity configurations name the URLs that are fetched.
   *
   * @default global.fetch
   */
  fetchCallback?: FetchCallback
  /**
   * @default new Date()
   */
  currentDate?: Date
  /**
   * Allowed clock difference for `iat` and `exp`.
   *
   * @default 0
   */
  clockSkewSeconds?: number
  /**
   * Maximum number of superiors followed from the leaf, including the trust anchor.
   *
   * @default 8
   */
  maxDepth?: number
  /**
   * Maximum number of requests (entity configurations and subordinate statements) for one resolution. It also bounds
   * the number of entities visited while following authority hints, as an entity reached on several paths is
   * visited once per path.
   *
   * @default 64
   */
  maxRequests?: number
  /**
   * Maximum number of `authority_hints` followed per entity. Duplicates are ignored.
   *
   * @default 10
   */
  maxAuthorityHints?: number
  /**
   * Claims listed in `crit` that the caller understands. A statement whose `crit` lists another claim is rejected.
   *
   * @default []
   */
  understoodCriticalClaims?: Array<string>
}

export type TrustChain = {
  valid: true

  /**
   * The subordinate statements, leaf side first, followed by the trust anchor's entity configuration.
   * When the leaf is a trust anchor, only its entity configuration.
   */
  chain: EntityStatementChain
  /**
   * The trust chain as defined in {@link https://openid.net/specs/openid-federation-1_0.html#section-4 | Section 4}:
   * the leaf's entity configuration, the subordinate statements and the trust anchor's entity configuration, as compact JWTs.
   * When the leaf is a trust anchor, only its entity configuration.
   */
  jwtChain: Array<string>
  /**
   * The raw leaf entity configuration before the policy is applied.
   * So the metadata is not valid yet.
   */
  rawLeafEntityConfiguration: EntityConfigurationClaims
  /**
   * The resolved leaf metadata after the policy is applied and the metadata is merged with the superior entity's metadata.
   */
  resolvedLeafMetadata: EntityConfigurationClaims['metadata']
  trustAnchorEntityConfiguration: EntityConfigurationClaims
  /**
   * The earliest `exp` of all statements in the chain. The chain must not be used after it.
   */
  expiresAt: Date
}

export type TrustChainFailure = {
  /**
   * The entities of the failed path, leaf first.
   */
  entityIds: Array<string>
  reason: string
  cause?: unknown
}

export type TrustChainResolution = {
  trustChains: Array<TrustChain>
  failures: Array<TrustChainFailure>
}

type FetchedEntityConfiguration = { jwt: string; claims: EntityConfigurationClaims }

const ENTITY_STATEMENT_CONTENT_TYPE = 'application/entity-statement+jwt'

const fail = (message: string) => new OpenIdFederationError(PolicyErrorStage.Validation, message)

const reasonOf = (error: unknown) => (error instanceof Error && error.message ? error.message : String(error))

/**
 * Resolves the trust chains from the given entity to the given trust anchors and validates them as described in
 * {@link https://openid.net/specs/openid-federation-1_0.html#section-10 | Section 10}.
 *
 * Every entity configuration and subordinate statement is checked for its signature, `iat`, `exp` and `crit`. An
 * entity configuration must be about the requested entity and signed with a key its superior's subordinate statement
 * lists. A subordinate statement must be issued by the superior about the subject. `max_path_length` and
 * `allowed_entity_types` constraints are applied, then the metadata policies. Chains with `naming_constraints` are
 * rejected, as they are not evaluated. Trust marks are not verified.
 *
 * Paths that fail are returned in `failures` with the reason.
 */
export const resolveTrustChainsWithFailures = async (
  options: ResolveTrustChainsOptions
): Promise<TrustChainResolution> => {
  const {
    entityId,
    verifyJwtCallback,
    fetchCallback,
    clockSkewSeconds = 0,
    maxDepth = 8,
    maxRequests = 64,
    maxAuthorityHints = 10,
    understoodCriticalClaims = [],
  } = options
  const now = options.currentDate ?? new Date()

  const trustAnchors: Array<TrustAnchor> = [
    ...(options.trustAnchors ?? []),
    ...(options.trustAnchorEntityIds ?? []).map((id) => ({ entityId: id })),
  ]
  if (trustAnchors.length === 0) {
    throw fail('Cannot resolve a trust chain for zero trust anchors')
  }
  const findTrustAnchor = (id: string) => trustAnchors.find((anchor) => isSameEntityId(anchor.entityId, id))

  const failures: Array<TrustChainFailure> = []
  let requests = 0
  let visits = 0
  const get = async (url: string, searchParams?: Record<string, string>) => {
    requests++
    if (requests > maxRequests) {
      throw fail(`trust chain resolution exceeded ${maxRequests} requests`)
    }
    return fetcher.get({ url, searchParams, requiredContentType: ENTITY_STATEMENT_CONTENT_TYPE, fetchCallback })
  }

  const assertCurrent = (statement: EntityStatementClaims) => {
    const skewMs = clockSkewSeconds * 1000
    if (!Number.isFinite(statement.iat.getTime()) || !Number.isFinite(statement.exp.getTime())) {
      throw fail(`statement about '${statement.sub}' issued by '${statement.iss}' has an invalid iat or exp`)
    }
    if (statement.iat.getTime() > now.getTime() + skewMs) {
      throw fail(`statement about '${statement.sub}' issued by '${statement.iss}' has an iat in the future`)
    }
    if (statement.exp.getTime() <= now.getTime() - skewMs) {
      throw fail(`statement about '${statement.sub}' issued by '${statement.iss}' has expired`)
    }
    const notUnderstood = (statement.crit ?? []).filter((claim) => !understoodCriticalClaims.includes(claim))
    if (notUnderstood.length > 0) {
      throw fail(
        `statement about '${statement.sub}' issued by '${statement.iss}' has critical claims that are not understood: ${notUnderstood.join(', ')}`
      )
    }
  }

  // An entity reached through several superiors is fetched once per resolution
  const entityConfigurations = new Map<string, Promise<FetchedEntityConfiguration>>()
  const fetchEntityConfiguration = (id: string) => {
    let pending = entityConfigurations.get(id)
    if (!pending) {
      pending = (async () => {
        const jwt = await get(addPaths(id, '.well-known', 'openid-federation'))
        const { claims } = validate({
          schema: entityConfigurationJwtSchema,
          data: jwt,
          errorMessage: `entity configuration of '${id}' is invalid`,
        })
        if (!isSameEntityId(claims.sub, id)) {
          throw fail(`entity configuration fetched for '${id}' has subject '${claims.sub}'`)
        }
        await verifyJwtSignature({ jwt, verifyJwtCallback })
        assertCurrent(claims)
        return { jwt, claims }
      })()
      entityConfigurations.set(id, pending)
    }
    return pending
  }

  /**
   * Follows the authority hints up to the trust anchors and returns every path of entity configurations,
   * leaf first, that ends at a trust anchor.
   */
  const discover = async (
    id: string,
    path: Array<FetchedEntityConfiguration>
  ): Promise<Array<Array<FetchedEntityConfiguration>>> => {
    // Without this bound, repeated or converging authority hints would enumerate exponentially many paths
    visits++
    if (visits > maxRequests) {
      throw fail(`trust chain resolution exceeded ${maxRequests} entity visits`)
    }
    const configuration = await fetchEntityConfiguration(id)
    const localPath = [...path, configuration]
    const paths: Array<Array<FetchedEntityConfiguration>> = []

    if (findTrustAnchor(configuration.claims.sub)) {
      paths.push(localPath)
    }

    // The path holds the leaf and its superiors
    if (localPath.length > maxDepth) return paths

    const superiors: Array<string> = []
    for (const superior of configuration.claims.authority_hints ?? []) {
      if (superiors.length === maxAuthorityHints) break
      if (localPath.some((entry) => isSameEntityId(entry.claims.sub, superior))) continue
      if (superiors.some((entry) => isSameEntityId(entry, superior))) continue
      superiors.push(superior)
    }
    const results = await Promise.allSettled(superiors.map((superior) => discover(superior, localPath)))
    results.forEach((result, index) => {
      if (result.status === 'fulfilled') {
        paths.push(...result.value)
      } else {
        failures.push({
          entityIds: [...localPath.map((entry) => entry.claims.sub), superiors[index] as string],
          reason: reasonOf(result.reason),
          cause: result.reason,
        })
      }
    })

    return paths
  }

  const validatePath = async (path: Array<FetchedEntityConfiguration>): Promise<TrustChain> => {
    const leaf = path[0] as FetchedEntityConfiguration
    const trustAnchorConfiguration = path[path.length - 1] as FetchedEntityConfiguration
    const trustAnchor = findTrustAnchor(trustAnchorConfiguration.claims.sub) as TrustAnchor

    if (trustAnchor.jwks) {
      await verifyJwtSignature({
        jwt: trustAnchorConfiguration.jwt,
        jwks: trustAnchor.jwks,
        verifyJwtCallback,
      }).catch((error: unknown) => {
        throw fail(
          `entity configuration of trust anchor '${trustAnchor.entityId}' is not signed with a configured key: ${reasonOf(error)}`
        )
      })
    }

    const statements: Array<{ jwt: string; claims: EntityStatementClaims }> = []
    for (let index = 0; index < path.length - 1; index++) {
      const subject = path[index] as FetchedEntityConfiguration
      const superior = path[index + 1] as FetchedEntityConfiguration

      const fetchEndpoint = superior.claims.metadata?.federation_entity?.federation_fetch_endpoint
      if (!fetchEndpoint) {
        throw fail(`'${superior.claims.sub}' has no federation_fetch_endpoint`)
      }

      const jwt = await get(fetchEndpoint, { sub: subject.claims.sub })
      const { claims } = validate({
        schema: entityStatementJwtSchema,
        data: jwt,
        errorMessage: `subordinate statement about '${subject.claims.sub}' issued by '${superior.claims.sub}' is invalid`,
      })
      if (!isSameEntityId(claims.iss, superior.claims.sub) || !isSameEntityId(claims.sub, subject.claims.sub)) {
        throw fail(
          `subordinate statement requested from '${superior.claims.sub}' about '${subject.claims.sub}' has issuer '${claims.iss}' and subject '${claims.sub}'`
        )
      }
      assertCurrent(claims)

      // Naming constraints are not evaluated, so a chain that sets them is rejected instead of ignoring them
      if (claims.constraints?.naming_constraints) {
        throw fail(`'${superior.claims.sub}' sets naming_constraints, which are not supported`)
      }

      // The statement at this index is issued `index + 1` levels above the leaf, so `index` intermediates are between them
      const maxPathLength = claims.constraints?.max_path_length
      if (maxPathLength !== undefined && index > maxPathLength) {
        throw fail(`'${superior.claims.sub}' allows ${maxPathLength} intermediates, the chain has ${index}`)
      }

      statements.push({ jwt, claims })
    }

    // Section 10.2: each statement validates with a key the next one lists. The leaf's entity configuration with the keys
    // of the statement about it, each subordinate statement with the keys its superior's statement lists for the
    // superior, and the last one with the trust anchor's keys.
    const signers = statements.length > 0 ? [leaf, ...statements] : []
    for (let index = 0; index < signers.length; index++) {
      const signed = signers[index] as { jwt: string; claims: EntityStatementClaims }
      const next = statements[index]
      const jwks = next ? next.claims.jwks : trustAnchorConfiguration.claims.jwks
      await verifyJwtSignature({ jwt: signed.jwt, jwks, verifyJwtCallback }).catch((error: unknown) => {
        throw fail(
          `statement about '${signed.claims.sub}' issued by '${signed.claims.iss}' is not signed with a key listed by '${next ? next.claims.iss : trustAnchorConfiguration.claims.sub}': ${reasonOf(error)}`
        )
      })
    }

    const expiresAt = new Date(Math.min(...[...path, ...statements].map((statement) => statement.claims.exp.getTime())))

    if (statements.length === 0) {
      return {
        valid: true,
        chain: [leaf.claims],
        jwtChain: [leaf.jwt],
        rawLeafEntityConfiguration: leaf.claims,
        resolvedLeafMetadata: leaf.claims.metadata,
        trustAnchorEntityConfiguration: leaf.claims,
        expiresAt,
      }
    }

    const statementClaims = statements.map((statement) => statement.claims)
    const { mergedPolicy } = combineMetadataPolicies({ statements: statementClaims })

    // Section 6: the superior's metadata is applied first, then entity types the constraints do not allow are removed,
    // then the metadata policies are applied
    const mergedLeafMetadata = restrictEntityTypes(
      mergeMetadata(leaf.claims.metadata ?? {}, statementClaims[0]?.metadata ?? {}),
      statementClaims
    )
    const { resolvedLeafMetadata } = applyMetadataPolicyToMetadata({
      leafMetadata: mergedLeafMetadata,
      policyMetadata: mergedPolicy,
    })

    return {
      valid: true,
      chain: [...statementClaims, trustAnchorConfiguration.claims],
      jwtChain: [leaf.jwt, ...statements.map((statement) => statement.jwt), trustAnchorConfiguration.jwt],
      rawLeafEntityConfiguration: leaf.claims,
      // Again after the policies, which could otherwise add a removed entity type back
      resolvedLeafMetadata: restrictEntityTypes(resolvedLeafMetadata, statementClaims),
      trustAnchorEntityConfiguration: trustAnchorConfiguration.claims,
      expiresAt,
    }
  }

  let paths: Array<Array<FetchedEntityConfiguration>>
  try {
    paths = await discover(entityId, [])
  } catch (error) {
    // The leaf's own entity configuration could not be used
    return { trustChains: [], failures: [{ entityIds: [entityId], reason: reasonOf(error), cause: error }] }
  }

  const trustChains: Array<TrustChain> = []
  for (const path of paths) {
    try {
      trustChains.push(await validatePath(path))
    } catch (error) {
      failures.push({ entityIds: path.map((entry) => entry.claims.sub), reason: reasonOf(error), cause: error })
    }
  }

  return { trustChains, failures }
}

/**
 * Removes the entity types that `allowed_entity_types` constraints of the chain do not allow. `federation_entity` is always allowed.
 */
const restrictEntityTypes = (metadata: Metadata, statements: Array<EntityStatementClaims>): Metadata => {
  const allowed = statements
    .map((statement) => statement.constraints?.allowed_entity_types)
    .filter((types): types is Array<string> => types !== undefined)
  if (allowed.length === 0) return metadata

  return Object.fromEntries(
    Object.entries(metadata).filter(
      ([entityType]) => entityType === 'federation_entity' || allowed.every((types) => types.includes(entityType))
    )
  ) as Metadata
}

/**
 * Resolves the trust chains for the given entityId and trust anchors. See {@link resolveTrustChainsWithFailures},
 * which also returns why paths failed.
 *
 * @returns the valid trust chains
 */
export const resolveTrustChains = async (options: ResolveTrustChainsOptions): Promise<Array<TrustChain>> =>
  (await resolveTrustChainsWithFailures(options)).trustChains
