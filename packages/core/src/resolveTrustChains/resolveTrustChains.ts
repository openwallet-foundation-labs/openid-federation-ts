import { type EntityConfigurationClaims, fetchEntityConfigurationChains } from '../entityConfiguration'
import { type EntityStatementChain, fetchEntityStatementChain } from '../entityStatement'
import { OpenIdFederationError } from '../error/OpenIdFederationError'
import { PolicyErrorStage } from '../error/PolicyErrorStage'
import type { VerifyCallback } from '../utils'
import { tryCatch } from '../utils/tryCatch'
import {
  PolicyOperatorMergeError,
  PolicyValidationError,
  applyMetadataPolicyToMetadata,
  combineMetadataPolicies,
} from './policies'
import { mergeMetadata } from './policies/utils'

type Options = {
  verifyJwtCallback: VerifyCallback
  entityId: string
  trustAnchorEntityIds: Array<string>
}

export type TrustChain = {
  /**
   * Later this will give us the ability to provide the failed chains to the caller
   */
  valid: true

  chain: EntityStatementChain
  /**
   * The raw leaf entity configuration before the policy is applied.
   * So the metadata is not valid yet.
   */
  rawLeafEntityConfiguration: EntityConfigurationClaims
  /**
   * The resolved leaf metadata after the policy is applied and the metadata is merged with the superior entity's metadata.
   * This should be used to
   */
  resolvedLeafMetadata: EntityConfigurationClaims['metadata']
  trustAnchorEntityConfiguration: EntityConfigurationClaims
}

// TODO: Think about how we make this more open for debugging. Because when something goes wrong now in the policies it will be skipped but you can't really see what went wrong.

/**
 * Resolves the trust chains for the given entityId and trust anchor entityIds.
 *
 * @param options - The options for the trust chain resolution.
 * @returns A promise that resolves to an array of trust chains. (The first item in the trust chain is the leaf entity configuration, the last item is the trust anchor entity configuration)
 */
export const resolveTrustChains = async (options: Options): Promise<Array<TrustChain>> => {
  const { entityId, trustAnchorEntityIds, verifyJwtCallback } = options

  const now = new Date()

  const entityConfigurationChains = await fetchEntityConfigurationChains({
    leafEntityId: entityId,
    trustAnchorEntityIds,
    verifyJwtCallback,
  })

  const trustChains: Array<TrustChain> = []

  for (const entityConfigurationChain of entityConfigurationChains) {
    // The last item in the chain is the trust anchor's entity configuration
    const entityStatementChain = await fetchEntityStatementChain({
      entityConfigurations: entityConfigurationChain,
      verifyJwtCallback,
    })
    if (entityStatementChain.length === 0) continue

    if (entityStatementChain.some((statement) => statement.exp < now)) {
      // Skip expired chains
      // TODO: Think about how we want to share this conclusion with the caller
      continue
    }

    const leafEntityConfiguration = entityConfigurationChain[0]

    if (entityStatementChain.length === 1) {
      // When there is only one statement, we can assume that the leaf is also the trust anchor

      trustChains.push({
        valid: true,
        chain: entityStatementChain,
        trustAnchorEntityConfiguration: leafEntityConfiguration,
        rawLeafEntityConfiguration: leafEntityConfiguration,
        resolvedLeafMetadata: leafEntityConfiguration.metadata,
      })
      continue
    }

    const statementsWithoutLeaf = entityStatementChain.slice(0, -1)
    const combinedPolicyResult = tryCatch(() =>
      combineMetadataPolicies({
        statements: statementsWithoutLeaf,
      })
    )
    if (!combinedPolicyResult.success) {
      // TODO: In this function we can make conclusions they all now continue but at some point they should be reflected back to the caller
      if (combinedPolicyResult.error instanceof PolicyOperatorMergeError) {
        // When some operators can't be merged, we can declare the chain invalid
        // TODO: Think about how we want to share this conclusion with the caller
        continue
      }
      if (OpenIdFederationError.isMetadataPolicyCritError(combinedPolicyResult.error)) {
        // When the error is a metadata_policy_crit error, we can declare the chain invalid
        // TODO: Think about how we want to share this conclusion with the caller
        continue
      }

      // An unexpected error occurred while combining the policies
      // TODO: Think about how we want to share this conclusion with the caller
      continue
    }
    const { mergedPolicy } = combinedPolicyResult.value

    // When the superior entity has a metadata in it's statement we need to merge that first with the leaf metadata. Before applying the policy
    const superiorEntityStatement = statementsWithoutLeaf[0]
    const mergedLeafMetadata = mergeMetadata(
      leafEntityConfiguration.metadata ?? {},
      superiorEntityStatement?.metadata ?? {}
    )

    const policyApplyResult = tryCatch(() =>
      applyMetadataPolicyToMetadata({
        leafMetadata: mergedLeafMetadata,
        policyMetadata: mergedPolicy,
      })
    )
    if (!policyApplyResult.success) {
      // TODO: In this function we can make conclusions they all now continue but at some point they should be reflected back to the caller
      if (policyApplyResult.error instanceof PolicyValidationError) {
        // When the policy validation fails on the leaf metadata, we can declare the chain invalid
        // TODO: Think about how we want to share this conclusion with the caller
        continue
      }

      // An unexpected error occurred while applying the policy
      // TODO: Think about how we want to share this conclusion with the caller
      continue
    }
    const { resolvedLeafMetadata } = policyApplyResult.value

    const trustAnchorEntityConfiguration = entityConfigurationChain[entityConfigurationChain.length - 1]
    if (!trustAnchorEntityConfiguration)
      // Should never fail
      throw new OpenIdFederationError(PolicyErrorStage.Validation, 'No trust anchor entity configuration found')

    trustChains.push({
      valid: true,
      chain: entityStatementChain,
      trustAnchorEntityConfiguration,
      rawLeafEntityConfiguration: leafEntityConfiguration,
      resolvedLeafMetadata: resolvedLeafMetadata,
    })
  }

  return trustChains
}
