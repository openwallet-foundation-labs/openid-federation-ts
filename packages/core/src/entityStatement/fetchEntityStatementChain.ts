import type { EntityConfigurationClaims } from '../entityConfiguration'
import { OpenIdFederationError } from '../error/OpenIdFederationError'
import { PolicyErrorStage } from '../error/PolicyErrorStage'
import type { FetchCallback, VerifyCallback } from '../utils'
import type { EntityStatementClaims } from './entityStatementClaims'
import { fetchEntityStatement } from './fetchEntityStatement'

export type FetchEntityStatementChainOptions = {
  entityConfigurations: Array<EntityConfigurationClaims>
  verifyJwtCallback: VerifyCallback
  fetchCallback?: FetchCallback
}

export type EntityStatementChain = Array<EntityStatementClaims>

export const fetchEntityStatementChain = async ({
  verifyJwtCallback,
  entityConfigurations,
  fetchCallback,
}: FetchEntityStatementChainOptions): Promise<EntityStatementChain> => {
  if (entityConfigurations.length === 0) {
    throw new OpenIdFederationError(
      PolicyErrorStage.Validation,
      'Cannot establish a statement chain for zero entity configurations'
    )
  }

  // Reverse the configurations as we have to fetch the entity configuration of the trust anchor first
  // A copy is done here as the reverse method  mutates in place
  const reversedConfigurations = [...entityConfigurations].reverse()

  const promises: Array<Promise<EntityStatementClaims>> = []

  for (let i = 0; i < reversedConfigurations.length; i++) {
    // Get the configuration of the issuer
    const configuration = reversedConfigurations[i]

    // Get the configuration of the subject, i.e. the next in the chain
    const subjectConfiguration = reversedConfigurations[i + 1]

    // If we have no subject configuration we have reached the leaf entity as the `configuration`
    if (!subjectConfiguration) continue

    const fetchEndpoint = configuration?.metadata?.federation_entity?.federation_fetch_endpoint

    if (!fetchEndpoint) {
      throw new OpenIdFederationError(
        PolicyErrorStage.Validation,
        `No fetch endpoint found for configuration for: '${configuration?.sub}'`
      )
    }

    promises.push(
      fetchEntityStatement({
        verifyJwtCallback,
        endpoint: fetchEndpoint,
        iss: configuration.iss,
        sub: subjectConfiguration.sub,
        issEntityConfiguration: configuration,
        fetchCallback,
      })
    )
  }

  // The trust anchors (i.e. the last item of the list) entity configuration will be used instead of a statement issued by a superior

  const trustAnchorEntityConfiguration = entityConfigurations[entityConfigurations.length - 1]
  // Should never happen because there will always be a trust anchor in a valid chain
  if (!trustAnchorEntityConfiguration) {
    throw new OpenIdFederationError(PolicyErrorStage.Validation, 'No trust anchor entity configuration found')
  }

  return [trustAnchorEntityConfiguration, ...(await Promise.all(promises))].reverse()
}
