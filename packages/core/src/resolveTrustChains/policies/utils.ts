import { immutable, objectToEntries } from '../../utils/data'

import type { Metadata } from '../../metadata'
import { MetadataHelper } from './MetadataHelper'

export type PolicyValue = boolean | string | number

export type PolicyValueArray = PolicyValue[]

export function intersect(operator1: PolicyValueArray, operator2: PolicyValueArray) {
  const set1 = new Set(operator1)
  const set2 = new Set(operator2)
  const intersection = [...set1].filter((value) => set2.has(value))
  return intersection
}

export function union(operator1: PolicyValueArray, operator2: PolicyValueArray) {
  return [...new Set([...operator1, ...operator2])]
}

/**
 * Merges the metadata of the leaf entity with the metadata of the superior entity statement
 * The superior always has the highest priority
 */
export function mergeMetadata(leafConfigMetadata: Metadata, superiorEntityStatement: Metadata): Metadata {
  const mergedLeafMetadata = new MetadataHelper(immutable(leafConfigMetadata))

  for (const [entityType, entityConfigMetadata] of objectToEntries(superiorEntityStatement)) {
    // Section 3.1.1: it applies only to the entity types present in the subject's entity configuration
    if (!mergedLeafMetadata.hasEntityType(String(entityType))) continue
    for (const [key, value] of objectToEntries((entityConfigMetadata ?? {}) as Record<string, unknown>)) {
      mergedLeafMetadata.setPropertyValue(String(entityType), String(key), value)
    }
  }

  return mergedLeafMetadata.asMetadata()
}
