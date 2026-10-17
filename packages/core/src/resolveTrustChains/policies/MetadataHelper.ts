import type { Metadata } from '../../metadata'
import type { MetadataPolicy } from '../../metadata/metadataPolicy'

export class MetadataHelper {
  private leafMetadata: Record<string, Record<string, unknown>>

  public constructor(leafMetadata: Metadata) {
    this.leafMetadata = leafMetadata as Record<string, Record<string, unknown>>
  }

  public hasProperty(service: string, property: string) {
    return this.leafMetadata[service]?.[property] !== undefined
  }

  public getPropertyValue<T = unknown>(service: string, property: string): T | undefined {
    const serviceBlock = this.leafMetadata[service]
    if (serviceBlock === undefined) return undefined
    const propertyValue = serviceBlock[property]
    if (propertyValue === undefined) return undefined
    return propertyValue as T
  }

  public setPropertyValue(service: string, property: string, value: unknown) {
    this.leafMetadata = {
      ...this.leafMetadata,
      [service]: {
        ...this.leafMetadata[service], // optionally add a helper method to get a value or an empty object otherwise
        [property]: value,
      },
    }
  }

  public deleteProperty(service: string, property: string) {
    const serviceBlock = this.leafMetadata[service]
    if (serviceBlock === undefined) return

    this.leafMetadata = {
      ...this.leafMetadata,
      [service]: {
        ...this.leafMetadata[service],
      },
    }

    delete this.leafMetadata[service][property]

    // When the service block is empty we can delete the service block
    if (Object.keys(serviceBlock).length === 0) {
      delete this.leafMetadata[service]
    }
  }

  public asMetadata(): Metadata {
    return this.leafMetadata
  }

  public asMetadataPolicy(): MetadataPolicy {
    return this.leafMetadata
  }
}
