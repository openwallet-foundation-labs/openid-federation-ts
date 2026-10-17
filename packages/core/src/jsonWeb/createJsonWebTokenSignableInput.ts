import { Buffer } from 'buffer'
import { base64ToBase64URL, stringifyJwtPart } from '../utils/encoding'

/**
 *
 * Converts a JSON header and payload into a byte array which can be used to verify and sign a JWT
 *
 */
export const createJwtSignableInput = (header: Record<string, unknown>, payload: Record<string, unknown>) => {
  if (Object.keys(header).length === 0) {
    throw new Error('Can not create JWT with an empty header')
  }

  if (Object.keys(payload).length === 0) {
    throw new Error('Can not create JWT with an empty payload')
  }

  const encodedHeader = base64ToBase64URL(Buffer.from(stringifyJwtPart(header)).toString('base64'))
  const encodedPayload = base64ToBase64URL(Buffer.from(stringifyJwtPart(payload)).toString('base64'))

  const toBeSignedString = `${encodedHeader}.${encodedPayload}`

  return new Uint8Array(Buffer.from(toBeSignedString))
}
