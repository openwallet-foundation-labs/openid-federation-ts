export function base64ToBase64URL(base64: string) {
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '')
}

/**
 *
 * JSON serialization for JWT parts. `Date` values become NumericDate values (seconds since the epoch, RFC 7519),
 * instead of the ISO strings `JSON.stringify` would produce.
 *
 */
export function stringifyJwtPart(value: Record<string, unknown>) {
  return JSON.stringify(value, function (this: Record<string, unknown>, key, serialized) {
    const original = this[key]
    return original instanceof Date ? Math.floor(original.getTime() / 1000) : serialized
  })
}
