/**
 *
 * A date with whole seconds, as JWT NumericDate values have no milliseconds.
 *
 */
export const dateInSeconds = (offsetMs = 0) => new Date(Math.floor((Date.now() + offsetMs) / 1000) * 1000)
