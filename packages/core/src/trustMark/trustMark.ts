import { z } from 'zod'
import { jsonWebTokenSchema } from '../jsonWeb'
import { dateSchema } from '../utils'

/**
 *
 * Adds `trust_mark_type` from the pre-final `id` claim, so entity configurations of both
 * the final specification and earlier drafts can be read.
 *
 */
const withTrustMarkType = <T extends { trust_mark_type?: string; id?: string }>(
  value: T,
  ctx: z.RefinementCtx
): T & { trust_mark_type: string } => {
  const trustMarkType = value.trust_mark_type ?? value.id
  if (!trustMarkType) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      message: 'trust_mark_type is required',
      path: ['trust_mark_type'],
    })
    return z.NEVER
  }
  return { ...value, trust_mark_type: trustMarkType }
}

/**
 *
 * {@link https://openid.net/specs/openid-federation-1_0.html#section-7.1 | Trust Mark Claims}
 *
 */
export const trustMarkClaimsSchema = z
  .object({
    iss: z.string(),
    sub: z.string(),
    trust_mark_type: z.string().optional(),
    /**
     * @deprecated replaced by `trust_mark_type` in OpenID Federation 1.0
     */
    id: z.string().optional(),
    iat: dateSchema,
    exp: dateSchema.optional(),
    logo_uri: z.string().url().optional(),
    ref: z.string().url().optional(),
    delegation: z.string().optional(),
  })
  .passthrough()
  .transform(withTrustMarkType)

/**
 *
 * An entry of the `trust_marks` claim of an entity configuration
 *
 * {@link https://openid.net/specs/openid-federation-1_0.html#section-3.1.1 | trust_marks}
 *
 */
export const trustMarkSchema = z
  .object({
    trust_mark_type: z.string().optional(),
    /**
     * @deprecated replaced by `trust_mark_type` in OpenID Federation 1.0
     */
    id: z.string().optional(),
    trust_mark: jsonWebTokenSchema({
      claimsSchema: trustMarkClaimsSchema,
    }),
  })
  .transform(withTrustMarkType)
  .refine((entry) => entry.trust_mark_type === entry.trust_mark.claims.trust_mark_type, {
    message: 'trust_mark_type must be the trust_mark_type of the trust mark JWT',
    path: ['trust_mark_type'],
  })

export type TrustMark = z.output<typeof trustMarkSchema>
