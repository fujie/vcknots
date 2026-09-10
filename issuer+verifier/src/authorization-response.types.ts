import { z } from 'zod'
import { DeepPartialUnknown } from './type.utils'

// https://openid.net/specs/openid-4-verifiable-presentations-1_0-ID2.html#section-6.1
const vpTokenSchema = z.string().or(z.record(z.string(), z.unknown()))
const authorizationResponseSchema = z.object({
  vp_token: vpTokenSchema.or(z.array(vpTokenSchema)),
  state: z.string().optional(),
})
export type AuthorizationResponse = z.infer<typeof authorizationResponseSchema>
export const AuthorizationResponse = (value?: DeepPartialUnknown<AuthorizationResponse>) =>
  authorizationResponseSchema.parse(value)
AuthorizationResponse.schema = authorizationResponseSchema

/**
 * The `vp_token` of OpenID4VP 1.0 Section 8.1: an object whose keys are
 * Credential Query ids from the DCQL query and whose values are non-empty arrays
 * of Presentations.
 *
 * The looser schema above stays for the Presentation Exchange responses this
 * library still accepts, where `vp_token` is a single Presentation. This one is
 * what a 1.0 response has to satisfy. Neither carries
 * `presentation_submission`, which 1.0 removed.
 */
const presentationSchema = z.union([z.string(), z.looseObject({})])

const dcqlVpTokenSchema = z
  .record(
    z.string().regex(/^[A-Za-z0-9_-]+$/, 'Credential Query ids are alphanumeric, _ or -'),
    z.array(presentationSchema).nonempty()
  )
  .refine((token) => Object.keys(token).length > 0, {
    message: 'vp_token must contain at least one entry',
  })

export type DcqlVpToken = z.infer<typeof dcqlVpTokenSchema>
export const DcqlVpToken = (value?: unknown) => dcqlVpTokenSchema.parse(value)
DcqlVpToken.schema = dcqlVpTokenSchema

/**
 * Whether a `vp_token` uses the 1.0 object form rather than a single
 * Presentation, so a caller can tell a DCQL response from a Presentation
 * Exchange one before deciding how to verify it.
 */
export const isDcqlVpToken = (vpToken: AuthorizationResponse['vp_token']): vpToken is DcqlVpToken =>
  dcqlVpTokenSchema.safeParse(vpToken).success
