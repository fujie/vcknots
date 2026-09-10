import { z } from 'zod'

// https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html#name-verifier-metadata-client-me
// https://www.rfc-editor.org/rfc/rfc7591.html#section-2
//
// This is the Verifier's stored configuration, which is a superset of what a
// request may carry. OpenID4VP 1.0 Section 5.1 allows only `jwks`,
// `encrypted_response_enc_values_supported` and `vp_formats_supported` in the
// `client_metadata` request parameter, and requires a Wallet to ignore
// everything else; `toClientMetadata` below projects this object down to those.
export const verifierMetadataSchema = z.object({
  redirect_uris: z.array(z.string()).optional(),
  token_endpoint_auth_method: z
    .enum(['none', 'client_secret_post', 'client_secret_basic'])
    .optional(),
  grant_types: z
    .enum([
      'authorization_code',
      'implicit',
      'password',
      'client_credentials',
      'refresh_token',
      'urn:ietf:params:oauth:grant-type:jwt-bearer',
      'urn:ietf:params:oauth:grant-type:saml2-bearer',
    ])
    .optional(),
  client_name: z.string().optional(),
  client_uri: z.string().optional(),
  logo_uri: z.string().optional(),
  scope: z.string().optional(),
  contacts: z.array(z.string()).optional(),
  tos_uri: z.string().url().optional(),
  policy_uri: z.string().url().optional(),
  jwks_uri: z.string().url().optional(),
  jwks: z
    .object({
      keys: z.array(
        z
          .object({
            e: z.string().optional(),
            n: z.string().optional(),
            kty: z.string().optional(),
            x: z.string().optional(),
            y: z.string().optional(),
            crv: z.string().optional(),
            alg: z.string().optional(),
            kid: z.string().optional(),
            use: z.string().optional(),
          })
          .and(z.record(z.string(), z.unknown()))
          .optional()
      ),
    })
    .optional(),
  software_id: z.string().optional(),
  software_version: z.string().optional(),
  response_types: z.enum(['code', 'token']).optional(),
  /**
   * The Credential Formats this Verifier supports, keyed by Credential Format
   * Identifier (Section 11.1). Each value carries format-specific members —
   * `alg_values` for `jwt_vc_json`, `sd-jwt_alg_values` and `kb-jwt_alg_values`
   * for `dc+sd-jwt` (Appendix B).
   */
  vp_formats_supported: z.record(z.string(), z.unknown()),
  /**
   * The alg this Verifier signs Request Objects with. This is local
   * configuration, not a request parameter: OpenID4VP 1.0 has no
   * `authorization_signed_response_alg`, and a Wallet ignores it, so it is
   * never sent as part of `client_metadata`.
   */
  authorization_signed_response_alg: z.string().optional(),
  /**
   * The JWE `enc` values the Verifier accepts for an encrypted Authorization
   * Response (Section 8.3). It has no effect when JOSE HPKE Integrated
   * Encryption is used, since that mode has no separate content encryption
   * algorithm.
   */
  encrypted_response_enc_values_supported: z.array(z.string()).nonempty().optional(),
})
export type VerifierMetadata = z.infer<typeof verifierMetadataSchema>
export const VerifierMetadata = (value?: {
  redirect_uris?: string[]
  token_endpoint_auth_method?: string
  grant_types?: string
  client_name?: string
  client_uri?: string
  logo_uri?: string
  scope?: string
  contacts?: string[]
  tos_uri?: string
  policy_uri?: string
  jwks_uri?: string
  jwks?: {
    keys?: {
      e?: string
      n?: string
      kty?: string
      x?: string
      y?: string
      crv?: string
      alg?: string
      kid?: string
      use?: string
    }[]
  }
  software_id?: string
  software_version?: string
  response_types?: string[]
  vp_formats_supported?: Record<string, unknown>
  authorization_signed_response_alg?: string
  encrypted_response_enc_values_supported?: string[]
}) => verifierMetadataSchema.parse(value)
VerifierMetadata.schema = verifierMetadataSchema

/**
 * The Verifier metadata a request may carry.
 *
 * OpenID4VP 1.0 Section 5.1 names exactly three members for the
 * `client_metadata` request parameter — `jwks`,
 * `encrypted_response_enc_values_supported` and `vp_formats_supported` — and
 * states that a Wallet MUST ignore anything else unless a profile defines it.
 * Sending the whole stored configuration would put RFC 7591 registration
 * members and local settings on the wire for a Wallet to discard, so the
 * request carries only these.
 */
export type ClientMetadata = {
  vp_formats_supported: Record<string, unknown>
  jwks?: VerifierMetadata['jwks']
  encrypted_response_enc_values_supported?: string[]
}

export const toClientMetadata = (metadata: VerifierMetadata): ClientMetadata => ({
  vp_formats_supported: metadata.vp_formats_supported,
  ...(metadata.jwks ? { jwks: metadata.jwks } : {}),
  ...(metadata.encrypted_response_enc_values_supported
    ? {
        encrypted_response_enc_values_supported: [
          ...metadata.encrypted_response_enc_values_supported,
        ],
      }
    : {}),
})
