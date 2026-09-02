import { z } from 'zod'
import { Dcql } from './dcql.type'
import { PresentationExchange } from './presentation-exchange.types'
import { DeepPartialUnknown } from './type.utils'
import { commonReqSchema } from './request-object.types'

// https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.1
// https://openid.net/specs/openid-4-verifiable-presentations-1_0-ID2.html#name-authorization-request
// https://openid.net/specs/openid-4-verifiable-presentations-1_0-ID2.html#section-5-10

const commonAuthzRequestSchema = commonReqSchema.extend({
  response_type: z.union([z.literal('vp_token'), z.literal('id_token'), z.string()]).optional(),
  /**
   * @deprecated Removed in OpenID4VP 1.0, which carries the Client Identifier
   * Prefix inside `client_id` instead (for example
   * `x509_san_dns:verifier.example.com`). Still emitted and accepted for
   * compatibility with draft 24 Wallets; behaviour is driven by the prefix in
   * `client_id`, never by this parameter.
   */
  client_id_scheme: z.string().optional(),
  client_metadata_uri: z.string().optional(),
  response_mode: z.enum(['direct_post', 'direct_post.jwt', 'query', 'fragment']).optional(),
  request_uri: z.string().url().optional(),
})

const authorizationRequestPeSchema = commonAuthzRequestSchema
  .and(PresentationExchange.schema)
  .superRefine((data, ctx) => {
    if (!data.request_uri && !data.nonce && !data.response_type && !data.presentation_definition) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message:
          'When request_uri is not present, response_type or nonce or presentation_definition is required',
        path: ['nonce', 'response_type', 'presentation_definition'],
      })
    }
  })
export type AuthorizationRequestPe = z.infer<typeof authorizationRequestPeSchema>
export const AuthorizationRequestPe = (value?: DeepPartialUnknown<AuthorizationRequestPe>) =>
  authorizationRequestPeSchema.parse(value)
AuthorizationRequestPe.schema = authorizationRequestPeSchema

const authorizationRequestDcqlSchema = commonAuthzRequestSchema
  .and(Dcql.schema)
  .superRefine((data, ctx) => {
    if (!data.request_uri && !data.nonce && !data.response_type) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'When request_uri is not present, response_type or nonce is required',
        path: ['nonce', 'response_type'],
      })
    }
  })
export type AuthorizationRequestDcql = z.infer<typeof authorizationRequestDcqlSchema>
export const AuthorizationRequestDcql = (value?: DeepPartialUnknown<AuthorizationRequestDcql>) =>
  authorizationRequestDcqlSchema.parse(value)
AuthorizationRequestDcql.schema = authorizationRequestDcqlSchema

const authorizationRequestSchema = authorizationRequestDcqlSchema.or(authorizationRequestPeSchema)
export type AuthorizationRequest = z.infer<typeof authorizationRequestSchema>
export const AuthorizationRequest = (value?: DeepPartialUnknown<AuthorizationRequest>) =>
  authorizationRequestSchema.parse(value)
AuthorizationRequest.schema = authorizationRequestSchema
