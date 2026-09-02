import { z } from 'zod'

// https://openid.net/specs/openid-4-verifiable-presentations-1_0-24.html#name-defined-client-identifier-s
/**
 * The Client Identifier Prefixes of OpenID4VP 1.0 Section 5.9. The type keeps
 * its historical name because it is part of the published API; the concept the
 * specification defines is the prefix carried inside `client_id`, not the
 * separate `client_id_scheme` request parameter that 1.0 removed.
 */
export const ClientIdSchemeSchema = z.enum([
  'redirect_uri',
  'https',
  'did',
  'verifier_attestation',
  'x509_san_dns',
  'x509_san_uri',
  'web-origin',
])
// https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html#name-defined-client-identifier-p
// clientIdPrefixSchema = z.enum(['redirect_uri', 'openid_federation', 'decentralized_identifier', 'x509_san_dns', 'x509_hash', 'origin'])

export type ClientIdScheme = z.infer<typeof ClientIdSchemeSchema>
export const ClientIdScheme = (value?: unknown) => ClientIdSchemeSchema.parse(value)
ClientIdScheme.schema = ClientIdSchemeSchema
export type ClientIdentifier = `${ClientIdScheme}:${string}`
const schemeAlternation = ClientIdSchemeSchema.options
  .map((s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'))
  .join('|')
const re = new RegExp(`^(?:${schemeAlternation}):.+$`)

const ClientIdentifierSchema = z
  .string()
  .regex(re, 'Invalid client identifier')
  .transform((v): ClientIdentifier => v as ClientIdentifier)
export const ClientIdentifier = (value?: unknown): ClientIdentifier =>
  ClientIdentifierSchema.parse(value)
ClientIdentifier.schema = ClientIdentifierSchema
