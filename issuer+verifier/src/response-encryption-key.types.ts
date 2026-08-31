import { z } from 'zod'
import { jwkSchema } from './jwk.type'

/**
 * A key pair the Verifier uses to receive encrypted Authorization Responses
 * (OID4VP 1.1 Section 8.3). The public JWK is published in
 * `client_metadata.jwks`; the private JWK never leaves the Verifier.
 */
export const responseEncryptionKeyEntrySchema = z.object({
  /** The JWE `alg` the key is dedicated to, such as `HPKE-0` or `ECDH-ES`. */
  declaredAlg: z.string(),
  publicKey: jwkSchema,
  privateKey: jwkSchema,
})

export type ResponseEncryptionKeyEntry = z.infer<typeof responseEncryptionKeyEntrySchema>
export const ResponseEncryptionKeyEntry = (value?: unknown) =>
  responseEncryptionKeyEntrySchema.parse(value)
ResponseEncryptionKeyEntry.schema = responseEncryptionKeyEntrySchema
