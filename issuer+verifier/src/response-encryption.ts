import { compactDecrypt, importJWK } from 'jose'
import { err } from './errors/vcknots.error'
import { decryptHpkeJwe, isHpkeAlgorithm, isSupportedHpkeAlgorithm } from './jose-hpke'
import { Jwk } from './jwk.type'

/**
 * Encrypted Authorization Responses, OID4VP 1.1 Section 8.3.
 *
 * The Verifier publishes encryption keys in `client_metadata.jwks`, asks for a
 * `.jwt` Response Mode, and receives the Authorization Response as a single
 * `response` parameter holding an unsigned, encrypted JWT.
 */

/**
 * The fixed ASCII labels that open the session_info structure of Section 8.3.1.
 * Which one applies depends on how the presentation was invoked.
 */
const SESSION_INFO_PREFIX_REDIRECT = 'OpenID4VP-si'
const SESSION_INFO_PREFIX_DC_API = 'OpenID4VPDCAPI-si'

/** The 0xFF byte that delimits the session_info fields. */
const SESSION_INFO_SEPARATOR = 0xff

const buildSessionInfo = (prefix: string, ...fields: string[]): Buffer =>
  Buffer.concat([
    Buffer.from(prefix, 'ascii'),
    ...fields.flatMap((field) => [
      Buffer.from([SESSION_INFO_SEPARATOR]),
      Buffer.from(field, 'ascii'),
    ]),
  ])

/**
 * The session_info structure for the Response Modes invoked through redirects,
 * `direct_post.jwt` among them:
 *
 * ```
 * session_info = ASCII("OpenID4VP-si") || BYTE(255) || ASCII(clientId) ||
 *                BYTE(255) || ASCII(nonce) || BYTE(255) || ASCII(responseUri)
 * ```
 *
 * `clientId` is the client_id request parameter including its Client Identifier
 * Prefix, and `responseUri` is whichever of response_uri or redirect_uri the
 * Response Mode uses.
 */
export const redirectSessionInfo = (clientId: string, nonce: string, responseUri: string): Buffer =>
  buildSessionInfo(SESSION_INFO_PREFIX_REDIRECT, clientId, nonce, responseUri)

/**
 * The session_info structure for the `dc_api.jwt` Response Mode:
 *
 * ```
 * session_info = ASCII("OpenID4VPDCAPI-si") || BYTE(255) || ASCII(origin) ||
 *                BYTE(255) || ASCII(nonce)
 * ```
 *
 * `origin` is the Origin of the request and must not carry the `origin:` prefix.
 */
export const dcApiSessionInfo = (origin: string, nonce: string): Buffer =>
  buildSessionInfo(SESSION_INFO_PREFIX_DC_API, origin, nonce)

/**
 * The session an encrypted Authorization Response belongs to.
 *
 * The Verifier reconstructs this from the request parameters it issued rather
 * than from anything the Wallet sends back, which is what makes HPKE decryption
 * fail closed on a response captured from a different session.
 */
export type ResponseEncryptionSession =
  | {
      responseMode: 'direct_post.jwt'
      /** The client_id request parameter, including its Client Identifier Prefix. */
      clientId: string
      nonce: string
      /** The response_uri, or the redirect_uri when the Response Mode uses one. */
      responseUri: string
    }
  | {
      responseMode: 'dc_api.jwt'
      /** The Origin of the request, without the `origin:` prefix. */
      origin: string
      nonce: string
    }

/** The session_info structure that matches a session's Response Mode. */
export const sessionInfoFor = (session: ResponseEncryptionSession): Buffer =>
  session.responseMode === 'dc_api.jwt'
    ? dcApiSessionInfo(session.origin, session.nonce)
    : redirectSessionInfo(session.clientId, session.nonce, session.responseUri)

/** The JWE `alg` values usable for response encryption alongside JOSE HPKE. */
const supportedKeyAgreementAlgorithms = [
  'ECDH-ES',
  'ECDH-ES+A128KW',
  'ECDH-ES+A192KW',
  'ECDH-ES+A256KW',
]

/** Whether an `alg` value can encrypt an Authorization Response to this library. */
export const isSupportedResponseEncryptionAlgorithm = (alg: unknown): alg is string =>
  isSupportedHpkeAlgorithm(alg) ||
  (typeof alg === 'string' && supportedKeyAgreementAlgorithms.includes(alg))

/**
 * Decrypts the `response` parameter of an encrypted Authorization Response and
 * returns its payload, which carries the response parameters as top-level JSON
 * members.
 *
 * `privateKeys` are the Verifier's response encryption keys. The `kid` header
 * parameter selects among them when present, as Section 8.3 requires the Wallet
 * to echo it; otherwise every key whose algorithm matches is tried.
 */
export const decryptAuthorizationResponse = async (
  response: string,
  privateKeys: Jwk[],
  session: ResponseEncryptionSession
): Promise<Record<string, unknown>> => {
  if (typeof response !== 'string' || response.trim() === '') {
    throw err('invalid_request', { message: 'The response parameter is empty.' })
  }
  if (privateKeys.length === 0) {
    throw err('authz_verifier_key_not_found', {
      message: 'The verifier holds no response encryption key.',
    })
  }

  const header = readProtectedHeader(response)
  const alg = header.alg
  if (!isSupportedResponseEncryptionAlgorithm(alg)) {
    throw err('invalid_encryption_parameters', {
      message: isHpkeAlgorithm(alg)
        ? `The response uses JOSE HPKE algorithm "${alg}", which this library does not implement.`
        : `The response uses unsupported encryption algorithm "${String(alg)}".`,
    })
  }

  const candidates = selectDecryptionKeys(privateKeys, alg, header.kid)
  if (candidates.length === 0) {
    throw err('authz_verifier_key_not_found', {
      message: header.kid
        ? `No verifier response encryption key matches kid "${header.kid}" and alg "${alg}".`
        : `No verifier response encryption key matches alg "${alg}".`,
    })
  }

  const sessionInfo = sessionInfoFor(session)
  const failures: string[] = []

  for (const key of candidates) {
    try {
      const payload = isSupportedHpkeAlgorithm(alg)
        ? decryptHpkeJwe(response, key, sessionInfo).plaintext
        : (await compactDecrypt(response, await importPrivateKey(key, alg))).plaintext
      return parsePayload(payload)
    } catch (error) {
      failures.push(`${key.kid ?? '(no kid)'}: ${error instanceof Error ? error.message : error}`)
    }
  }

  throw err('invalid_encryption_parameters', {
    message: `The authorization response could not be decrypted. ${failures.join('; ')}`,
  })
}

/**
 * Reads the `alg` and `kid` of a JWE compact serialization without decrypting,
 * so that the recipient can look up the key before it has one to decrypt with.
 */
const readProtectedHeader = (compact: string): { alg?: unknown; kid?: string } => {
  const parts = compact.split('.')
  if (parts.length !== 5) {
    throw err('invalid_encryption_parameters', {
      message: `Expected 5 JWE compact serialization parts, got ${parts.length}.`,
    })
  }
  try {
    const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'))
    return {
      alg: header?.alg,
      kid: typeof header?.kid === 'string' ? header.kid : undefined,
    }
  } catch (_error) {
    throw err('invalid_encryption_parameters', {
      message: 'The JWE protected header is not valid JSON.',
    })
  }
}

/**
 * Narrows the Verifier's keys to those that could have encrypted this response.
 * A key that pins a different `alg` is meant for a different algorithm, so it is
 * skipped rather than tried and reported as a decryption failure.
 */
const selectDecryptionKeys = (privateKeys: Jwk[], alg: string, kid?: string): Jwk[] =>
  privateKeys.filter((key) => {
    if (kid !== undefined && key.kid !== kid) return false
    return typeof key.alg !== 'string' || key.alg === alg
  })

const importPrivateKey = async (key: Jwk, alg: string) => {
  const imported = await importJWK(key as Parameters<typeof importJWK>[0], alg)
  if (imported instanceof Uint8Array) {
    throw err('invalid_encryption_parameters', {
      message: 'A symmetric key cannot decrypt an authorization response.',
    })
  }
  return imported
}

const parsePayload = (payload: Uint8Array): Record<string, unknown> => {
  let parsed: unknown
  try {
    parsed = JSON.parse(Buffer.from(payload).toString('utf8'))
  } catch (_error) {
    throw err('invalid_request', {
      message: 'The decrypted authorization response is not valid JSON.',
    })
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw err('invalid_request', {
      message: 'The decrypted authorization response is not a JSON object.',
    })
  }
  return parsed as Record<string, unknown>
}
