import { err } from './errors/vcknots.error'
import { Aead, generateKemKeyPair, HpkeSuite, Kdf, Kem, kemKeyType, open, seal } from './hpke'
import { Jwk } from './jwk.type'

/**
 * The JOSE binding of HPKE, "Use of Hybrid Public Key Encryption (HPKE) with
 * JSON Web Encryption (JWE)" (draft-ietf-jose-hpke-encrypt), restricted to the
 * Integrated Encryption key management mode.
 *
 * Integrated Encryption is the mode OID4VP 1.1 Section 8.3.1 builds on. In it
 * the JWE Encrypted Key carries the HPKE encapsulated secret, no separate
 * content encryption algorithm ("enc") is involved, and the JWE Initialization
 * Vector and Authentication Tag are the empty octet sequence.
 */

/** A JWE `alg` value using HPKE Integrated Encryption. */
export type HpkeAlgorithm = 'HPKE-0' | 'HPKE-1' | 'HPKE-2' | 'HPKE-3' | 'HPKE-4' | 'HPKE-7'

/**
 * The Integrated Encryption algorithms this library implements. HPKE-5 and
 * HPKE-6 are defined by the draft but use DHKEM(X448). Node.js can perform it,
 * but the Go wallet in this repository cannot — the Go standard library has no
 * X448 — so implementing it here would only produce responses this project
 * could not itself generate.
 */
const suites: Record<HpkeAlgorithm, HpkeSuite> = {
  'HPKE-0': { kem: Kem.P256_HKDF_SHA256, kdf: Kdf.HKDF_SHA256, aead: Aead.AES_128_GCM },
  'HPKE-1': { kem: Kem.P384_HKDF_SHA384, kdf: Kdf.HKDF_SHA384, aead: Aead.AES_256_GCM },
  'HPKE-2': { kem: Kem.P521_HKDF_SHA512, kdf: Kdf.HKDF_SHA512, aead: Aead.AES_256_GCM },
  'HPKE-3': { kem: Kem.X25519_HKDF_SHA256, kdf: Kdf.HKDF_SHA256, aead: Aead.AES_128_GCM },
  'HPKE-4': { kem: Kem.X25519_HKDF_SHA256, kdf: Kdf.HKDF_SHA256, aead: Aead.CHACHA20_POLY1305 },
  'HPKE-7': { kem: Kem.P256_HKDF_SHA256, kdf: Kdf.HKDF_SHA256, aead: Aead.AES_256_GCM },
}

/**
 * The supported Integrated Encryption algorithms, most preferred first. HPKE-0
 * leads because it is the interoperability baseline in OID4VP deployments.
 */
export const supportedHpkeAlgorithms: HpkeAlgorithm[] = [
  'HPKE-0',
  'HPKE-7',
  'HPKE-3',
  'HPKE-4',
  'HPKE-1',
  'HPKE-2',
]

/** Every `alg` value the draft defines, including the ones not implemented here. */
const allHpkeAlgorithms = [
  'HPKE-0',
  'HPKE-1',
  'HPKE-2',
  'HPKE-3',
  'HPKE-4',
  'HPKE-5',
  'HPKE-6',
  'HPKE-7',
  'HPKE-0-KE',
  'HPKE-1-KE',
  'HPKE-2-KE',
  'HPKE-3-KE',
  'HPKE-5-KE',
  'HPKE-7-KE',
]

/** Whether an `alg` value names an Integrated Encryption algorithm this library implements. */
export const isSupportedHpkeAlgorithm = (alg: unknown): alg is HpkeAlgorithm =>
  typeof alg === 'string' && alg in suites

/**
 * Whether an `alg` value names any JOSE HPKE algorithm, including the ones this
 * library does not implement. Callers use it to tell an HPKE response apart from
 * an ECDH-ES one, so that an unimplemented HPKE algorithm surfaces as an
 * explicit error rather than being mistaken for something else.
 */
export const isHpkeAlgorithm = (alg: unknown): boolean =>
  typeof alg === 'string' && allHpkeAlgorithms.includes(alg)

/** The JWE protected header of a JOSE HPKE token. */
export type HpkeProtectedHeader = {
  alg: string
  kid?: string
  [parameter: string]: unknown
}

/**
 * Generates a key pair for an Integrated Encryption algorithm and returns the
 * public JWK a Verifier publishes alongside the private JWK it keeps.
 */
export const generateHpkeKeyPair = (
  alg: HpkeAlgorithm,
  kid?: string
): { publicKey: Jwk; privateKey: Jwk } => {
  const { publicKey, privateKey } = generateKemKeyPair(suiteFor(alg).kem)
  return {
    // OID4VP Section 8.3 requires the `alg` member on response encryption keys
    // and reads `use` to tell encryption keys from signing keys.
    publicKey: { ...publicKey, alg, use: 'enc', ...(kid ? { kid } : {}) },
    privateKey: { ...privateKey, alg, use: 'enc', ...(kid ? { kid } : {}) },
  }
}

/** The JWK key type and curve an Integrated Encryption algorithm requires. */
export const hpkeKeyType = (alg: HpkeAlgorithm) => kemKeyType(suiteFor(alg).kem)

/**
 * Encrypts a payload to a recipient and returns a JWE Compact Serialization
 * built with HPKE Integrated Encryption.
 *
 * `info` becomes the HPKE info parameter. OID4VP 1.1 Section 8.3.1 puts the
 * session_info structure there so that decryption fails closed when the session
 * the response belongs to does not match.
 */
export const encryptHpkeJwe = (
  alg: HpkeAlgorithm,
  recipientPublicKey: Jwk,
  header: Record<string, unknown>,
  info: Uint8Array,
  plaintext: Uint8Array
): string => {
  if ('enc' in header) {
    throw err('invalid_encryption_parameters', {
      message: 'The "enc" header parameter must not be present with Integrated Encryption.',
    })
  }

  const protectedHeader = Buffer.from(JSON.stringify({ ...header, alg })).toString('base64url')

  // Step 15 of draft-ietf-jose-hpke-encrypt Section 7.1: with the Compact
  // Serialization the Additional Authenticated Data is the encoded protected
  // header, which is what binds the header to the ciphertext.
  const { enc, ciphertext } = seal(
    suiteFor(alg),
    recipientPublicKey,
    info,
    Buffer.from(protectedHeader),
    plaintext
  )

  // The JWE Initialization Vector and the JWE Authentication Tag are the empty
  // octet sequence, so the third and fifth components stay empty.
  return [
    protectedHeader,
    enc.toString('base64url'),
    '',
    ciphertext.toString('base64url'),
    '',
  ].join('.')
}

/**
 * Reverses {@link encryptHpkeJwe}, returning the JWE protected header alongside
 * the plaintext so the caller can inspect parameters such as `kid`.
 *
 * The algorithm is taken from the header rather than from the caller, but a
 * recipient key on the wrong curve, a tampered header and a mismatched `info`
 * value all fail here instead of yielding a plaintext.
 */
export const decryptHpkeJwe = (
  compact: string,
  recipientPrivateKey: Jwk,
  info: Uint8Array
): { header: HpkeProtectedHeader; plaintext: Buffer } => {
  const parts = compact.split('.')
  if (parts.length !== 5) {
    throw err('invalid_encryption_parameters', {
      message: `Expected 5 JWE compact serialization parts, got ${parts.length}.`,
    })
  }
  const [protectedHeader, encodedEnc, initializationVector, encodedCiphertext, authenticationTag] =
    parts

  if (initializationVector !== '' || authenticationTag !== '') {
    throw err('invalid_encryption_parameters', {
      message:
        'The JWE initialization vector and authentication tag must be empty with Integrated Encryption.',
    })
  }

  const header = parseProtectedHeader(protectedHeader)
  if (!isSupportedHpkeAlgorithm(header.alg)) {
    throw err('invalid_encryption_parameters', {
      message: `Unsupported JOSE HPKE algorithm "${header.alg}".`,
    })
  }
  if ('enc' in header) {
    throw err('invalid_encryption_parameters', {
      message: 'The "enc" header parameter must not be present with Integrated Encryption.',
    })
  }

  const plaintext = open(
    suiteFor(header.alg),
    recipientPrivateKey,
    Buffer.from(encodedEnc, 'base64url'),
    info,
    Buffer.from(protectedHeader),
    Buffer.from(encodedCiphertext, 'base64url')
  )

  return { header, plaintext }
}

/**
 * Reads the JWE protected header without decrypting, so that a recipient can
 * look up the key named by `kid` before it has one to decrypt with.
 */
export const readHpkeProtectedHeader = (compact: string): HpkeProtectedHeader => {
  const [protectedHeader] = compact.split('.')
  return parseProtectedHeader(protectedHeader)
}

const parseProtectedHeader = (encoded: string): HpkeProtectedHeader => {
  let header: unknown
  try {
    header = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8'))
  } catch (_error) {
    throw err('invalid_encryption_parameters', {
      message: 'The JWE protected header is not valid JSON.',
    })
  }
  if (typeof header !== 'object' || header === null || typeof (header as Jwk).alg !== 'string') {
    throw err('invalid_encryption_parameters', {
      message: 'The JWE protected header carries no "alg" parameter.',
    })
  }
  return header as HpkeProtectedHeader
}

const suiteFor = (alg: HpkeAlgorithm): HpkeSuite => {
  const suite = suites[alg]
  if (!suite) {
    throw err('invalid_encryption_parameters', {
      message: `Unsupported JOSE HPKE algorithm "${alg}".`,
    })
  }
  return suite
}
