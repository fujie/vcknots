import {
  CipherGCMTypes,
  createCipheriv,
  createDecipheriv,
  createHmac,
  createPrivateKey,
  createPublicKey,
  diffieHellman,
  generateKeyPairSync,
  KeyObject,
} from 'node:crypto'
import { err } from './errors/vcknots.error'
import { Jwk } from './jwk.type'

/**
 * Hybrid Public Key Encryption (RFC 9180) in base mode: no pre-shared key and
 * no sender authentication.
 *
 * This is the primitive behind the JOSE HPKE binding that OID4VP 1.1
 * Section 8.3.1 uses to encrypt Authorization Responses. DHKEM(X448) is absent
 * even though Node.js could perform it: the Go wallet in this repository has no
 * X448 to pair with, so the suite is left out of both sides together.
 */

/** The version label that prefixes every labeled KDF input (RFC 9180 Section 4). */
const HPKE_VERSION = 'HPKE-v1'

/** mode_base: no PSK, no sender authentication (RFC 9180 Section 5.1). */
const MODE_BASE = 0x00

/** KEM identifiers from the IANA HPKE registry. */
export const Kem = {
  P256_HKDF_SHA256: 0x0010,
  P384_HKDF_SHA384: 0x0011,
  P521_HKDF_SHA512: 0x0012,
  X25519_HKDF_SHA256: 0x0020,
} as const
export type KemId = (typeof Kem)[keyof typeof Kem]

/** KDF identifiers from the IANA HPKE registry. */
export const Kdf = {
  HKDF_SHA256: 0x0001,
  HKDF_SHA384: 0x0002,
  HKDF_SHA512: 0x0003,
} as const
export type KdfId = (typeof Kdf)[keyof typeof Kdf]

/** AEAD identifiers from the IANA HPKE registry. */
export const Aead = {
  AES_128_GCM: 0x0001,
  AES_256_GCM: 0x0002,
  CHACHA20_POLY1305: 0x0003,
} as const
export type AeadId = (typeof Aead)[keyof typeof Aead]

/** An HPKE ciphersuite. In JOSE HPKE the `alg` header parameter names one. */
export type HpkeSuite = {
  kem: KemId
  kdf: KdfId
  aead: AeadId
}

type KemParams = {
  /** The KDF baked into the KEM, independent of the suite's KDF. */
  kdf: KdfId
  /** Nsecret, the length of the KEM shared secret. */
  secretLength: number
  /** The JWK key type and curve the KEM operates on. */
  kty: 'EC' | 'OKP'
  crv: string
  /** The byte length of a single coordinate on the curve. */
  coordinateLength: number
  /** The Node.js key generation parameters. */
  generate: () => { publicKey: KeyObject; privateKey: KeyObject }
}

const kemParams: Record<KemId, KemParams> = {
  [Kem.P256_HKDF_SHA256]: {
    kdf: Kdf.HKDF_SHA256,
    secretLength: 32,
    kty: 'EC',
    crv: 'P-256',
    coordinateLength: 32,
    generate: () => generateKeyPairSync('ec', { namedCurve: 'prime256v1' }),
  },
  [Kem.P384_HKDF_SHA384]: {
    kdf: Kdf.HKDF_SHA384,
    secretLength: 48,
    kty: 'EC',
    crv: 'P-384',
    coordinateLength: 48,
    generate: () => generateKeyPairSync('ec', { namedCurve: 'secp384r1' }),
  },
  [Kem.P521_HKDF_SHA512]: {
    kdf: Kdf.HKDF_SHA512,
    secretLength: 64,
    kty: 'EC',
    crv: 'P-521',
    coordinateLength: 66,
    generate: () => generateKeyPairSync('ec', { namedCurve: 'secp521r1' }),
  },
  [Kem.X25519_HKDF_SHA256]: {
    kdf: Kdf.HKDF_SHA256,
    secretLength: 32,
    kty: 'OKP',
    crv: 'X25519',
    coordinateLength: 32,
    generate: () => generateKeyPairSync('x25519'),
  },
}

const kdfHash: Record<KdfId, string> = {
  [Kdf.HKDF_SHA256]: 'sha256',
  [Kdf.HKDF_SHA384]: 'sha384',
  [Kdf.HKDF_SHA512]: 'sha512',
}

type AeadParams = {
  /**
   * The Node.js cipher name. It is typed as the GCM family because all three
   * AEADs expose the same authenticated-encryption interface, and the narrower
   * `createCipheriv` overloads that accept `authTagLength` are keyed on it.
   */
  cipher: CipherGCMTypes
  keyLength: number
  nonceLength: number
  tagLength: number
}

const aeadParams: Record<AeadId, AeadParams> = {
  [Aead.AES_128_GCM]: { cipher: 'aes-128-gcm', keyLength: 16, nonceLength: 12, tagLength: 16 },
  [Aead.AES_256_GCM]: { cipher: 'aes-256-gcm', keyLength: 32, nonceLength: 12, tagLength: 16 },
  [Aead.CHACHA20_POLY1305]: {
    cipher: 'chacha20-poly1305' as CipherGCMTypes,
    keyLength: 32,
    nonceLength: 12,
    tagLength: 16,
  },
}

/** The JWK key type and curve a KEM expects its keys to use. */
export const kemKeyType = (kem: KemId): { kty: 'EC' | 'OKP'; crv: string } => {
  const params = kemParams[kem]
  return { kty: params.kty, crv: params.crv }
}

/** Generates a key pair for a KEM and returns it as a public and a private JWK. */
export const generateKemKeyPair = (kem: KemId): { publicKey: Jwk; privateKey: Jwk } => {
  const { publicKey, privateKey } = kemParams[kem].generate()
  return {
    publicKey: publicKey.export({ format: 'jwk' }) as Jwk,
    privateKey: privateKey.export({ format: 'jwk' }) as Jwk,
  }
}

/**
 * Encrypts plaintext to a recipient in a single shot (RFC 9180 Section 6.1),
 * returning the encapsulated secret alongside the ciphertext.
 */
export const seal = (
  suite: HpkeSuite,
  recipientPublicKey: Jwk,
  info: Uint8Array,
  aad: Uint8Array,
  plaintext: Uint8Array
): { enc: Buffer; ciphertext: Buffer } => {
  const { sharedSecret, enc } = encapsulate(suite.kem, recipientPublicKey)
  const { key, nonce } = keySchedule(suite, sharedSecret, info)
  const params = aeadParams[suite.aead]

  const cipher = createCipheriv(params.cipher, key, nonce, {
    authTagLength: params.tagLength,
  })
  cipher.setAAD(Buffer.from(aad))
  const body = Buffer.concat([cipher.update(Buffer.from(plaintext)), cipher.final()])

  return { enc, ciphertext: Buffer.concat([body, cipher.getAuthTag()]) }
}

/**
 * Reverses {@link seal}. The info and aad values must match the ones the sender
 * used; anything else fails authentication rather than returning wrong data.
 */
export const open = (
  suite: HpkeSuite,
  recipientPrivateKey: Jwk,
  enc: Uint8Array,
  info: Uint8Array,
  aad: Uint8Array,
  ciphertext: Uint8Array
): Buffer => {
  const params = aeadParams[suite.aead]
  if (ciphertext.length < params.tagLength) {
    throw err('invalid_encryption_parameters', {
      message: 'The HPKE ciphertext is shorter than its authentication tag.',
    })
  }

  const sharedSecret = decapsulate(suite.kem, recipientPrivateKey, enc)
  const { key, nonce } = keySchedule(suite, sharedSecret, info)

  const body = Buffer.from(ciphertext.subarray(0, ciphertext.length - params.tagLength))
  const tag = Buffer.from(ciphertext.subarray(ciphertext.length - params.tagLength))

  const decipher = createDecipheriv(params.cipher, key, nonce, {
    authTagLength: params.tagLength,
  })
  decipher.setAAD(Buffer.from(aad))
  decipher.setAuthTag(tag)

  try {
    return Buffer.concat([decipher.update(body), decipher.final()])
  } catch (_error) {
    throw err('invalid_encryption_parameters', {
      message:
        'HPKE decryption failed. The key, the ciphertext or the bound context does not match.',
    })
  }
}

/** DHKEM Encap (RFC 9180 Section 4.1). */
const encapsulate = (kem: KemId, recipientPublicKey: Jwk) => {
  const params = kemParams[kem]
  const recipient = importPublicKey(kem, recipientPublicKey)

  const ephemeral = params.generate()
  const dh = diffieHellman({ privateKey: ephemeral.privateKey, publicKey: recipient })

  const enc = serializePublicKey(kem, ephemeral.publicKey.export({ format: 'jwk' }) as Jwk)
  const kemContext = Buffer.concat([enc, serializePublicKey(kem, recipientPublicKey)])

  return { sharedSecret: extractAndExpand(kem, dh, kemContext), enc }
}

/** DHKEM Decap (RFC 9180 Section 4.1). */
const decapsulate = (kem: KemId, recipientPrivateKey: Jwk, enc: Uint8Array) => {
  const recipient = importPrivateKey(kem, recipientPrivateKey)
  const ephemeral = deserializePublicKey(kem, enc)

  const dh = diffieHellman({ privateKey: recipient, publicKey: ephemeral })
  const kemContext = Buffer.concat([
    Buffer.from(enc),
    serializePublicKey(kem, publicPartOf(recipientPrivateKey)),
  ])

  return extractAndExpand(kem, dh, kemContext)
}

/** ExtractAndExpand, which derives the KEM shared secret (RFC 9180 Section 4.1). */
const extractAndExpand = (kem: KemId, dh: Buffer, kemContext: Buffer): Buffer => {
  const params = kemParams[kem]
  const suiteId = Buffer.concat([Buffer.from('KEM'), uint16(kem)])

  const eaePrk = labeledExtract(params.kdf, suiteId, Buffer.alloc(0), 'eae_prk', dh)
  return labeledExpand(
    params.kdf,
    suiteId,
    eaePrk,
    'shared_secret',
    kemContext,
    params.secretLength
  )
}

/**
 * The base-mode key schedule (RFC 9180 Section 5.1). Single-shot encryption
 * never advances the sequence number, so the base nonce is the nonce.
 */
const keySchedule = (suite: HpkeSuite, sharedSecret: Buffer, info: Uint8Array) => {
  const aead = aeadParams[suite.aead]
  const suiteId = Buffer.concat([
    Buffer.from('HPKE'),
    uint16(suite.kem),
    uint16(suite.kdf),
    uint16(suite.aead),
  ])

  const empty = Buffer.alloc(0)
  // mode_base prescribes an empty psk and an empty psk_id.
  const pskIdHash = labeledExtract(suite.kdf, suiteId, empty, 'psk_id_hash', empty)
  const infoHash = labeledExtract(suite.kdf, suiteId, empty, 'info_hash', Buffer.from(info))
  const context = Buffer.concat([Buffer.from([MODE_BASE]), pskIdHash, infoHash])

  const secret = labeledExtract(suite.kdf, suiteId, sharedSecret, 'secret', empty)

  return {
    key: labeledExpand(suite.kdf, suiteId, secret, 'key', context, aead.keyLength),
    nonce: labeledExpand(suite.kdf, suiteId, secret, 'base_nonce', context, aead.nonceLength),
  }
}

/** LabeledExtract (RFC 9180 Section 4). */
const labeledExtract = (
  kdf: KdfId,
  suiteId: Buffer,
  salt: Buffer,
  label: string,
  ikm: Buffer
): Buffer => {
  const labeledIkm = Buffer.concat([Buffer.from(HPKE_VERSION), suiteId, Buffer.from(label), ikm])
  return hkdfExtract(kdfHash[kdf], salt, labeledIkm)
}

/** LabeledExpand (RFC 9180 Section 4). */
const labeledExpand = (
  kdf: KdfId,
  suiteId: Buffer,
  prk: Buffer,
  label: string,
  info: Buffer,
  length: number
): Buffer => {
  const labeledInfo = Buffer.concat([
    uint16(length),
    Buffer.from(HPKE_VERSION),
    suiteId,
    Buffer.from(label),
    info,
  ])
  return hkdfExpand(kdfHash[kdf], prk, labeledInfo, length)
}

/**
 * HKDF-Extract (RFC 5869 Section 2.2). Node's `hkdfSync` fuses extract and
 * expand, but HPKE needs the pseudorandom key on its own.
 */
const hkdfExtract = (hash: string, salt: Buffer, ikm: Buffer): Buffer => {
  const hashLength = createHmac(hash, Buffer.alloc(0)).digest().length
  const key = salt.length > 0 ? salt : Buffer.alloc(hashLength)
  return createHmac(hash, key).update(ikm).digest()
}

/** HKDF-Expand (RFC 5869 Section 2.3). */
const hkdfExpand = (hash: string, prk: Buffer, info: Buffer, length: number): Buffer => {
  const hashLength = createHmac(hash, Buffer.alloc(0)).digest().length
  if (length > 255 * hashLength) {
    throw err('illegal_argument', { message: 'HKDF cannot expand to the requested length.' })
  }

  const blocks: Buffer[] = []
  let previous = Buffer.alloc(0)
  for (let counter = 1; Buffer.concat(blocks).length < length; counter++) {
    previous = createHmac(hash, prk)
      .update(Buffer.concat([previous, info, Buffer.from([counter])]))
      .digest()
    blocks.push(previous)
  }
  return Buffer.concat(blocks).subarray(0, length)
}

/** SerializePublicKey: the SEC 1 uncompressed point, or the raw X25519 key. */
const serializePublicKey = (kem: KemId, jwk: Jwk): Buffer => {
  const params = kemParams[kem]
  const x = decodeCoordinate(jwk.x, 'x', params.coordinateLength)

  if (params.kty === 'OKP') return x
  return Buffer.concat([
    Buffer.from([0x04]),
    x,
    decodeCoordinate(jwk.y, 'y', params.coordinateLength),
  ])
}

/** DeserializePublicKey, the inverse of {@link serializePublicKey}. */
const deserializePublicKey = (kem: KemId, encoded: Uint8Array): KeyObject => {
  const params = kemParams[kem]
  const bytes = Buffer.from(encoded)
  const encode = (value: Buffer) => value.toString('base64url')

  if (params.kty === 'OKP') {
    if (bytes.length !== params.coordinateLength) {
      throw err('invalid_encryption_parameters', {
        message: `The encapsulated secret is ${bytes.length} bytes, expected ${params.coordinateLength}.`,
      })
    }
    return importPublicKey(kem, { kty: 'OKP', crv: params.crv, x: encode(bytes) })
  }

  const expected = 1 + params.coordinateLength * 2
  if (bytes.length !== expected || bytes[0] !== 0x04) {
    throw err('invalid_encryption_parameters', {
      message: 'The encapsulated secret is not an uncompressed elliptic curve point.',
    })
  }
  return importPublicKey(kem, {
    kty: 'EC',
    crv: params.crv,
    x: encode(bytes.subarray(1, 1 + params.coordinateLength)),
    y: encode(bytes.subarray(1 + params.coordinateLength)),
  })
}

const importPublicKey = (kem: KemId, jwk: Jwk): KeyObject => {
  assertKeyMatchesKem(kem, jwk)
  try {
    return createPublicKey({ key: jwk as Record<string, unknown>, format: 'jwk' })
  } catch (error) {
    throw err('invalid_encryption_parameters', {
      message: `The HPKE public key could not be imported: ${error}`,
    })
  }
}

const importPrivateKey = (kem: KemId, jwk: Jwk): KeyObject => {
  assertKeyMatchesKem(kem, jwk)
  if (typeof jwk.d !== 'string' || jwk.d === '') {
    throw err('invalid_encryption_parameters', { message: 'The HPKE key holds no private part.' })
  }
  try {
    return createPrivateKey({ key: jwk as Record<string, unknown>, format: 'jwk' })
  } catch (error) {
    throw err('invalid_encryption_parameters', {
      message: `The HPKE private key could not be imported: ${error}`,
    })
  }
}

const assertKeyMatchesKem = (kem: KemId, jwk: Jwk) => {
  const params = kemParams[kem]
  if (jwk.kty !== params.kty || jwk.crv !== params.crv) {
    throw err('invalid_encryption_parameters', {
      message: `The HPKE key is ${jwk.kty}/${jwk.crv}, but the algorithm needs ${params.kty}/${params.crv}.`,
    })
  }
}

/** Drops the private members of a JWK, leaving the public key. */
const publicPartOf = (jwk: Jwk): Jwk => {
  const { d: _d, ...publicKey } = jwk
  return publicKey
}

const decodeCoordinate = (value: unknown, name: string, length: number): Buffer => {
  if (typeof value !== 'string' || value === '') {
    throw err('invalid_encryption_parameters', { message: `The JWK member "${name}" is missing.` })
  }
  const decoded = Buffer.from(value, 'base64url')
  if (decoded.length !== length) {
    throw err('invalid_encryption_parameters', {
      message: `The JWK member "${name}" is ${decoded.length} bytes, expected ${length}.`,
    })
  }
  return decoded
}

const uint16 = (value: number): Buffer => {
  const encoded = Buffer.alloc(2)
  encoded.writeUInt16BE(value)
  return encoded
}
