import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, it } from 'node:test'
import {
  decryptHpkeJwe,
  encryptHpkeJwe,
  generateHpkeKeyPair,
  HpkeAlgorithm,
  isHpkeAlgorithm,
  isSupportedHpkeAlgorithm,
  readHpkeProtectedHeader,
  supportedHpkeAlgorithms,
} from '../src/jose-hpke'
import { Jwk } from '../src/jwk.type'

/** One entry of the test vector file published with draft-ietf-jose-hpke-encrypt. */
type JoseVector = {
  alg: string
  jwk: Jwk
  compact: string
}

const vectors: JoseVector[] = JSON.parse(
  readFileSync(join(import.meta.dirname, 'testdata', 'jose-vectors.json'), 'utf8')
)

describe('JOSE HPKE', () => {
  describe('draft-ietf-jose-hpke-encrypt test vectors', () => {
    const covered = new Set<string>()

    for (const vector of vectors) {
      if (!isSupportedHpkeAlgorithm(vector.alg)) continue
      covered.add(vector.alg)

      it(`decrypts the ${vector.alg} compact serialization`, () => {
        // The compact examples carry no HPKE info; the flattened ones use a JWE
        // AAD, which the Compact Serialization cannot express.
        const { header, plaintext } = decryptHpkeJwe(vector.compact, vector.jwk, new Uint8Array())

        assert.equal(header.alg, vector.alg)
        assert.ok(plaintext.length > 0)
      })
    }

    it('covers every supported algorithm', () => {
      assert.deepEqual([...covered].sort(), [...supportedHpkeAlgorithms].sort())
    })
  })

  describe('algorithm recognition', () => {
    it('recognises the algorithms it cannot perform', () => {
      // HPKE-5 needs DHKEM(X448), and the "-KE" variants use Key Encryption.
      assert.equal(isHpkeAlgorithm('HPKE-5'), true)
      assert.equal(isSupportedHpkeAlgorithm('HPKE-5'), false)
      assert.equal(isHpkeAlgorithm('HPKE-0-KE'), true)
      assert.equal(isSupportedHpkeAlgorithm('HPKE-0-KE'), false)
    })

    it('does not mistake ECDH-ES for HPKE', () => {
      assert.equal(isHpkeAlgorithm('ECDH-ES'), false)
    })
  })

  for (const alg of supportedHpkeAlgorithms) {
    describe(alg, () => {
      it('round trips a payload', () => {
        const { publicKey, privateKey } = generateHpkeKeyPair(alg, 'kid-1')
        const info = Buffer.from('session-a')

        const compact = encryptHpkeJwe(
          alg,
          publicKey,
          { kid: 'kid-1' },
          info,
          Buffer.from('{"vp_token":"x"}')
        )
        const { header, plaintext } = decryptHpkeJwe(compact, privateKey, info)

        assert.equal(header.alg, alg)
        assert.equal(header.kid, 'kid-1')
        assert.equal(plaintext.toString('utf8'), '{"vp_token":"x"}')
      })

      it('fails closed when the HPKE info differs', () => {
        const { publicKey, privateKey } = generateHpkeKeyPair(alg)

        const compact = encryptHpkeJwe(
          alg,
          publicKey,
          {},
          Buffer.from('session-a'),
          Buffer.from('payload')
        )

        assert.throws(() => decryptHpkeJwe(compact, privateKey, Buffer.from('session-b')))
      })

      it('generates keys that declare their algorithm and use', () => {
        const { publicKey, privateKey } = generateHpkeKeyPair(alg, 'kid-1')

        assert.equal(publicKey.alg, alg)
        assert.equal(publicKey.use, 'enc')
        assert.equal(publicKey.kid, 'kid-1')
        // The published key must not leak the private part.
        assert.equal(publicKey.d, undefined)
        assert.ok(typeof privateKey.d === 'string' && privateKey.d.length > 0)
      })
    })
  }

  describe('compact serialization', () => {
    const build = () => {
      const { publicKey, privateKey } = generateHpkeKeyPair('HPKE-0')
      const compact = encryptHpkeJwe(
        'HPKE-0',
        publicKey,
        {},
        new Uint8Array(),
        Buffer.from('payload')
      )
      return { compact, privateKey }
    }

    it('leaves the initialization vector and the authentication tag empty', () => {
      const { compact } = build()
      const parts = compact.split('.')

      assert.equal(parts.length, 5)
      assert.equal(parts[2], '')
      assert.equal(parts[4], '')
    })

    it('does not carry an enc header parameter', () => {
      const { compact } = build()
      const header = readHpkeProtectedHeader(compact)

      assert.equal(header.alg, 'HPKE-0')
      assert.equal('enc' in header, false)
    })

    it('rejects an enc header parameter on encryption', () => {
      const { publicKey } = generateHpkeKeyPair('HPKE-0')

      assert.throws(() =>
        encryptHpkeJwe(
          'HPKE-0',
          publicKey,
          { enc: 'A128GCM' },
          new Uint8Array(),
          Buffer.from('payload')
        )
      )
    })

    it('rejects malformed serializations', () => {
      const { compact, privateKey } = build()
      const parts = compact.split('.')

      const malformed: Record<string, string> = {
        'too few parts': parts.slice(0, 4).join('.'),
        'non-empty initialization vector': [
          parts[0],
          parts[1],
          'AAAAAAAAAAAAAAAA',
          parts[3],
          parts[4],
        ].join('.'),
        'non-empty authentication tag': [
          parts[0],
          parts[1],
          parts[2],
          parts[3],
          'AAAAAAAAAAAAAAAA',
        ].join('.'),
        'tampered ciphertext': [
          parts[0],
          parts[1],
          parts[2],
          Buffer.from('tampered').toString('base64url'),
          parts[4],
        ].join('.'),
      }

      for (const [name, token] of Object.entries(malformed)) {
        assert.throws(() => decryptHpkeJwe(token, privateKey, new Uint8Array()), undefined, name)
      }
    })

    it('rejects a recipient key on the wrong curve', () => {
      const { publicKey } = generateHpkeKeyPair('HPKE-0')
      // HPKE-3 needs an X25519 key, not the P-256 key generated above.
      assert.throws(() =>
        encryptHpkeJwe('HPKE-3', publicKey, {}, new Uint8Array(), Buffer.from('payload'))
      )
    })

    it('rejects a public key when decrypting', () => {
      const { publicKey } = generateHpkeKeyPair('HPKE-0')
      const compact = encryptHpkeJwe(
        'HPKE-0',
        publicKey,
        {},
        new Uint8Array(),
        Buffer.from('payload')
      )

      assert.throws(() => decryptHpkeJwe(compact, publicKey, new Uint8Array()))
    })

    it('rejects an unimplemented algorithm', () => {
      const { publicKey } = generateHpkeKeyPair('HPKE-0')

      assert.throws(() =>
        encryptHpkeJwe(
          'HPKE-5' as HpkeAlgorithm,
          publicKey,
          {},
          new Uint8Array(),
          Buffer.from('payload')
        )
      )
    })
  })
})
