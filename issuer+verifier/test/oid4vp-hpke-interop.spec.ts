import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, it } from 'node:test'
import { Jwk } from '../src/jwk.type'
import { decryptAuthorizationResponse, ResponseEncryptionSession } from '../src/response-encryption'

/**
 * Interoperability vectors shared with the Go wallet, which produced them and
 * decrypts them in its own suite
 * (wallet/presenter/plugins/oid4vp/interop_test.go). Both implementations being
 * pinned to the same bytes is what keeps them able to talk to each other.
 *
 * Regenerate with:
 *   VCKNOTS_UPDATE_INTEROP_VECTORS=1 go test ./presenter/plugins/oid4vp/ \
 *     -run TestOID4VPHPKEInteropVectors
 */
type InteropVector = {
  alg: string
  privateJwk: Jwk
  session: {
    responseMode: 'direct_post.jwt' | 'dc_api.jwt'
    clientId?: string
    nonce: string
    responseUri?: string
    origin?: string
  }
  response: string
  payload: Record<string, string>
}

const vectors: InteropVector[] = JSON.parse(
  readFileSync(
    join(import.meta.dirname, '..', '..', 'testdata', 'oid4vp-hpke-interop.json'),
    'utf8'
  )
)

const sessionOf = (vector: InteropVector): ResponseEncryptionSession =>
  vector.session.responseMode === 'dc_api.jwt'
    ? {
        responseMode: 'dc_api.jwt',
        origin: vector.session.origin ?? '',
        nonce: vector.session.nonce,
      }
    : {
        responseMode: 'direct_post.jwt',
        clientId: vector.session.clientId ?? '',
        nonce: vector.session.nonce,
        responseUri: vector.session.responseUri ?? '',
      }

describe('OID4VP HPKE interoperability with the Go wallet', () => {
  it('has vectors to check', () => {
    assert.ok(vectors.length > 0)
  })

  for (const vector of vectors) {
    it(`decrypts a ${vector.alg} response sent with ${vector.session.responseMode}`, async () => {
      const decrypted = await decryptAuthorizationResponse(
        vector.response,
        [vector.privateJwk],
        sessionOf(vector)
      )

      for (const [name, value] of Object.entries(vector.payload)) {
        assert.equal(decrypted[name], value)
      }
    })

    it(`rejects the ${vector.alg} ${vector.session.responseMode} response under another session`, async () => {
      const session = sessionOf(vector)

      await assert.rejects(() =>
        decryptAuthorizationResponse(vector.response, [vector.privateJwk], {
          ...session,
          nonce: 'a-nonce-from-another-session',
        })
      )
    })
  }
})
