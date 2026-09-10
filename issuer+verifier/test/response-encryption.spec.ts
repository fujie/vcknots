import assert from 'node:assert/strict'
import { generateKeyPairSync } from 'node:crypto'
import { beforeEach, describe, it } from 'node:test'
import { CompactEncrypt, exportJWK } from 'jose'
import { ClientId } from '../src/client-id.types'
import { encryptHpkeJwe, generateHpkeKeyPair, supportedHpkeAlgorithms } from '../src/jose-hpke'
import { Jwk } from '../src/jwk.type'
import { PresentationExchange } from '../src/presentation-exchange.types'
import {
  dcApiSessionInfo,
  decryptAuthorizationResponse,
  isSupportedResponseEncryptionAlgorithm,
  ResponseEncryptionSession,
  redirectSessionInfo,
} from '../src/response-encryption'
import { initializeContext } from '../src/vcknots.context'
import { initializeVerifierFlow, VerifierFlow } from '../src/verifier.flows'
import { VerifierMetadata } from '../src/verifier-metadata.types'

const VERIFIER_ID = ClientId('https://verifier.example.com')
const CLIENT_ID = 'x509_san_dns:verifier.example.com'
const RESPONSE_URI = 'https://verifier.example.com/callback'

const session: ResponseEncryptionSession = {
  responseMode: 'direct_post.jwt',
  clientId: CLIENT_ID,
  nonce: 'n-0S6_WzA2Mj',
  responseUri: RESPONSE_URI,
}

const query = PresentationExchange({
  presentation_definition: {
    id: 'test-definition',
    input_descriptors: [
      {
        id: 'test-credential',
        format: { jwt_vc_json: { proof_type: ['ES256'] } },
        constraints: { fields: [{ path: ['$.vc.type'] }] },
      },
    ],
  },
})

const verifierMetadata = () =>
  VerifierMetadata({
    client_name: 'Test Verifier',
    vp_formats_supported: {
      jwt_vc_json: { alg_values: ['ES256'] },
      jwt_vp_json: { alg_values: ['ES256'] },
    },
  })

describe('encrypted authorization responses', () => {
  describe('session_info', () => {
    // The specification gives these examples in hexadecimal, which pins the
    // separator byte and the field order.
    const NONCE = 'exc7gBkxjx1rdc9udRrveKvSsJIq80avlXeLHhGwqtA'

    it('encodes the direct_post.jwt structure as OID4VP Section 8.3.1 shows', () => {
      const info = redirectSessionInfo(
        'x509_san_dns:example.com',
        NONCE,
        'https://example.com/response'
      )

      assert.equal(
        info.toString('hex'),
        '4f70656e49443456502d7369ff783530395f73616e5f646e733a6578616d706c65' +
          '2e636f6dff6578633767426b786a7831726463397564527276654b7653734a49713830' +
          '61766c58654c48684777717441ff68747470733a2f2f6578616d706c652e636f6d2f72' +
          '6573706f6e7365'
      )
    })

    it('encodes the dc_api.jwt structure as OID4VP Section 8.3.1 shows', () => {
      const info = dcApiSessionInfo('https://example.com', NONCE)

      assert.equal(
        info.toString('hex'),
        '4f70656e494434565044434150492d7369ff68747470733a2f2f6578616d706c652e' +
          '636f6dff6578633767426b786a7831726463397564527276654b7653734a4971383061' +
          '766c58654c48684777717441'
      )
    })
  })

  describe('decryptAuthorizationResponse', () => {
    it('accepts a response the wallet encrypted for this session', async () => {
      const { publicKey, privateKey } = generateHpkeKeyPair('HPKE-0', 'enc-1')

      const response = encryptHpkeJwe(
        'HPKE-0',
        publicKey,
        { kid: 'enc-1' },
        redirectSessionInfo(CLIENT_ID, session.nonce, RESPONSE_URI),
        Buffer.from(JSON.stringify({ vp_token: 'vp', state: 'state-1' }))
      )

      const decrypted = await decryptAuthorizationResponse(response, [privateKey], session)

      assert.equal(decrypted.vp_token, 'vp')
      assert.equal(decrypted.state, 'state-1')
    })

    it('rejects a response captured from a different session', async () => {
      const { publicKey, privateKey } = generateHpkeKeyPair('HPKE-0', 'enc-1')

      const response = encryptHpkeJwe(
        'HPKE-0',
        publicKey,
        { kid: 'enc-1' },
        redirectSessionInfo(CLIENT_ID, 'a-different-nonce', RESPONSE_URI),
        Buffer.from(JSON.stringify({ vp_token: 'vp' }))
      )

      await assert.rejects(() => decryptAuthorizationResponse(response, [privateKey], session))
    })

    it('picks the key named by the kid header', async () => {
      const decoy = generateHpkeKeyPair('HPKE-0', 'decoy')
      const real = generateHpkeKeyPair('HPKE-0', 'enc-1')

      const response = encryptHpkeJwe(
        'HPKE-0',
        real.publicKey,
        { kid: 'enc-1' },
        redirectSessionInfo(CLIENT_ID, session.nonce, RESPONSE_URI),
        Buffer.from(JSON.stringify({ vp_token: 'vp' }))
      )

      const decrypted = await decryptAuthorizationResponse(
        response,
        [decoy.privateKey, real.privateKey],
        session
      )
      assert.equal(decrypted.vp_token, 'vp')
    })

    it('reports an unimplemented JOSE HPKE algorithm as such', async () => {
      const { privateKey } = generateHpkeKeyPair('HPKE-0')
      // HPKE-5 needs DHKEM(X448).
      const header = Buffer.from(JSON.stringify({ alg: 'HPKE-5' })).toString('base64url')

      await assert.rejects(
        () => decryptAuthorizationResponse(`${header}...AAAA.`, [privateKey], session),
        /HPKE-5/
      )
    })

    it('decrypts an ECDH-ES response too', async () => {
      const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
      const privateJwk = (await exportJWK(privateKey)) as Jwk

      const response = await new CompactEncrypt(Buffer.from(JSON.stringify({ vp_token: 'vp' })))
        .setProtectedHeader({ alg: 'ECDH-ES', enc: 'A128GCM' })
        .encrypt(publicKey)

      const decrypted = await decryptAuthorizationResponse(response, [privateJwk], session)
      assert.equal(decrypted.vp_token, 'vp')
    })

    it('recognises the algorithms it supports', () => {
      for (const alg of supportedHpkeAlgorithms) {
        assert.equal(isSupportedResponseEncryptionAlgorithm(alg), true)
      }
      assert.equal(isSupportedResponseEncryptionAlgorithm('ECDH-ES'), true)
      assert.equal(isSupportedResponseEncryptionAlgorithm('HPKE-5'), false)
      assert.equal(isSupportedResponseEncryptionAlgorithm('RSA-OAEP'), false)
    })
  })

  describe('VerifierFlow', () => {
    let verifierFlow: VerifierFlow

    beforeEach(async () => {
      verifierFlow = initializeVerifierFlow(initializeContext())
      await verifierFlow.createVerifierMetadata(VERIFIER_ID, verifierMetadata())
    })

    it('publishes HPKE encryption keys in the verifier metadata', async () => {
      const published = await verifierFlow.createResponseEncryptionKeys(VERIFIER_ID)

      assert.deepEqual(
        published.map((key) => key.alg),
        supportedHpkeAlgorithms
      )
      for (const key of published) {
        // Section 8.3 relies on use, alg and kid to select a key, and the
        // published key must not leak the private part.
        assert.equal(key.use, 'enc')
        assert.ok(typeof key.kid === 'string' && key.kid.length > 0)
        assert.equal(key.d, undefined)
      }

      const metadata = await verifierFlow.findVerifierMetadata(VERIFIER_ID)
      const kids = (metadata?.jwks?.keys ?? []).map((key) => key?.kid)
      for (const key of published) {
        assert.ok(kids.includes(key.kid))
      }
      // The signing key created with the metadata is still published.
      assert.equal(metadata?.jwks?.keys.length, published.length + 1)
    })

    it('publishes only the requested algorithms', async () => {
      const published = await verifierFlow.createResponseEncryptionKeys(VERIFIER_ID, {
        algs: ['HPKE-3'],
      })

      assert.deepEqual(
        published.map((key) => key.alg),
        ['HPKE-3']
      )
      assert.equal(published[0].kty, 'OKP')
      assert.equal(published[0].crv, 'X25519')
    })

    it('advertises the enc values a verifier chooses to support', async () => {
      await verifierFlow.createResponseEncryptionKeys(VERIFIER_ID, {
        algs: ['HPKE-0'],
        encValuesSupported: ['A128GCM', 'A256GCM'],
      })

      const metadata = await verifierFlow.findVerifierMetadata(VERIFIER_ID)
      assert.deepEqual(metadata?.encrypted_response_enc_values_supported, ['A128GCM', 'A256GCM'])
    })

    it('refuses a .jwt response mode before encryption keys exist', async () => {
      await assert.rejects(
        () =>
          verifierFlow.createAuthzRequest(
            VERIFIER_ID,
            'vp_token',
            CLIENT_ID,
            'direct_post.jwt',
            query,
            false,
            { response_uri: RESPONSE_URI }
          ),
        /createResponseEncryptionKeys/
      )
    })

    it('issues a direct_post.jwt request once encryption keys exist', async () => {
      await verifierFlow.createResponseEncryptionKeys(VERIFIER_ID, { algs: ['HPKE-0'] })

      const request = await verifierFlow.createAuthzRequest(
        VERIFIER_ID,
        'vp_token',
        CLIENT_ID,
        'direct_post.jwt',
        query,
        false,
        { response_uri: RESPONSE_URI }
      )

      assert.equal(request.response_mode, 'direct_post.jwt')
      assert.ok(request.nonce)
      const encryptionKey = request.client_metadata?.jwks?.keys.find((key) => key?.alg === 'HPKE-0')
      assert.ok(encryptionKey, 'the request must carry the encryption key the wallet encrypts to')
    })

    it('round trips a response through the request it issued', async () => {
      const [encryptionKey] = await verifierFlow.createResponseEncryptionKeys(VERIFIER_ID, {
        algs: ['HPKE-0'],
      })

      const request = await verifierFlow.createAuthzRequest(
        VERIFIER_ID,
        'vp_token',
        CLIENT_ID,
        'direct_post.jwt',
        query,
        false,
        { response_uri: RESPONSE_URI }
      )
      assert.ok(request.nonce)

      // The wallet encrypts to the published key, deriving session_info from the
      // request parameters exactly as the verifier will.
      const response = encryptHpkeJwe(
        'HPKE-0',
        encryptionKey,
        { kid: encryptionKey.kid },
        redirectSessionInfo(CLIENT_ID, request.nonce, RESPONSE_URI),
        Buffer.from(JSON.stringify({ vp_token: 'a-vp-token', state: 'state-1' }))
      )

      const decrypted = await verifierFlow.decryptAuthorizationResponse(VERIFIER_ID, response, {
        responseMode: 'direct_post.jwt',
        clientId: CLIENT_ID,
        nonce: request.nonce,
        responseUri: RESPONSE_URI,
      })

      assert.equal(decrypted.vp_token, 'a-vp-token')
      assert.equal(decrypted.state, 'state-1')
    })

    it('fails to decrypt a response bound to another nonce', async () => {
      const [encryptionKey] = await verifierFlow.createResponseEncryptionKeys(VERIFIER_ID, {
        algs: ['HPKE-0'],
      })

      const response = encryptHpkeJwe(
        'HPKE-0',
        encryptionKey,
        { kid: encryptionKey.kid },
        redirectSessionInfo(CLIENT_ID, 'nonce-from-another-session', RESPONSE_URI),
        Buffer.from(JSON.stringify({ vp_token: 'a-vp-token' }))
      )

      await assert.rejects(() =>
        verifierFlow.decryptAuthorizationResponse(VERIFIER_ID, response, session)
      )
    })

    it('refuses to generate a key for an algorithm it cannot generate', async () => {
      await assert.rejects(
        () => verifierFlow.createResponseEncryptionKeys(VERIFIER_ID, { algs: ['ECDH-ES'] }),
        /Supply the key pair instead/
      )
    })
  })
})
