import assert from 'node:assert/strict'
import { once } from 'node:events'
import { createServer } from 'node:http'
import { after, before, describe, it } from 'node:test'
import {
  createAuthorizationRequest,
  createCredentialOffer,
  listCredentials,
  presentCredential,
  readPresentationResult,
  readServerTrace,
  readWalletTrace,
  receiveCredential,
  type StoredCredential,
  waitForPresentationResult,
} from '../src/flows.js'
import { type Harness, startHarness } from '../src/harness.js'

/**
 * Issue, store, present, verify — over real HTTP, against the sample server and
 * the Go web wallet.
 *
 * Node's test runner runs the cases in a file in order, which these rely on: the
 * presentation scenarios need the credential that issuance put in the wallet.
 */

/** The wallet and the servers are shared; starting them takes a few seconds. */
const START_TIMEOUT_MS = 120_000

describe('issue, present and verify end to end', { timeout: START_TIMEOUT_MS }, () => {
  let harness: Harness
  let issued: StoredCredential

  before(
    async () => {
      harness = await startHarness()
    },
    { timeout: START_TIMEOUT_MS }
  )

  after(async () => {
    await harness?.stop()
  })

  describe('the screens', () => {
    const contains = async (url: string, expected: string[]) => {
      const response = await fetch(url)
      assert.equal(response.status, 200, `${url} returned ${response.status}`)
      const html = await response.text()
      for (const marker of expected) {
        assert.ok(html.includes(marker), `${url} does not mention ${marker}`)
      }
    }

    it('serves the overview', async () => {
      await contains(`${harness.serverUrl}/ui`, ['/ui/issuer', '/ui/verifier', harness.walletUrl])
    })

    it('serves the issuer screen', async () => {
      await contains(`${harness.serverUrl}/ui/issuer`, ['Credential offer', '/offer'])
    })

    it('serves the verifier screen', async () => {
      await contains(`${harness.serverUrl}/ui/verifier`, [
        'direct_post.jwt',
        '/request-encrypted',
        '/presentations/',
      ])
    })

    it('serves the wallet screen', async () => {
      await contains(`${harness.walletUrl}/`, [
        'Receive a credential',
        'Present a credential',
        '/api/present',
      ])
    })
  })

  describe('issuance', () => {
    it('issues a credential into the wallet', async () => {
      const offer = await createCredentialOffer(harness, 'UniversityDegreeCredential')
      assert.ok(
        offer.startsWith('openid-credential-offer://'),
        `the issuer returned ${offer.slice(0, 40)}…`
      )

      issued = await receiveCredential(harness, offer)

      assert.ok(issued.id, 'the wallet stored no credential id')
      assert.deepEqual(issued.types, ['VerifiableCredential', 'UniversityDegreeCredential'])
      assert.ok(issued.claims, 'the credential carries no claims')
    })

    it('keeps the credential', async () => {
      const credentials = await listCredentials(harness)
      assert.ok(
        credentials.some((credential) => credential.id === issued.id),
        'the issued credential is not in the wallet'
      )
    })

    it('refuses an offer it cannot parse', async () => {
      await assert.rejects(() => receiveCredential(harness, 'openid-credential-offer://?nothing=1'))
    })
  })

  describe('presentation with response_mode=direct_post', () => {
    it('verifies the presentation', async () => {
      const request = await createAuthorizationRequest(harness, 'direct_post')
      assert.ok(request.uri.startsWith('openid4vp://authorize?'), request.uri.slice(0, 40))

      await presentCredential(harness, request.uri)
      const result = await waitForPresentationResult(harness, request.transactionId)

      assert.equal(result.status, 'verified', JSON.stringify(result.error))
      assert.equal(result.responseMode, 'direct_post')
      // Nothing was encrypted, so the verifier recorded no algorithm.
      assert.equal(result.encryption, undefined)
      assert.ok(result.vpPayload, 'the verifier recorded no VP payload')
    })
  })

  describe('the credential format', () => {
    /**
     * Support for a Credential Format is a deployment decision on both sides: a
     * Wallet that does not implement one answers `vp_formats_not_supported`
     * (§8.5). This server can ask for either format it issues, so a wallet that
     * speaks only SD-JWT VC can be exercised too.
     */
    it('answers a dc+sd-jwt query with a key-bound SD-JWT VC', async () => {
      const offer = await createCredentialOffer(harness, 'UniversityDegreeCredentialSdJwt')
      const credential = await receiveCredential(harness, offer)
      assert.equal(credential.mimeType, 'application/dc+sd-jwt')

      const request = await createAuthorizationRequest(harness, 'direct_post', 'dcql', 'dc+sd-jwt')
      // Appendix B.3.5: an SD-JWT VC is named by vct_values, not by the
      // expanded types a W3C Verifiable Credential uses.
      assert.ok(request.uri.includes('vct_values'), 'the query should name the vct')

      await presentCredential(harness, request.uri)
      const result = await waitForPresentationResult(harness, request.transactionId)
      assert.equal(result.status, 'verified', JSON.stringify(result.error))
    })
  })

  describe('the query language', () => {
    /**
     * OpenID4VP 1.0 replaced Presentation Exchange with DCQL, and with it the
     * shape of the response: `vp_token` became an object keyed by the Credential
     * Query id, and `presentation_submission` was removed (§6, §8.1). These two
     * check that the Go wallet answers both languages and that the verifier
     * reads back what each one defines.
     */
    it('answers a DCQL query with a vp_token keyed by the Credential Query id', async () => {
      const request = await createAuthorizationRequest(harness, 'direct_post', 'dcql')
      assert.ok(request.uri.includes('dcql_query='), 'the request carries no dcql_query')
      assert.ok(
        !request.uri.includes('presentation_definition='),
        'a DCQL request must not carry a presentation_definition'
      )

      await presentCredential(harness, request.uri)
      const result = await waitForPresentationResult(harness, request.transactionId)
      assert.equal(result.status, 'verified', JSON.stringify(result.error))

      // verifyDcqlPresentations returns the Presentations grouped by Credential
      // Query id, which is the id the request asked under.
      const payload = result.vpPayload as { presentations?: Record<string, unknown[]> }
      assert.ok(
        payload?.presentations?.UniversityDegreeCredential?.length === 1,
        `expected one presentation under UniversityDegreeCredential, got ${JSON.stringify(payload)}`
      )
    })

    it('still answers a Presentation Exchange request', async () => {
      const request = await createAuthorizationRequest(
        harness,
        'direct_post',
        'presentation-exchange'
      )
      assert.ok(
        request.uri.includes('presentation_definition='),
        'the request carries no presentation_definition'
      )

      await presentCredential(harness, request.uri)
      const result = await waitForPresentationResult(harness, request.transactionId)
      assert.equal(result.status, 'verified', JSON.stringify(result.error))
      assert.ok(result.vpPayload, 'the verifier recorded no VP payload')
    })
  })

  describe('presentation with a signed Request Object', () => {
    it('verifies the presentation', async () => {
      const request = await createAuthorizationRequest(harness, 'jar')
      assert.ok(
        request.uri.includes('request_uri='),
        `expected a request_uri, got ${request.uri.slice(0, 60)}…`
      )

      await presentCredential(harness, request.uri)
      const result = await waitForPresentationResult(harness, request.transactionId)

      assert.equal(result.status, 'verified', JSON.stringify(result.error))
      assert.ok(result.vpPayload, 'the verifier recorded no VP payload')
    })
  })

  describe('presentation with response_mode=direct_post.jwt', () => {
    it('verifies a response the wallet encrypted with JOSE HPKE', async () => {
      const request = await createAuthorizationRequest(harness, 'direct_post.jwt')

      await presentCredential(harness, request.uri)
      const result = await waitForPresentationResult(harness, request.transactionId)

      assert.equal(result.status, 'verified', JSON.stringify(result.error))
      assert.equal(result.responseMode, 'direct_post.jwt')

      // The Go wallet encrypted and the TypeScript verifier decrypted, so this
      // is where the two HPKE implementations meet.
      assert.ok(result.encryption, 'the verifier recorded no encryption details')
      assert.match(
        result.encryption.alg,
        /^HPKE-\d$/,
        `expected a JOSE HPKE algorithm, got ${result.encryption.alg}`
      )
      assert.ok(result.encryption.kid, 'the response did not echo the verifier key id')
      assert.ok(result.vpPayload, 'the verifier recorded no VP payload')
    })

    it('rejects a response that is not a JWE', async () => {
      const request = await createAuthorizationRequest(harness, 'direct_post.jwt')

      const response = await fetch(
        `${harness.serverUrl}/callback/${encodeURIComponent(request.transactionId)}`,
        {
          method: 'POST',
          headers: { 'content-type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({ response: 'not-a-jwe' }).toString(),
        }
      )
      assert.equal(response.status, 400)

      const result = await readPresentationResult(harness, request.transactionId)
      assert.equal(result.status, 'failed')
    })

    it('rejects a response bound to a different session', async () => {
      // A real JWE, produced by the wallet for one session.
      const captured = await captureEncryptedResponse(harness)

      // Offering it to a different transaction must fail: session_info binds the
      // response to the client_id, nonce and response endpoint it was issued
      // for, so the verifier cannot decrypt it in another context.
      const victim = await createAuthorizationRequest(harness, 'direct_post.jwt')
      const response = await fetch(
        `${harness.serverUrl}/callback/${encodeURIComponent(victim.transactionId)}`,
        {
          method: 'POST',
          headers: { 'content-type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({ response: captured }).toString(),
        }
      )
      assert.equal(response.status, 400)

      const result = await readPresentationResult(harness, victim.transactionId)
      assert.equal(result.status, 'failed')
      // It was refused at decryption rather than at parsing: the header is a
      // well-formed JOSE HPKE one.
      assert.match(result.encryption?.alg ?? '', /^HPKE-\d$/)
    })
  })

  describe('the protocol trace', () => {
    it('records the issuance and presentation steps on the server', async () => {
      const steps = (await readServerTrace(harness)).map((entry) => entry.step)

      for (const expected of [
        'OID4VCI · Credential Offer created',
        'OID4VCI · Credential Issuer Metadata',
        'OAuth · Token Request',
        'OID4VCI · Credential Request',
        'OID4VP · Authorization Response',
        'OID4VP · Authorization Response (encrypted)',
      ]) {
        assert.ok(steps.includes(expected), `the trace has no "${expected}" step: ${steps}`)
      }
    })

    it('describes the encrypted response it received', async () => {
      const encrypted = (await readServerTrace(harness)).filter(
        (entry) =>
          entry.step === 'OID4VP · Authorization Response (encrypted)' && entry.status === 200
      )
      assert.ok(encrypted.length > 0, 'no successful encrypted response was traced')

      const notes = encrypted.at(-1)?.notes.join('\n') ?? ''
      assert.match(notes, /alg=HPKE-\d/, `the JWE header was not described: ${notes}`)
      assert.match(notes, /Integrated Encryption/)
    })

    it('records what the wallet sent, from the wallet side', async () => {
      const entries = await readWalletTrace(harness)
      const steps = entries.map((entry) => entry.step)

      for (const expected of [
        'OID4VCI · Credential Issuer Metadata',
        'OAuth · Token Request',
        'OID4VCI · Credential Request',
        'OID4VP · Authorization Response sent',
      ]) {
        assert.ok(steps.includes(expected), `the wallet trace has no "${expected}" step: ${steps}`)
      }

      // The token request is where the wallet proves possession of its DPoP key.
      const token = entries.find((entry) => entry.step === 'OAuth · Token Request')
      assert.ok(token?.notes.includes('Carries a DPoP proof'), `notes: ${token?.notes}`)
    })

    it('serves the trace screen', async () => {
      const response = await fetch(`${harness.serverUrl}/ui/trace`)
      assert.equal(response.status, 200)
      const html = await response.text()
      assert.ok(html.includes('/trace?since='))
      assert.ok(html.includes('Protocol trace'))
    })
  })
})

/**
 * Returns an encrypted Authorization Response the wallet really produced, by
 * pointing one request's response endpoint at a sink this test controls.
 *
 * Capturing it this way is the only honest way to test the session binding: the
 * token has to be one the wallet built, not one the test fabricated.
 */
const captureEncryptedResponse = async (harness: Harness): Promise<string> => {
  let resolveReceived: (response: string) => void = () => {}
  const received = new Promise<string>((resolve) => {
    resolveReceived = resolve
  })

  const sink = createServer((request, serverResponse) => {
    let body = ''
    request.on('data', (chunk) => {
      body += chunk
    })
    request.on('end', () => {
      serverResponse.writeHead(200, { 'content-type': 'application/json' })
      serverResponse.end('{}')
      resolveReceived(new URLSearchParams(body).get('response') ?? '')
    })
  })
  sink.listen(0, '127.0.0.1')
  await once(sink, 'listening')

  const address = sink.address()
  if (address === null || typeof address === 'string') {
    throw new Error('failed to open the capture sink')
  }

  try {
    const request = await createAuthorizationRequest(harness, 'direct_post.jwt')
    // openid4vp:// is not a URL the WHATWG parser handles, so swap the scheme
    // to read and rewrite the parameters.
    const parsed = new URL(request.uri.replace('openid4vp://authorize', 'http://request/'))
    parsed.searchParams.set('response_uri', `http://127.0.0.1:${address.port}/sink`)

    await presentCredential(harness, `openid4vp://authorize?${parsed.searchParams.toString()}`)
    return await received
  } finally {
    sink.close()
  }
}
