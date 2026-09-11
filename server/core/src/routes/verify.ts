import { Hono } from 'hono'
import { VcknotsContext } from '@trustknots/vcknots'
import {
  VerifierClientIdScheme,
  VerifierRequestObjectId,
  initializeVerifierFlow,
  VerifierAuthorizationResponse,
  VerifierClientId,
  ClientIdentifier,
  PresentationExchange,
  Dcql,
  DcqlQuery,
} from '@trustknots/vcknots/verifier'
import { randomUUID } from 'node:crypto'
import { handleError } from '../utils/error-handler.js'
import { createDirectPostVpAudTransactionStore } from '../utils/direct-post-vp-aud-transaction-store.js'
import {
  createPresentationResultStore,
  readResponseEncryptionInfo,
} from '../utils/presentation-result-store.js'
import { err } from '@trustknots/vcknots/errors'

/**
 * Reads the `vp_token` of a form-encoded Authorization Response.
 *
 * OpenID4VP 1.0 §8.1 defines `vp_token` as a JSON object, but §8.2 sends the
 * response as `application/x-www-form-urlencoded`, where every parameter is a
 * string. The specification does not say how the object survives that encoding,
 * so a Wallet sends the JSON text and a Verifier has to decide for itself
 * whether a given string is the object or a bare Presentation.
 *
 * The rule here: a string that parses as a JSON object is the 1.0 `vp_token`;
 * anything else is the single Presentation a Presentation Exchange response
 * carries. A Presentation is a JWT or an SD-JWT VC, neither of which parses as a
 * JSON object, so the two cannot be confused.
 */
const decodeVpTokenField = (value: string): string | Record<string, unknown> => {
  const trimmed = value.trim()
  if (!trimmed.startsWith('{')) {
    return value
  }
  try {
    const parsed: unknown = JSON.parse(trimmed)
    return typeof parsed === 'object' && parsed !== null && !Array.isArray(parsed)
      ? (parsed as Record<string, unknown>)
      : value
  } catch {
    return value
  }
}

/**
 * The Client Identifier this verifier uses when a caller does not supply one.
 *
 * The Client Identifier Prefix of OpenID4VP 1.0 Section 5.9 has to agree with
 * where the response is sent: `x509_san_dns` requires a certificate whose SAN
 * carries the host, and a Wallet checks the response endpoint against it. The
 * bundled sample certificate is issued for `localhost`, so it only works when
 * this server is reached as localhost.
 *
 * Anywhere else — a deployment behind a real hostname — the prefix has to be
 * `redirect_uri`, whose Client Identifier is the response endpoint itself and
 * needs no certificate. Deriving the default from BASE_URL keeps the local
 * setup on the certificate it was built for while letting a deployed instance
 * work at all.
 */
const defaultClientId = (baseUrl: string): string => {
  let hostname: string
  try {
    hostname = new URL(baseUrl).hostname
  } catch {
    return 'x509_san_dns:localhost'
  }
  return hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '::1'
    ? 'x509_san_dns:localhost'
    : `redirect_uri:${baseUrl}/callback`
}

/**
 * Which query language a request uses. OpenID4VP 1.0 defines DCQL and dropped
 * Presentation Exchange; this server still offers both so a Wallet on either can
 * be exercised.
 */
type QueryLanguage = 'dcql' | 'presentation-exchange'

/** Reads the query language from a request body, defaulting to DCQL. */
const readQueryLanguage = (value: unknown): QueryLanguage =>
  value === 'presentation-exchange' ? 'presentation-exchange' : 'dcql'

/**
 * Which Credential Format the Verifier asks for. Support for a format is a
 * deployment decision on both sides — a Wallet that does not implement one
 * answers `vp_formats_not_supported` (Section 8.5) — so this server offers the
 * two it can issue, to be pointed at whichever a given Wallet speaks.
 */
type CredentialFormat = 'jwt_vc_json' | 'dc+sd-jwt'

/** Reads the requested Credential Format, defaulting to the W3C VC one. */
const readCredentialFormat = (value: unknown): CredentialFormat =>
  value === 'dc+sd-jwt' ? 'dc+sd-jwt' : 'jwt_vc_json'

/**
 * The `vct` of the SD-JWT VC this issuer issues, which a Credential Query for
 * `dc+sd-jwt` names in `meta.vct_values` (Appendix B.3.5).
 */
const SD_JWT_VCT = 'UniversityDegreeCredential'

export const createVerifierRouter = (context: VcknotsContext, baseUrl: string) => {
  const verifyApp = new Hono()

  const verifierFlow = initializeVerifierFlow(context)
  const vpAudTx = createDirectPostVpAudTransactionStore()
  // Lets a verification screen poll for the outcome, which arrives on the
  // wallet's connection rather than on the browser's.
  const presentationResults = createPresentationResultStore()

  type PayloadResult =
    | { ok: true; payload: Partial<VerifierAuthorizationResponse> }
    | { ok: false; error: { error: string; error_description: string } }
  const normalizeContentType = (value: string) => value.split(';')[0]?.trim().toLowerCase() ?? ''
  const parseFormPayload = (form: FormData): PayloadResult => {
    const payload: Partial<VerifierAuthorizationResponse> = {}
    const vpToken = form.getAll('vp_token').filter((v): v is string => typeof v === 'string')
    payload.vp_token =
      vpToken.length === 0
        ? undefined
        : vpToken.length === 1
          ? decodeVpTokenField(vpToken[0])
          : vpToken.map(decodeVpTokenField)
    const state = form.get('state')
    if (typeof state === 'string') {
      payload.state = state
    }
    return { ok: true, payload }
  }

  const canHandleClientIdScheme: VerifierClientIdScheme[] = ['redirect_uri', 'x509_san_dns']
  function validateClientIdScheme(client_id: string): ClientIdentifier {
    if (client_id == null || client_id === '') {
      return ClientIdentifier(defaultClientId(baseUrl))
    }
    const m = client_id.match(/^([^:]+):(.+)$/)
    const prefix = m?.[1]
    if (!prefix || !canHandleClientIdScheme.includes(prefix as VerifierClientIdScheme)) {
      throw err('invalid_request', {
        message: 'Invalid client_id parameter.',
      })
    }
    return ClientIdentifier(client_id)
  }

  /**
   * The DCQL query of OpenID4VP 1.0, asking for the same Credential the
   * Presentation Exchange definition below asks for. `credentialId` becomes the
   * Credential Query id, so it is also the key of the `vp_token` object the
   * Wallet returns (§8.1).
   */
  const buildTestDcqlQuery = (credentialId: string, format: CredentialFormat = 'jwt_vc_json') =>
    format === 'dc+sd-jwt'
      ? Dcql({
          dcql_query: {
            credentials: [
              {
                id: credentialId,
                format: 'dc+sd-jwt',
                // Appendix B.3.5: vct_values names the SD-JWT VC type. Unlike
                // the W3C VC case there is no @context, so the value is the vct
                // as the issuer writes it.
                meta: { vct_values: [SD_JWT_VCT] },
              },
            ],
          },
        })
      : Dcql({
          dcql_query: {
            credentials: [
              {
                // `id` only names this Credential Query — it is the key the
                // vp_token comes back under (§6.1), and constrains nothing. What
                // the Verifier actually asks for is in `meta`.
                id: credentialId,
                format: 'jwt_vc_json',
                meta: {
                  // Appendix B.1.1: type_values holds fully expanded types (IRIs),
                  // obtained by applying the credential's @context. The sample
                  // credential declares only https://www.w3.org/2018/credentials/v1,
                  // which defines VerifiableCredential and expands it; it does not
                  // define UniversityDegreeCredential, so that term stays as it is
                  // and is already its own fully expanded type.
                  type_values: [
                    [
                      'https://www.w3.org/2018/credentials#VerifiableCredential',
                      'UniversityDegreeCredential',
                    ],
                  ],
                },
              },
            ],
          },
        })

  /**
   * The query a request carries. DCQL is what 1.0 defines; Presentation Exchange
   * stays reachable so wallets that have not moved yet keep working.
   */
  const buildQuery = (
    credentialId: string,
    queryLanguage: QueryLanguage,
    format: CredentialFormat
  ) =>
    queryLanguage === 'dcql'
      ? buildTestDcqlQuery(credentialId, format)
      : buildTestQuery(credentialId)

  /** The presentation definition both request endpoints ask for. */
  const buildTestQuery = (credentialId: string) =>
    PresentationExchange({
      presentation_definition: {
        id: randomUUID(),
        name: 'Test Name',
        purpose: 'Test Purpose',
        input_descriptors: [
          {
            id: credentialId,
            format: {
              jwt_vc_json: {
                proof_type: ['ES256'],
              },
            },
            constraints: {
              fields: [
                {
                  path: ['$.vc.type'],
                  filter: {
                    type: 'array',
                    contains: {
                      const: 'VerifiableCredential',
                    },
                  },
                },
              ],
            },
          },
        ],
      },
    })

  /**
   * Verifies the `vp_token` with whichever query language the request used. A
   * DCQL response is checked against the query that produced it; a Presentation
   * Exchange one keeps the earlier path.
   */
  /**
   * Verifies the `vp_token` with whichever query language and Credential Format
   * the request used.
   *
   * An SD-JWT VC presentation carries a Key Binding JWT, whose `nonce` must be
   * the one from the Authorization Request and whose `aud` must be the Client
   * Identifier (Appendix B.3.6), so those are passed when the query asked for
   * `dc+sd-jwt`.
   */
  const verifyResponse = async (
    verifierId: ReturnType<typeof VerifierClientId>,
    authorizationResponse: VerifierAuthorizationResponse,
    dcqlQuery: DcqlQuery | undefined,
    options: { expectedAud: ClientIdentifier; nonce?: string }
  ): Promise<unknown> => {
    if (!dcqlQuery) {
      return await verifierFlow.verifyPresentations(verifierId, authorizationResponse, {
        expectedAud: options.expectedAud,
      })
    }

    const asksForSdJwtVc = dcqlQuery.credentials.some(
      (credential) => credential.format === 'dc+sd-jwt'
    )

    if (asksForSdJwtVc && !options.nonce) {
      // Without the nonce this request was issued with there is nothing to hold
      // the Key Binding JWT to, so the response is refused rather than accepted
      // on the strength of the nonce store alone.
      throw err('internal_server_error', {
        message: 'The nonce of the authorization request was not recorded.',
      })
    }

    return await verifierFlow.verifyDcqlPresentations(
      verifierId,
      authorizationResponse,
      dcqlQuery,
      {
        expectedAud: options.expectedAud,
        ...(asksForSdJwtVc ? { isKbJwt: true, expectedNonce: options.nonce } : {}),
      }
    )
  }

  verifyApp.post('/request', async (c) => {
    try {
      const verifierId = VerifierClientId(baseUrl)
      type Payload = Record<string, unknown>
      const body: Payload = await c.req.json<Payload>().catch(() => ({}))

      const credentialId =
        typeof body.credentialId === 'string' && body.credentialId.trim() !== ''
          ? body.credentialId
          : undefined

      if (!credentialId) {
        return c.json(
          {
            error: 'invalid_request',
            error_description: 'credentialId must be a non-empty string.',
          },
          400
        )
      }
      const state =
        typeof body.state === 'string' && body.state.trim() !== '' ? body.state.trim() : undefined
      if (state === undefined) {
        return c.json(
          {
            error: 'invalid_request',
            error_description: 'state is required.',
          },
          400
        )
      }
      const client_id = validateClientIdScheme(body.client_id as string)

      const queryLanguage = readQueryLanguage(body.queryLanguage)
      const credentialFormat = readCredentialFormat(body.credentialFormat)
      const query = buildQuery(credentialId, queryLanguage, credentialFormat)
      const request = await verifierFlow.createAuthzRequest(
        verifierId,
        'vp_token',
        client_id,
        'direct_post',
        query,
        false,
        {
          response_uri: `${baseUrl}/callback`,
          base_url: baseUrl,
        }
      )
      const registered = vpAudTx.register(client_id, state)
      if (!registered.ok) {
        return c.json(registered.error, 400)
      }
      if (queryLanguage === 'dcql') {
        vpAudTx.bindDcqlQuery(
          registered.transactionId,
          buildTestDcqlQuery(credentialId, credentialFormat).dcql_query
        )
      }
      // The Key Binding JWT of an SD-JWT VC presentation has to carry the nonce
      // from this request (Appendix B.3.6), so the callback needs it back. A
      // request without one cannot be checked against later and is refused here
      // rather than verified loosely.
      if (!request.nonce) {
        return c.json(
          {
            error: 'internal_server_error',
            error_description: 'The authorization request carries no nonce.',
          },
          500
        )
      }
      vpAudTx.bindSession(registered.transactionId, {
        nonce: request.nonce,
        responseUri: `${baseUrl}/callback`,
      })
      console.log('[verify] direct_post transaction_id:', registered.transactionId)
      presentationResults.start({
        transactionId: registered.transactionId,
        state,
        clientId: client_id,
        responseMode: 'direct_post',
        responseUri: `${baseUrl}/callback`,
      })

      const encoded = Object.entries({ ...request, state })
        .map(([key, value]) => {
          const encode = value && typeof value === 'object' ? JSON.stringify(value) : String(value)
          return `${encodeURIComponent(key)}=${encodeURIComponent(encode)}`
        })
        .join('&')

      return c.text(`openid4vp://authorize?${encoded}`, 200, {
        'X-Presentation-Transaction-Id': registered.transactionId,
      })
    } catch (err) {
      const errorResponse = handleError(err)
      const status = errorResponse.error === 'internal_server_error' ? 500 : 400
      return c.json(errorResponse, status)
    }
  })

  /**
   * Create a request that asks for an encrypted Authorization Response
   * (OpenID4VP §8.3, response_mode=direct_post.jwt).
   *
   * Each transaction gets its own response_uri. The wallet folds it, together
   * with client_id and nonce, into the session_info structure of §8.3.1, so the
   * response only decrypts against the transaction it was issued for. That also
   * solves the ordering problem at the endpoint: `state` is inside the
   * ciphertext, so the transaction has to be identifiable from the URL.
   */
  verifyApp.post('/request-encrypted', async (c) => {
    try {
      const verifierId = VerifierClientId(baseUrl)
      type Payload = Record<string, unknown>
      const body: Payload = await c.req.json<Payload>().catch(() => ({}))

      const credentialId =
        typeof body.credentialId === 'string' && body.credentialId.trim() !== ''
          ? body.credentialId
          : undefined
      if (!credentialId) {
        return c.json(
          {
            error: 'invalid_request',
            error_description: 'credentialId must be a non-empty string.',
          },
          400
        )
      }
      const state =
        typeof body.state === 'string' && body.state.trim() !== '' ? body.state.trim() : undefined
      if (state === undefined) {
        return c.json({ error: 'invalid_request', error_description: 'state is required.' }, 400)
      }
      const client_id = validateClientIdScheme(body.client_id as string)

      const registered = vpAudTx.register(client_id, state)
      if (!registered.ok) {
        return c.json(registered.error, 400)
      }
      const responseUri = `${baseUrl}/callback/${encodeURIComponent(registered.transactionId)}`

      const queryLanguage = readQueryLanguage(body.queryLanguage)
      const credentialFormat = readCredentialFormat(body.credentialFormat)
      const request = await verifierFlow.createAuthzRequest(
        verifierId,
        'vp_token',
        client_id,
        'direct_post.jwt',
        buildQuery(credentialId, queryLanguage, credentialFormat),
        false,
        { response_uri: responseUri, base_url: baseUrl }
      )
      if (!request.nonce) {
        return c.json(
          {
            error: 'internal_server_error',
            error_description: 'The authorization request carries no nonce.',
          },
          500
        )
      }

      // The nonce is minted by createAuthzRequest, so the session can only be
      // recorded now.
      vpAudTx.bindSession(registered.transactionId, { nonce: request.nonce, responseUri })
      if (queryLanguage === 'dcql') {
        vpAudTx.bindDcqlQuery(
          registered.transactionId,
          buildTestDcqlQuery(credentialId, credentialFormat).dcql_query
        )
      }
      console.log('[verify] direct_post.jwt transaction_id:', registered.transactionId)
      presentationResults.start({
        transactionId: registered.transactionId,
        state,
        clientId: client_id,
        responseMode: 'direct_post.jwt',
        responseUri,
      })

      const encoded = Object.entries({ ...request, state })
        .map(([key, value]) => {
          const encode = value && typeof value === 'object' ? JSON.stringify(value) : String(value)
          return `${encodeURIComponent(key)}=${encodeURIComponent(encode)}`
        })
        .join('&')

      return c.text(`openid4vp://authorize?${encoded}`, 200, {
        'X-Presentation-Transaction-Id': registered.transactionId,
      })
    } catch (err) {
      const errorResponse = handleError(err)
      const status = errorResponse.error === 'internal_server_error' ? 500 : 400
      return c.json(errorResponse, status)
    }
  })

  /**
   * Receive an encrypted Authorization Response (OpenID4VP §8.3) and verify the
   * vp_token it carries.
   */
  verifyApp.post('/callback/:transactionId', async (c) => {
    try {
      const verifierId = VerifierClientId(baseUrl)
      const contentType = normalizeContentType(c.req.header('content-type') ?? '')
      if (contentType !== 'application/x-www-form-urlencoded') {
        return c.json(
          {
            error: 'invalid_request',
            error_description: 'content-type must be application/x-www-form-urlencoded',
          },
          400
        )
      }

      const formData = await c.req.formData().catch(() => null)
      const response = formData?.get('response')
      if (typeof response !== 'string' || response.trim() === '') {
        return c.json(
          {
            error: 'invalid_request',
            error_description: 'response is required for an encrypted authorization response.',
          },
          400
        )
      }

      const transactionId = c.req.param('transactionId')
      const transaction = vpAudTx.getById(transactionId)
      if (transaction.kind !== 'ok' || !transaction.session) {
        return c.json(
          {
            error: 'invalid_request',
            error_description: 'unknown or expired transaction',
          },
          400
        )
      }

      // Read for display only. Whether the response is acceptable is decided by
      // the decryption below, not by what its header claims.
      const encryption = readResponseEncryptionInfo(response)

      try {
        // The session context comes from what this server issued, never from the
        // response, which is what makes decryption fail closed on a response
        // captured from another transaction.
        const authorizationResponse = await verifierFlow.decryptAuthorizationResponse(
          verifierId,
          response,
          {
            responseMode: 'direct_post.jwt',
            clientId: transaction.clientId,
            nonce: transaction.session.nonce,
            responseUri: transaction.session.responseUri,
          }
        )

        if (authorizationResponse.state !== transaction.state) {
          const mismatch = {
            error: 'invalid_request',
            error_description: 'state does not match the transaction',
          }
          presentationResults.fail(transactionId, mismatch, encryption)
          return c.json(mismatch, 400)
        }

        const vpPayload = await verifyResponse(
          verifierId,
          authorizationResponse,
          transaction.dcqlQuery,
          { expectedAud: transaction.clientId, nonce: transaction.session.nonce }
        )
        vpAudTx.consume(transactionId, transaction.state)
        presentationResults.succeed(transactionId, vpPayload, encryption)
        console.log('Verified encrypted VP Payload:', vpPayload)
        return c.json({ redirect_uri: `${baseUrl}/verified` }, 200)
      } catch (error) {
        presentationResults.fail(transactionId, handleError(error), encryption)
        throw error
      }
    } catch (err) {
      const errorResponse = handleError(err)
      console.log('error Response:', errorResponse)
      const status = errorResponse.error === 'internal_server_error' ? 500 : 400
      return c.json(errorResponse, status)
    }
  })

  // Receive the vp_token from the request and verify it
  verifyApp.post('/callback', async (c) => {
    try {
      const verifierId = VerifierClientId(baseUrl)
      const contentType = normalizeContentType(c.req.header('content-type') ?? '')

      if (contentType !== 'application/x-www-form-urlencoded') {
        return c.json(
          {
            error: 'invalid_request',
            error_description: 'content-type must be application/x-www-form-urlencoded',
          },
          400
        )
      }

      const formData = await c.req.formData().catch(() => null)
      if (!formData) {
        return c.json(
          {
            error: 'invalid_request',
            error_description: 'Request body must be a valid form data.',
          },
          400
        )
      }
      const parsed = parseFormPayload(formData)

      if (!parsed.ok) {
        return c.json(parsed.error, 400)
      }

      // Validate it using the AuthorizationResponse
      const parseResult = VerifierAuthorizationResponse.schema.safeParse(parsed.payload)
      if (!parseResult.success) {
        return c.json(
          {
            error: 'invalid_request',
            error_description: 'Invalid authorization response parameters.',
          },
          400
        )
      }
      const authorizationResponse = parseResult.data

      const audResolved = vpAudTx.resolveExpectedAudFromWalletState(authorizationResponse.state)
      if (!audResolved.ok) {
        return c.json(audResolved.error, 400)
      }
      console.log('[verify] expectedAud:', audResolved.aud)
      let vpPayload: unknown
      try {
        vpPayload = await verifyResponse(verifierId, authorizationResponse, audResolved.dcqlQuery, {
          expectedAud: audResolved.aud,
          nonce: audResolved.nonce,
        })
      } catch (error) {
        presentationResults.fail(audResolved.transactionId, handleError(error))
        throw error
      }
      if (authorizationResponse.state != null && authorizationResponse.state !== '') {
        vpAudTx.consume(audResolved.transactionId, authorizationResponse.state)
      }
      presentationResults.succeed(audResolved.transactionId, vpPayload)
      console.log('Verified VP Payload:', vpPayload)
      return c.json({ redirect_uri: `${baseUrl}/verified` }, 200)
    } catch (err) {
      const errorResponse = handleError(err)
      console.log('error Response:', errorResponse)
      const status = errorResponse.error === 'internal_server_error' ? 500 : 400
      return c.json(errorResponse, status)
    }
  })

  verifyApp.post('/callback-kbjwt', async (c) => {
    try {
      console.log('callback-kbjwt')
      const verifierId = VerifierClientId(baseUrl)
      const contentType = normalizeContentType(c.req.header('content-type') ?? '')

      if (contentType !== 'application/x-www-form-urlencoded') {
        return c.json(
          {
            error: 'invalid_request',
            error_description: 'content-type must be application/x-www-form-urlencoded',
          },
          400
        )
      }
      const formData = await c.req.formData().catch(() => null)
      if (!formData) {
        return c.json(
          {
            error: 'invalid_request',
            error_description: 'Request body must be a valid form data.',
          },
          400
        )
      }
      const parsed = parseFormPayload(formData)
      if (!parsed.ok) {
        return c.json(parsed.error, 400)
      }

      // Validate it using the AuthorizationResponse
      const parseResult = VerifierAuthorizationResponse.schema.safeParse(parsed.payload)
      if (!parseResult.success) {
        return c.json(
          {
            error: 'invalid_request',
            error_description: 'Invalid authorization response parameters.',
          },
          400
        )
      }
      const authorizationResponse = parseResult.data
      const audResolved = vpAudTx.resolveExpectedAudFromWalletState(authorizationResponse.state)
      if (!audResolved.ok) {
        return c.json(audResolved.error, 400)
      }
      console.log('[verify] expectedAud (callback-kbjwt):', audResolved.aud)
      const vpPayload = await verifierFlow.verifyPresentations(verifierId, authorizationResponse, {
        expectedAud: audResolved.aud,
        isKbJwt: true,
      })
      if (authorizationResponse.state != null && authorizationResponse.state !== '') {
        vpAudTx.consume(audResolved.transactionId, authorizationResponse.state)
      }
      console.log('Verified KBJWT VP Payload:', vpPayload)
      return c.json({ redirect_uri: `${baseUrl}/verified` }, 200)
    } catch (err) {
      const errorResponse = handleError(err)
      console.log('error Response:', errorResponse)
      const status = errorResponse.error === 'internal_server_error' ? 500 : 400
      return c.json(errorResponse, status)
    }
  })

  // Create the request in JAR format
  type RequestObjectShape = {
    query: PresentationExchange
    state: string
    base_url: string
    is_request_uri: boolean
    client_id: ClientIdentifier
    is_transaction_data: boolean
    response_uri?: string
  }
  verifyApp.post('/request-object', async (c) => {
    const presentationDefinitionJwtVC = {
      id: randomUUID(),
      name: 'Test Name',
      purpose: 'Test Purpose',
      input_descriptors: [
        {
          id: randomUUID(),
          format: {
            jwt_vc_json: {
              proof_type: ['ES256'],
            },
          },
          constraints: {
            fields: [
              {
                path: ['$.vc.type'],
                filter: {
                  type: 'array',
                  contains: {
                    const: 'VerifiableCredential',
                  },
                },
              },
            ],
          },
        },
      ],
    }
    const raw = await c.req.text()
    let parsed: unknown = {}
    if (raw.trim()) {
      try {
        parsed = JSON.parse(raw)
      } catch (e) {
        return c.json(
          { error: 'invalid_request', error_description: 'Request body must be valid JSON' },
          400
        )
      }
    }
    try {
      const input =
        parsed && typeof parsed === 'object' ? (parsed as Partial<RequestObjectShape>) : {}
      const requestObject: RequestObjectShape = {
        query:
          typeof input.query === 'object' && input.query !== null
            ? input.query
            : {
                presentation_definition: presentationDefinitionJwtVC,
              },
        state:
          typeof input.state === 'string' && input.state.trim() !== ''
            ? input.state
            : randomUUID().replaceAll('-', ''),
        base_url:
          typeof input.base_url === 'string' && input.base_url.trim() !== ''
            ? input.base_url
            : baseUrl,
        is_request_uri: typeof input.is_request_uri === 'boolean' ? input.is_request_uri : true,
        is_transaction_data:
          typeof input.is_transaction_data === 'boolean' ? input.is_transaction_data : false,
        response_uri:
          typeof input.response_uri === 'string' && input.response_uri.trim() !== ''
            ? input.response_uri
            : undefined,
        client_id:
          typeof input.client_id === 'string' && input.client_id.trim() !== ''
            ? validateClientIdScheme(input.client_id)
            : ClientIdentifier(defaultClientId(baseUrl)),
      }

      const verifierId = VerifierClientId(baseUrl)
      const request = await verifierFlow.createAuthzRequest(
        verifierId,
        'vp_token',
        requestObject.client_id,
        'direct_post',
        requestObject.query,
        requestObject.is_request_uri,
        {
          state: requestObject.state,
          base_url: baseUrl,
          response_uri: requestObject.response_uri ?? `${baseUrl}/callback`,
          request_uri: `${baseUrl}/request.jwt`,
          ...(requestObject.is_transaction_data
            ? { transaction_data: { type: 'sample_type' } }
            : {}),
        }
      )
      const registered = vpAudTx.register(requestObject.client_id, requestObject.state)
      if (!registered.ok) {
        return c.json(registered.error, 400)
      }
      console.log('[verify] direct_post transaction_id:', registered.transactionId)
      presentationResults.start({
        transactionId: registered.transactionId,
        state: requestObject.state,
        clientId: requestObject.client_id,
        responseMode: 'direct_post',
        responseUri: requestObject.response_uri ?? `${baseUrl}/callback`,
      })
      // const params = requestObject.is_request_uri
      //   ? request
      //   : { ...request, state: requestObject.state }
      const encoded = Object.entries(request)
        .map(([key, value]) => {
          const encode = value && typeof value === 'object' ? JSON.stringify(value) : String(value)
          return `${encodeURIComponent(key)}=${encodeURIComponent(encode)}`
        })
        .join('&')

      return c.text(`openid4vp://authorize?${encoded}`, 200, {
        'X-Presentation-Transaction-Id': registered.transactionId,
      })
    } catch (err) {
      const errorResponse = handleError(err)
      const status = errorResponse.error === 'internal_server_error' ? 500 : 400
      return c.json(errorResponse, status)
    }
  })

  verifyApp.get('/request.jwt/:request-object-Id', async (c) => {
    try {
      console.log('request-object-Id:', c.req.param('request-object-Id'))
      const verifierId = VerifierClientId(baseUrl)
      const parseResult = VerifierRequestObjectId.schema.safeParse(c.req.param('request-object-Id'))
      if (!parseResult.success) {
        return c.json(
          {
            error: 'invalid_request',
            error_description: 'Invalid request-object-Id parameter.',
          },
          400
        )
      }
      const requestObjectId = parseResult.data
      const jar = await verifierFlow.findRequestObject(verifierId, requestObjectId)
      return c.body(jar, 200, {
        'Content-Type': 'application/oauth-authz-req+jwt',
      })
    } catch (err) {
      const errorResponse = handleError(err)
      const status = errorResponse.error === 'internal_server_error' ? 500 : 400
      return c.json(errorResponse, status)
    }
  })

  /** Poll target for the verification screen: the outcome of one presentation. */
  verifyApp.get('/presentations/:transactionId', async (c) => {
    const result = presentationResults.get(c.req.param('transactionId'))
    if (!result) {
      return c.json(
        { error: 'invalid_request', error_description: 'unknown or expired transaction' },
        404
      )
    }
    return c.json(result, 200)
  })

  /** Every presentation this process has started, newest first. */
  verifyApp.get('/presentations', async (c) =>
    c.json({ presentations: presentationResults.list() }, 200)
  )

  verifyApp.get('/verified', async (c) => {
    console.log('Verified received from get request')
    return c.json({ message: 'DONE!!' }, 200)
  })

  verifyApp.get('/presentation-transaction/:transactionId', async (c) => {
    const transactionId = c.req.param('transactionId')?.trim() ?? ''
    if (transactionId === '') {
      return c.json(
        { error: 'invalid_request', error_description: 'transactionId is required' },
        400
      )
    }
    const result = vpAudTx.getById(transactionId)
    if (result.kind === 'not_found') {
      return c.json(
        { error: 'not_found', error_description: 'transaction_id is unknown or already removed' },
        404
      )
    }
    if (result.kind === 'expired') {
      return c.json({ error: 'not_found', error_description: 'transaction_id has expired' }, 404)
    }
    return c.json({
      transaction_id: transactionId,
      state: result.state,
      client_id: result.clientId,
      expires_at: result.expiresAt,
    })
  })

  verifyApp.delete('/presentation-transaction/:transactionId', async (c) => {
    const transactionId = c.req.param('transactionId')?.trim() ?? ''
    if (transactionId === '') {
      return c.json(
        { error: 'invalid_request', error_description: 'transactionId is required' },
        400
      )
    }
    const result = vpAudTx.deleteById(transactionId)
    if (!result.ok) {
      return c.json(
        { error: 'not_found', error_description: 'transaction_id is unknown or already removed' },
        404
      )
    }
    return c.json({ ok: true }, 200)
  })

  return verifyApp
}
