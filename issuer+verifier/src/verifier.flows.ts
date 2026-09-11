import base64url from 'base64url'
import { AuthorizationRequest } from './authorization-request.types'
import { AuthorizationResponse, DcqlVpToken, isDcqlVpToken } from './authorization-response.types'
import { ClientId } from './client-id.types'
import { Dcql } from './dcql.type'
import { err, raise } from './errors/vcknots.error'
import { PresentationExchange } from './presentation-exchange.types'
import {
  CredentialQueryGenerationOptions,
  VerifyVerifiablePresentationVerifyOptions,
} from './providers'
import { selectProvider } from './providers/provider.utils'
import { RequestObject } from './request-object.types'
import { DeepPartialUnknown } from './type.utils'
import { VcknotsContext } from './vcknots.context'
import { VerifierMetadata } from './verifier-metadata.types'

import { RequestObjectId } from './request-object-id.types'
import { Certificate } from './signature-key.types'
import { Jwk } from './jwk.type'
import { calculateJwkThumbprint, exportJWK, importSPKI } from 'jose'
import { ClientIdentifier } from './client-id-scheme.types'
import { VpTokenPayload } from './presentation.types'
import { supportedHpkeAlgorithms } from './jose-hpke'
import { matchesCredentialQuery, validateVpTokenAgainstQuery } from './dcql'
import { DcqlQuery } from './dcql-query.types'
import { toClientMetadata } from './verifier-metadata.types'
import {
  isSupportedResponseEncryptionAlgorithm,
  ResponseEncryptionSession,
} from './response-encryption'
import { ResponseEncryptionKeyEntry } from './response-encryption-key.types'

type CreateVerifierMetadataOptionsBase = {
  format: 'pem' | 'jwk'
  alg: string
  kid?: string
}
type CreateVerifierMetadataOptionsWithCert = CreateVerifierMetadataOptionsBase & {
  privateKey: string | Jwk
  certificate: string | string[]
}
type CreateVerifierMetadataOptionsWithPubKey = CreateVerifierMetadataOptionsBase & {
  privateKey: string | Jwk
  publicKey: string | Jwk
}
export type CreateVerifierMetadataOptions =
  | CreateVerifierMetadataOptionsWithPubKey
  | CreateVerifierMetadataOptionsWithCert
export type CreateAuthzRequestOptions = {
  state?: string
  scope?: string
  response_uri?: string
  base_url?: string
  request_uri?: string
  transaction_data?: { type: string; transaction_data_hashes_alg?: string[] }
}
export type VerifyPresentationOptions = {
  /** OAuth/OID4VP client_id value the VP / KB-JWT must bind to (e.g. JWT `aud`). */
  expectedAud: ClientIdentifier
  specifiedDisclosures?: string[]
  isKbJwt?: boolean
  expectedNonce?: string
  expectedTransactionDataHashes?: string[]
}
export type CreateResponseEncryptionKeysOptions = {
  /**
   * The JWE `alg` values to publish encryption keys for, most preferred first.
   * Defaults to the JOSE HPKE algorithms this library implements.
   */
  algs?: string[]
  /**
   * Key pairs to publish instead of generating them. Required for the ECDH-ES
   * algorithms, which this library does not generate keys for.
   */
  keys?: ResponseEncryptionKeyEntry[]
  /**
   * The JWE `enc` values to advertise for the ECDH-ES algorithms. It has no
   * effect on JOSE HPKE, where no separate content encryption algorithm exists,
   * so it is only worth setting alongside an ECDH-ES key.
   */
  encValuesSupported?: string[]
}

/** What a DCQL response yielded, grouped by the Credential Query it answers. */
export type DcqlPresentationResult = {
  presentations: Record<string, VpTokenPayload[]>
}

/**
 * DCQL states the Credential Format Identifier, while the presentation
 * verification providers are keyed by the format of the Presentation. For
 * SD-JWT VC the two coincide; for a W3C Credential requested as `jwt_vc_json`
 * the Presentation is a VP JWT, which this library registers as `jwt_vp_json`.
 */
const presentationFormatFor = (credentialFormat: string): string =>
  credentialFormat === 'jwt_vc_json' ? 'jwt_vp_json' : credentialFormat

/**
 * The claim sets a verified Presentation carries, which is what a claims path
 * pointer is applied to.
 *
 * For SD-JWT VC the verified payload already is the Credential's claim set. A
 * W3C Verifiable Presentation is a wrapper, so the Credentials inside it have to
 * be unwrapped first — applying the pointer to the Presentation would look for
 * claims one level too high.
 */
const credentialClaimSets = (credentialFormat: string, payload: VpTokenPayload): unknown[] => {
  if (credentialFormat !== 'jwt_vc_json') return [payload]

  const vp = (payload as Record<string, unknown>).vp
  const credentials =
    typeof vp === 'object' && vp !== null
      ? (vp as Record<string, unknown>).verifiableCredential
      : undefined
  if (!Array.isArray(credentials)) return []

  return credentials.map((credential) => {
    // A Credential inside a VP is normally the encoded JWT; decoding it is safe
    // here because the Presentation has already been verified.
    if (typeof credential !== 'string') return credential
    const [, encodedPayload] = credential.split('.')
    if (!encodedPayload) return undefined
    try {
      return JSON.parse(Buffer.from(encodedPayload, 'base64url').toString('utf8'))
    } catch {
      return undefined
    }
  })
}

export type FindRequestObjectOptions = {
  alg?: string
  // https://openid.net/specs/openid-4-verifiable-presentations-1_0-24.html#section-5.11 is not supported
  // wallet_metadata? :
  // wallet_nonce?: string
}

export type VerifierFlow = {
  findVerifierCertificate: (id: ClientId) => Promise<Certificate | null>
  findVerifierMetadata: (verifierId: ClientId) => Promise<VerifierMetadata | null>
  createVerifierMetadata(
    verifierId: ClientId,
    metadata: VerifierMetadata,
    options?: CreateVerifierMetadataOptions
  ): Promise<void>
  /**
   * Generates the Verifier's Authorization Response encryption keys, publishes
   * their public JWKs in the stored verifier metadata, and returns them
   * (OID4VP 1.1 Section 8.3).
   *
   * Call this after {@link VerifierFlow.createVerifierMetadata} and before
   * issuing a request with a `.jwt` Response Mode.
   */
  createResponseEncryptionKeys(
    verifierId: ClientId,
    options?: CreateResponseEncryptionKeysOptions
  ): Promise<Jwk[]>
  createAuthzRequest(
    verifierId: ClientId,
    response_type: 'vp_token',
    client_id: ClientIdentifier,
    response_mode:
      | 'direct_post'
      | 'direct_post.jwt'
      | 'query'
      | 'fragment'
      | 'dc_api.jwt'
      | 'dc_api',
    query: DeepPartialUnknown<PresentationExchange> | DeepPartialUnknown<Dcql>,
    isRequestUri: boolean,
    options: CreateAuthzRequestOptions
  ): Promise<AuthorizationRequest>
  /**
   * Decrypts the `response` parameter of an encrypted Authorization Response
   * (OID4VP 1.1 Section 8.3) and returns the response parameters it carries.
   *
   * `session` must be rebuilt from the request parameters the Verifier issued.
   * With JOSE HPKE it becomes the session_info structure of Section 8.3.1, so a
   * response captured from a different session fails to decrypt rather than
   * being accepted.
   */
  decryptAuthorizationResponse(
    verifierId: ClientId,
    response: string,
    session: ResponseEncryptionSession
  ): Promise<AuthorizationResponse>
  findRequestObject(
    verifierId: ClientId,
    objectId: RequestObjectId,
    options?: FindRequestObjectOptions
  ): Promise<string>
  verifyPresentations: (
    id: ClientId,
    response: AuthorizationResponse,
    options: VerifyPresentationOptions
  ) => Promise<VpTokenPayload>
  /**
   * Verifies a `vp_token` returned for a DCQL query (OpenID4VP 1.0).
   *
   * The response is checked against the query that produced it — the keys name
   * Credential Queries, `multiple` is respected, and the required Credential Set
   * Queries are answered — and then every Presentation is verified for its
   * format.
   *
   * {@link VerifierFlow.verifyPresentations} remains for the Presentation
   * Exchange responses this library still accepts.
   */
  verifyDcqlPresentations(
    verifierId: ClientId,
    response: AuthorizationResponse,
    query: DcqlQuery,
    options: VerifyPresentationOptions
  ): Promise<DcqlPresentationResult>
}

/** Whether a Response Mode is one of the OID4VP Section 8.3 encrypted variants. */
const requiresEncryptedResponse = (responseMode: string): boolean =>
  responseMode === 'direct_post.jwt' || responseMode === 'dc_api.jwt'

/**
 * Whether the metadata publishes a key a Wallet could encrypt a response to.
 * Section 8.3 treats keys whose `use` is absent or `enc` as encryption keys and
 * requires the `alg` member on them.
 */
const hasResponseEncryptionKey = (metadata: VerifierMetadata): boolean =>
  (metadata.jwks?.keys ?? []).some(
    (key) =>
      key != null &&
      (key.use === undefined || key.use === 'enc') &&
      isSupportedResponseEncryptionAlgorithm(key.alg)
  )

/**
 * The Credential Format of a Presentation, read from the Presentation itself.
 *
 * Presentation Exchange named the format in `presentation_submission`, which
 * OpenID4VP 1.0 removed. A DCQL response takes the format from the Credential
 * Query it answers; a response to a `presentation_definition` has neither, so
 * the format is recognised from the encoding: an SD-JWT VC is the issuer-signed
 * JWT followed by tilde-separated disclosures, and nothing else uses a tilde.
 */
const presentationFormatOf = (presentation: string): 'dc+sd-jwt' | 'jwt_vp_json' =>
  presentation.includes('~') ? 'dc+sd-jwt' : 'jwt_vp_json'

/**
 * Gives a JWK a `kid` when it has none.
 *
 * OpenID4VP 1.0 Section 5.1 requires every JWK in `client_metadata.jwks` to
 * carry a `kid` that uniquely identifies it within the request, and Section 8.3
 * has the Wallet echo that `kid` in the JWE header so the Verifier knows which
 * key a response was encrypted to. The RFC 7638 thumbprint is unique per key by
 * construction, so it is used when the caller supplied no identifier.
 */
const withKeyId = async <T extends object>(jwk: T): Promise<T & { kid: string }> => {
  const existing = (jwk as { kid?: unknown }).kid
  if (typeof existing === 'string' && existing !== '') {
    return jwk as T & { kid: string }
  }
  const kid = await calculateJwkThumbprint(jwk as Parameters<typeof calculateJwkThumbprint>[0])
  return { ...jwk, kid }
}

const isPresentationExchange = (query: unknown): query is PresentationExchange =>
  typeof query === 'object' &&
  query !== null &&
  ('presentation_definition' in query || 'presentation_definition_uri' in query)

export const initializeVerifierFlow = (context: VcknotsContext): VerifierFlow => {
  const cnonce$ = context.providers.get('nonce-provider')
  const nonceStore$ = context.providers.get('nonce-store-provider')
  const query$ = context.providers.get('credential-query-provider')
  const verifierMetadata$ = context.providers.get('verifier-metadata-store-provider')
  const keyStore$ = context.providers.get('verifier-signature-key-store-provider')
  const requestObjectId$ = context.providers.get('request-object-id-provider')
  const requestObjectStore$ = context.providers.get('request-object-store-provider')
  const authzRequestJAR$ = context.providers.get('authz-request-jar-provider')
  const certificateStore$ = context.providers.get('verifier-certificate-store-provider')
  const certificate$ = context.providers.get('certificate-provider')
  const transactionData$ = context.providers.get('transaction-data-provider')
  const verifiablePresentation$ = context.providers.get('verify-verifiable-presentation-provider')
  const responseEncryptionKey$ = context.providers.get(
    'verifier-response-encryption-key-store-provider'
  )

  return {
    async findVerifierCertificate(id) {
      return certificateStore$.fetch(id)
    },
    async findVerifierMetadata(verifierId) {
      return verifierMetadata$.fetch(verifierId)
    },
    async createVerifierMetadata(verifierId, metadata, options) {
      const current = await verifierMetadata$.fetch(verifierId)
      if (current) {
        throw err('duplicate_verifier', {
          message: `verifier ${verifierId} is already registered.`,
        })
      }
      const verifierMetadata = metadata
      let keyPairsToSave:
        | {
            format: 'pem' | 'jwk'
            declaredAlg: string
            kid?: string
            publicKey?: string | Jwk
            privateKey: string | Jwk
          }
        | undefined
      let certificatesToSave: Certificate | undefined
      let keyAlg: string | undefined = options?.alg
      if (!options || !keyAlg) {
        // create new key pair (not support x509)
        keyAlg = metadata.authorization_signed_response_alg ?? 'ES256'
        await keyStore$.save(verifierId, keyAlg)
        const publicKey = await keyStore$.fetch(verifierId, keyAlg)
        if (!publicKey) {
          throw err('authz_verifier_key_not_found', {
            message: `Verifier public key for ${keyAlg} is not found.`,
          })
        }
        const jwk = await exportJWK(publicKey)
        verifierMetadata.jwks = { keys: [await withKeyId({ ...jwk, alg: keyAlg })] }
        verifierMetadata.authorization_signed_response_alg = keyAlg
      } else if ('publicKey' in options && options.publicKey !== undefined) {
        // use provided key pair (not support x509)
        if (!keyAlg) {
          throw err('internal_server_error', {
            message: 'alg is required in the provided publicKey.',
          })
        }
        if (options.format === 'jwk' && typeof options.publicKey !== 'string') {
          verifierMetadata.jwks = { keys: [await withKeyId(options.publicKey)] }
          verifierMetadata.authorization_signed_response_alg = keyAlg
        } else if (options.format === 'jwk') {
          throw err('invalid_options', {
            message: 'publicKey must be a JWK when format is jwk.',
          })
        } else if (options.format === 'pem' && typeof options.publicKey === 'string') {
          const key = await importSPKI(options.publicKey, keyAlg)
          const jwk = await exportJWK(key)
          verifierMetadata.jwks = { keys: [await withKeyId({ ...jwk, alg: keyAlg })] }
          verifierMetadata.authorization_signed_response_alg = keyAlg
        } else {
          throw err('invalid_options', {
            message: 'publicKey must be a PEM string when format is pem.',
          })
        }
        keyPairsToSave = {
          format: options.format,
          declaredAlg: keyAlg,
          kid: options.kid,
          publicKey: options.publicKey,
          privateKey: options.privateKey,
        }
      } else if ('certificate' in options && options.certificate !== undefined) {
        // use provided key pair and x509 certificate
        // password protected private key is not supported
        if (!keyAlg) {
          throw err('internal_server_error', {
            message: 'alg is required in the provided privateKey.',
          })
        }
        const certificateChain =
          typeof options.certificate === 'string' ? [options.certificate] : options.certificate
        const certificates = Certificate(certificateChain)
        const certValid = await certificate$.validate(certificates)
        if (!certValid) {
          throw err('invalid_certificate', {
            message: 'The provided certificate is not valid.',
          })
        }
        const certificate = certificates[0]
        const publicKey = await certificate$.getPublicKey(certificate)
        const key = await importSPKI(publicKey, keyAlg)
        const jwk = await exportJWK(key)
        verifierMetadata.jwks = { keys: [await withKeyId({ ...jwk, alg: keyAlg })] }
        verifierMetadata.authorization_signed_response_alg = keyAlg
        certificatesToSave = certificates
        keyPairsToSave = {
          format: options.format,
          declaredAlg: keyAlg,
          kid: options.kid,
          publicKey: publicKey,
          privateKey: options.privateKey,
        }
      }
      if (certificatesToSave) {
        await certificateStore$.save(verifierId, certificatesToSave)
      }
      if (keyPairsToSave) {
        await keyStore$.save(verifierId, keyAlg, keyPairsToSave)
      }
      await verifierMetadata$.save(verifierId, verifierMetadata)
    },
    async createResponseEncryptionKeys(verifierId, options) {
      const metadata = (await verifierMetadata$.fetch(verifierId)) ?? raise('verifier_not_found')

      const algs = options?.algs ?? [...supportedHpkeAlgorithms]
      const published = await responseEncryptionKey$.save(verifierId, algs, options?.keys)

      // Section 8.3 has the Wallet select the encryption key out of
      // client_metadata.jwks, so the keys have to end up there. Signing keys
      // already in the set are left untouched.
      const existing = (metadata.jwks?.keys ?? []).filter(
        (key): key is NonNullable<typeof key> =>
          key != null && !published.some((it) => it.kid !== undefined && it.kid === key.kid)
      )
      metadata.jwks = { keys: [...existing, ...published] }

      if (options?.encValuesSupported && options.encValuesSupported.length > 0) {
        metadata.encrypted_response_enc_values_supported = [...options.encValuesSupported] as [
          string,
          ...string[],
        ]
      }

      await verifierMetadata$.save(verifierId, metadata)
      return published
    },
    async createAuthzRequest(
      verifierId,
      response_type,
      client_id,
      response_mode,
      query,
      isRequestUri,
      options
    ) {
      // OpenID4VP 1.0 Section 5.9.1 carries the Client Identifier Prefix inside
      // client_id, separated by a colon. There is no client_id_scheme parameter.
      const clientIdPrefix = client_id.split(':')[0]
      const authzRequestJAR = selectProvider(authzRequestJAR$, clientIdPrefix)
      if (!authzRequestJAR) {
        throw err('unsupported_client_id_scheme', {
          message: 'The Client Identifier Prefix is not supported.',
        })
      }
      if (clientIdPrefix === 'x509_san_dns' || clientIdPrefix === 'x509_san_uri') {
        const certificate = await certificateStore$.fetch(verifierId)
        if (!certificate) {
          throw err('certificate_not_found', {
            message: 'verifier certificate is not found.',
          })
        }
      }

      const metadata = (await verifierMetadata$.fetch(verifierId)) ?? raise('verifier_not_found')

      // A ".jwt" Response Mode has the Wallet encrypt the response to a key from
      // client_metadata.jwks. Without such a key the Wallet has nothing to
      // encrypt to, so catch it here rather than at the response endpoint.
      if (requiresEncryptedResponse(response_mode) && !hasResponseEncryptionKey(metadata)) {
        throw err('invalid_encryption_parameters', {
          message: `response_mode ${response_mode} requires an encrypted response, but the verifier publishes no encryption key. Call createResponseEncryptionKeys first.`,
        })
      }

      const args: CredentialQueryGenerationOptions = isPresentationExchange(query)
        ? {
            kind: 'presentation-exchange',
            query: query as PresentationExchange,
          }
        : { kind: 'dcql', query: query as Dcql }

      const parsedQuery = await selectProvider(query$, args.kind).generate(args)

      const transaction_data: string[] = []
      const credentialIds: string[] = []
      let isDcSDJwtRequested = false
      // Validate: Metadata supports format
      const vpFormats = Object.keys(metadata.vp_formats_supported)
      if (isPresentationExchange(parsedQuery)) {
        if (parsedQuery.presentation_definition) {
          const input_descriptors = parsedQuery.presentation_definition.input_descriptors
          if (input_descriptors) {
            for (const descriptor of input_descriptors) {
              if (descriptor.format) {
                for (const format of Object.keys(descriptor.format)) {
                  if (!vpFormats.includes(format)) {
                    throw err('verifier_vp_formats_not_supported', {
                      message: `The vp_format ${format} is not supported by the verifier.`,
                    })
                  }
                  if (format === 'dc+sd-jwt') {
                    credentialIds.push(descriptor.id)
                    isDcSDJwtRequested = true
                  }
                }
              }
            }
            if (isDcSDJwtRequested && options.transaction_data) {
              transaction_data.push(
                transactionData$.generate(options.transaction_data.type, credentialIds)
              )
            }
          }
        }
      } else if (parsedQuery.dcql_query) {
        const credentials = parsedQuery.dcql_query.credentials
        console.log('credentials:', credentials)
        if (credentials) {
          for (const credential of credentials) {
            if (credential.format) {
              if (!vpFormats.includes(credential.format)) {
                throw err('verifier_vp_formats_not_supported', {
                  message: `The vp_format ${credential.format} is not supported by the verifier.`,
                })
              }
              if (credential.format === 'dc+sd-jwt') {
                isDcSDJwtRequested = true
                credentialIds.push(credential.id)
              }
            }
          }
          if (isDcSDJwtRequested && options.transaction_data) {
            transaction_data.push(
              transactionData$.generate(options.transaction_data.type, credentialIds)
            )
          }
        }
      }

      const responseUri = options.response_uri ?? `${verifierId}/post`

      // when using request_uri
      if (isRequestUri ?? true) {
        if (!options.base_url) {
          throw err('invalid_request', {
            message: 'base_url is required when is_request_uri is true',
          })
        }
        // create RequestObjectId
        const requestObjectId = await requestObjectId$.generate()

        // create RequestObjectを作成(generate iat and nonce when creating the JAR)
        const requestObject = RequestObject({
          response_type: response_type,
          client_id: client_id,
          scope: options.scope,
          state: options.state,
          response_uri: responseUri,
          iss: client_id,
          aud: 'https://self-issued.me/v2',
          client_metadata: toClientMetadata(metadata, {
            responseMode: response_mode || 'direct_post',
          }),
          response_mode: response_mode || 'direct_post',
          ...parsedQuery,
          ...(transaction_data.length > 0 ? { transaction_data } : {}),
        })
        await requestObjectStore$.save(requestObjectId, requestObject)

        return AuthorizationRequest({
          client_id: client_id,
          request_uri: options.request_uri
            ? `${options.request_uri}/${encodeURIComponent(requestObjectId)}`
            : `${options.base_url}/request.jwt/${encodeURIComponent(requestObjectId)}`,
        })
      }

      const nonce = await cnonce$.generate()
      await nonceStore$.save(nonce)
      return AuthorizationRequest({
        client_id: client_id,
        response_uri: responseUri,
        response_type: response_type,
        response_mode: response_mode || 'direct_post',
        client_metadata: toClientMetadata(metadata, {
          responseMode: response_mode || 'direct_post',
        }),
        nonce: nonce.nonce,
        ...parsedQuery,
        ...(transaction_data.length > 0 ? { transaction_data } : {}),
      })
    },
    async findRequestObject(verifierId, objectId) {
      const metadata = (await verifierMetadata$.fetch(verifierId)) ?? raise('verifier_not_found')
      const keyAlg = metadata.authorization_signed_response_alg ?? 'ES256'

      const requestObject = await requestObjectStore$.fetch(objectId)
      if (!requestObject) {
        throw raise('request_object_not_found', {
          message: 'Request object is not found.',
        })
      }

      const nonce = await cnonce$.generate()
      await nonceStore$.save(nonce)

      const clientId = requestObject.client_id
      const clientIdPrefix = clientId.split(':')[0]
      const authzRequestJAR = selectProvider(authzRequestJAR$, clientIdPrefix)
      if (!authzRequestJAR) {
        throw raise('provider_not_found', {
          message: 'Authorization request JAR provider is not found.',
        })
      }
      // wallet_nonce is not supported
      const walletNonce = undefined

      const { header, payload } = await authzRequestJAR.generate(
        verifierId,
        requestObject,
        keyAlg,
        nonce.nonce,
        walletNonce
      )

      // const keyProvider = selectProvider(key$, keyAlg)
      // if (!keyProvider) {
      //   throw raise('authz_verifier_key_not_found', {
      //     message: `Verifier signature key provider for ${keyAlg} is not found.`,
      //   })
      // }
      const signature = await keyStore$.sign(verifierId, keyAlg, payload, header)
      if (!signature) {
        throw err('authz_verifier_key_not_found', {
          message: `Verifier signing key for ${keyAlg} is not found.`,
        })
      }

      await requestObjectStore$.delete(objectId)

      const encode = (x: unknown) => base64url.encode(JSON.stringify(x))

      return `${encode(header)}.${encode(payload)}.${signature}`
    },
    async decryptAuthorizationResponse(verifierId, response, session) {
      const decrypted = await responseEncryptionKey$.decrypt(verifierId, response, session)
      return AuthorizationResponse(decrypted)
    },
    async verifyDcqlPresentations(verifierId, response, query, options) {
      const verifier = await verifierMetadata$.fetch(verifierId)
      if (!verifier) {
        throw raise('verifier_not_found', { message: 'verifier is not found.' })
      }

      if (!isDcqlVpToken(response.vp_token)) {
        throw err('unsupported_vp_token', {
          message:
            'vp_token must be an object mapping Credential Query ids to non-empty arrays of Presentations.',
        })
      }
      const vpToken: DcqlVpToken = response.vp_token

      const structure = validateVpTokenAgainstQuery(query, vpToken)
      if (!structure.valid) {
        throw err('invalid_vp_token', { message: structure.reason })
      }

      const presentations: Record<string, VpTokenPayload[]> = {}
      for (const [credentialId, entries] of Object.entries(vpToken)) {
        const credentialQuery = query.credentials.find(
          (credential) => credential.id === credentialId
        )
        if (!credentialQuery) {
          // validateVpTokenAgainstQuery already rejected unknown ids.
          throw err('illegal_state', { message: `Credential Query ${credentialId} disappeared.` })
        }

        const format = presentationFormatFor(credentialQuery.format)
        const verifyOptions: VerifyVerifiablePresentationVerifyOptions =
          format === 'dc+sd-jwt'
            ? {
                kind: 'dc+sd-jwt',
                specifiedDisclosures: options.specifiedDisclosures,
                isKbJwt: options.isKbJwt,
                expectedAud: options.expectedAud,
                expectedNonce: options.expectedNonce,
                expectedTransactionDataHashes: options.expectedTransactionDataHashes,
              }
            : { kind: 'jwt_vp_json', expectedAud: options.expectedAud }

        const verified: VpTokenPayload[] = []
        for (const entry of entries) {
          if (typeof entry !== 'string') {
            throw err('unsupported_vp_token', {
              message: `vp_token["${credentialId}"] holds a non-string Presentation, which is not supported yet.`,
            })
          }
          const payload = await selectProvider(verifiablePresentation$, format).verify(
            entry,
            verifyOptions
          )

          // A Presentation that verifies but does not answer the query is not an
          // acceptable response, so the claims are checked against the query too.
          // One Presentation can carry several Credentials; any one of them
          // answering the query is enough.
          const candidates = credentialClaimSets(credentialQuery.format, payload)
          const matches = candidates.map((claims) =>
            matchesCredentialQuery(credentialQuery, { format: credentialQuery.format, claims })
          )
          if (!matches.some((match) => match.matched)) {
            const reason =
              matches.find((match) => !match.matched)?.reason ??
              'the presentation carries no credential'
            throw err('invalid_vp_token', {
              message: `vp_token["${credentialId}"] does not satisfy its Credential Query: ${reason}`,
            })
          }

          verified.push(payload)
        }
        presentations[credentialId] = verified
      }

      return { presentations }
    },
    async verifyPresentations(id, response, options) {
      const verifier = await verifierMetadata$.fetch(id)
      if (!verifier) {
        throw raise('verifier_not_found', {
          message: 'verifier is not found.',
        })
      }

      if (Array.isArray(response.vp_token) && response.vp_token.length === 1) {
        throw err('unsupported_vp_token', {
          message:
            'When a single Verifiable Presentation is returned, the array syntax MUST NOT be used.',
        })
      }

      if (Array.isArray(response.vp_token) && response.vp_token.length !== 1) {
        throw err('unsupported_vp_token', {
          message: 'Submitting multiple verifiable presentations are not supported yet',
        })
      }
      if (typeof response.vp_token !== 'string') {
        throw err('unsupported_vp_token', {
          message: 'vp_token object is not supported yet',
        })
      }

      const format = presentationFormatOf(response.vp_token)
      const verifyOptions: VerifyVerifiablePresentationVerifyOptions =
        format === 'dc+sd-jwt'
          ? {
              kind: 'dc+sd-jwt',
              specifiedDisclosures: options.specifiedDisclosures,
              isKbJwt: options.isKbJwt,
              expectedAud: options.expectedAud,
              expectedNonce: options.expectedNonce,
              expectedTransactionDataHashes: options.expectedTransactionDataHashes,
            }
          : { kind: 'jwt_vp_json', expectedAud: options.expectedAud }
      const responsePresentation = await selectProvider(verifiablePresentation$, format).verify(
        response.vp_token,
        verifyOptions
      )

      return responsePresentation
    },
  }
}

export { VerifierMetadata } from './verifier-metadata.types'
export { ClientId as VerifierClientId } from './client-id.types'
export { AuthorizationResponse as VerifierAuthorizationResponse } from './authorization-response.types'
export { ClientIdScheme as VerifierClientIdScheme } from './client-id-scheme.types'
export { RequestObjectId as VerifierRequestObjectId } from './request-object-id.types'
export { PresentationExchange } from './presentation-exchange.types'
export { Dcql } from './dcql.type'
export { DcqlQuery } from './dcql-query.types'
export { ClientIdentifier } from './client-id-scheme.types'
export {
  dcApiSessionInfo,
  decryptAuthorizationResponse,
  isSupportedResponseEncryptionAlgorithm,
  redirectSessionInfo,
  sessionInfoFor,
  ResponseEncryptionSession as VerifierResponseEncryptionSession,
} from './response-encryption'
export { ResponseEncryptionKeyEntry as VerifierResponseEncryptionKeyEntry } from './response-encryption-key.types'
export {
  generateHpkeKeyPair,
  isHpkeAlgorithm,
  isSupportedHpkeAlgorithm,
  supportedHpkeAlgorithms,
  HpkeAlgorithm,
} from './jose-hpke'
