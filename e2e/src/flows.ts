import { setTimeout as delay } from 'node:timers/promises'
import type { Harness } from './harness.js'

/**
 * The steps an end-to-end run performs, expressed once so the scenarios read as
 * a sequence of protocol moves rather than as fetch plumbing.
 */

/** How long to wait for the wallet's response to reach the verifier. */
const RESULT_TIMEOUT_MS = 20_000
const RESULT_POLL_INTERVAL_MS = 200

export type PresentationResult = {
  transactionId: string
  state: string
  responseMode: 'direct_post' | 'direct_post.jwt'
  status: 'pending' | 'verified' | 'failed'
  encryption?: { alg: string; kid?: string }
  vpPayload?: unknown
  error?: { error: string; error_description: string }
}

export type StoredCredential = {
  id: string
  mimeType: string
  receivedAt: string
  raw: string
  types?: string[]
  claims?: Record<string, unknown>
}

const readBody = async (response: Response) => {
  const text = await response.text()
  if (!response.ok) {
    throw new Error(`${response.status} ${response.statusText}: ${text}`)
  }
  return text
}

const postJson = async (url: string, body: unknown): Promise<Response> =>
  fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  })

/** Issuer: create an OID4VCI credential offer. */
export const createCredentialOffer = async (
  harness: Harness,
  configuration: string
): Promise<string> => {
  const response = await postJson(
    `${harness.serverUrl}/configurations/${encodeURIComponent(configuration)}/offer`,
    {}
  )
  return (await readBody(response)).trim()
}

/** Wallet: accept an offer and store the credential it yields. */
export const receiveCredential = async (
  harness: Harness,
  offer: string,
  txCode?: string
): Promise<StoredCredential> => {
  const response = await postJson(`${harness.walletUrl}/api/receive`, {
    offer,
    tx_code: txCode ?? '',
  })
  const { credential } = JSON.parse(await readBody(response))
  return credential
}

/** Wallet: everything it currently holds. */
export const listCredentials = async (harness: Harness): Promise<StoredCredential[]> => {
  const response = await fetch(`${harness.walletUrl}/api/credentials`)
  const { credentials } = JSON.parse(await readBody(response))
  return credentials
}

export type TraceEntry = {
  id: number
  at: string
  step: string
  method: string
  status: number
  notes: string[]
  request: { headers: Record<string, string>; body?: string }
  response: { headers: Record<string, string>; body?: string }
}

/** Verifier: the exchanges the sample server has taken part in. */
export const readServerTrace = async (harness: Harness): Promise<TraceEntry[]> => {
  const response = await fetch(`${harness.serverUrl}/trace`)
  const { entries } = JSON.parse(await readBody(response))
  return entries
}

/** Wallet: the exchanges it has sent. */
export const readWalletTrace = async (harness: Harness): Promise<TraceEntry[]> => {
  const response = await fetch(`${harness.walletUrl}/api/trace`)
  const { entries } = JSON.parse(await readBody(response))
  return entries
}

/** The three ways the sample verifier can ask for a presentation. */
export type RequestKind =
  /** Parameters in the URL, response returned in the clear. */
  | 'direct_post'
  /** Parameters in the URL, response encrypted to the verifier (OpenID4VP §8.3). */
  | 'direct_post.jwt'
  /** Signed Request Object fetched over request_uri, response in the clear. */
  | 'jar'

const requestEndpoint: Record<RequestKind, string> = {
  direct_post: '/request',
  'direct_post.jwt': '/request-encrypted',
  jar: '/request-object',
}

/**
 * The query language a request asks in. OpenID4VP 1.0 defines DCQL and dropped
 * Presentation Exchange, so DCQL is what the verifier asks in unless told
 * otherwise. The signed Request Object endpoint always uses Presentation
 * Exchange.
 */
export type QueryLanguage = 'dcql' | 'presentation-exchange'

/** The Credential Format a request asks for (OpenID4VP Appendix B). */
export type CredentialFormat = 'jwt_vc_json' | 'dc+sd-jwt'

export type AuthorizationRequest = {
  uri: string
  transactionId: string
  state: string
}

/** Verifier: create an authorization request and remember how to follow it up. */
export const createAuthorizationRequest = async (
  harness: Harness,
  kind: RequestKind,
  queryLanguage: QueryLanguage = 'dcql',
  credentialFormat: CredentialFormat = 'jwt_vc_json'
): Promise<AuthorizationRequest> => {
  const state = crypto.randomUUID().replaceAll('-', '')
  const body =
    kind === 'jar'
      ? { state, client_id: 'x509_san_dns:localhost', is_request_uri: true }
      : {
          credentialId: 'UniversityDegreeCredential',
          state,
          client_id: 'x509_san_dns:localhost',
          queryLanguage,
          credentialFormat,
        }

  const response = await postJson(`${harness.serverUrl}${requestEndpoint[kind]}`, body)
  const transactionId = response.headers.get('x-presentation-transaction-id')
  const uri = (await readBody(response)).trim()

  if (!transactionId) {
    throw new Error('the verifier did not return a presentation transaction id')
  }
  return { uri, transactionId, state }
}

/** Wallet: answer an authorization request. */
export const presentCredential = async (
  harness: Harness,
  request: string
): Promise<{ redirect_uri: string }> => {
  const response = await postJson(`${harness.walletUrl}/api/present`, { request })
  return JSON.parse(await readBody(response))
}

/** Verifier: what it made of a presentation, once the wallet has delivered one. */
export const readPresentationResult = async (
  harness: Harness,
  transactionId: string
): Promise<PresentationResult> => {
  const response = await fetch(
    `${harness.serverUrl}/presentations/${encodeURIComponent(transactionId)}`
  )
  return JSON.parse(await readBody(response))
}

/**
 * Waits for the verifier to record an outcome. The wallet delivers the response
 * on its own connection, so the result arrives after the call that triggered it
 * has already returned.
 */
export const waitForPresentationResult = async (
  harness: Harness,
  transactionId: string
): Promise<PresentationResult> => {
  const deadline = Date.now() + RESULT_TIMEOUT_MS
  let last: PresentationResult | undefined

  while (Date.now() < deadline) {
    last = await readPresentationResult(harness, transactionId)
    if (last.status !== 'pending') return last
    await delay(RESULT_POLL_INTERVAL_MS)
  }

  throw new Error(
    `the verifier recorded no outcome for ${transactionId} within ${RESULT_TIMEOUT_MS}ms ` +
      `(last: ${JSON.stringify(last)})\n--- process output ---\n${harness.logs()}`
  )
}
