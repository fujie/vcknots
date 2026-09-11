import type { ClientIdentifier } from '@trustknots/vcknots/verifier'

/** Default TTL for a recorded presentation result (30 minutes). */
export const DEFAULT_PRESENTATION_RESULT_TTL_MS = 30 * 60 * 1000

/** How the wallet was asked to return the Authorization Response. */
export type PresentationResponseMode = 'direct_post' | 'direct_post.jwt'

/**
 * What the verifier learned about the encryption of a response, read from the
 * JWE protected header. Only present for the `.jwt` response modes.
 */
export type PresentationEncryptionInfo = {
  alg: string
  kid?: string
}

export type PresentationResult = {
  transactionId: string
  state: string
  clientId: ClientIdentifier
  responseMode: PresentationResponseMode
  /** Where the wallet was told to deliver the response. */
  responseUri: string
  status: 'pending' | 'verified' | 'failed'
  createdAt: number
  completedAt?: number
  encryption?: PresentationEncryptionInfo
  vpPayload?: unknown
  error?: { error: string; error_description: string }
}

export type PresentationResultStore = {
  /** Records a presentation the verifier has just asked for. */
  start: (
    result: Pick<
      PresentationResult,
      'transactionId' | 'state' | 'clientId' | 'responseMode' | 'responseUri'
    >
  ) => void
  /** Records a response that verified, together with the VP payload it carried. */
  succeed: (
    transactionId: string,
    vpPayload: unknown,
    encryption?: PresentationEncryptionInfo
  ) => void
  /** Records a response that did not verify. */
  fail: (
    transactionId: string,
    error: { error: string; error_description: string },
    encryption?: PresentationEncryptionInfo
  ) => void
  get: (transactionId: string) => PresentationResult | undefined
  /** Every result that has not expired, newest first. */
  list: () => PresentationResult[]
}

/**
 * Keeps the outcome of each presentation so that a verification screen can poll
 * for it after the wallet has posted its Authorization Response.
 *
 * The wallet delivers the response out of band, on its own connection, so the
 * browser that started the presentation has no other way to learn what
 * happened. This store is in memory and therefore single-process only, which is
 * all the sample server needs.
 */
export function createPresentationResultStore(options?: {
  ttlMs?: number
}): PresentationResultStore {
  const ttlMs = options?.ttlMs ?? DEFAULT_PRESENTATION_RESULT_TTL_MS
  const byId = new Map<string, PresentationResult>()

  const dropExpired = () => {
    const now = Date.now()
    for (const [id, result] of byId) {
      if (now - result.createdAt > ttlMs) byId.delete(id)
    }
  }

  const complete = (
    transactionId: string,
    patch: Pick<PresentationResult, 'status' | 'vpPayload' | 'error'>,
    encryption?: PresentationEncryptionInfo
  ) => {
    const current = byId.get(transactionId)
    if (!current) return
    byId.set(transactionId, {
      ...current,
      ...patch,
      completedAt: Date.now(),
      encryption: encryption ?? current.encryption,
    })
  }

  return {
    start(result) {
      dropExpired()
      byId.set(result.transactionId, { ...result, status: 'pending', createdAt: Date.now() })
    },

    succeed(transactionId, vpPayload, encryption) {
      complete(transactionId, { status: 'verified', vpPayload }, encryption)
    },

    fail(transactionId, error, encryption) {
      complete(transactionId, { status: 'failed', error }, encryption)
    },

    get(transactionId) {
      dropExpired()
      return byId.get(transactionId)
    },

    list() {
      dropExpired()
      return [...byId.values()].sort((a, b) => b.createdAt - a.createdAt)
    },
  }
}

/**
 * Reads `alg` and `kid` out of a JWE compact serialization without decrypting,
 * so the verification screen can show which algorithm the wallet chose.
 * Malformed input yields undefined rather than throwing: this is display data,
 * and the decryption step is what decides whether a response is acceptable.
 */
export const readResponseEncryptionInfo = (
  response: string
): PresentationEncryptionInfo | undefined => {
  const [protectedHeader] = response.split('.')
  if (!protectedHeader) return undefined
  try {
    const header = JSON.parse(Buffer.from(protectedHeader, 'base64url').toString('utf8'))
    if (typeof header?.alg !== 'string') return undefined
    return { alg: header.alg, kid: typeof header.kid === 'string' ? header.kid : undefined }
  } catch {
    return undefined
  }
}
