import { randomUUID } from 'node:crypto'
import type { ClientIdentifier, DcqlQuery } from '@trustknots/vcknots/verifier'

/** Default TTL for in-memory `direct_post` VP-aud binding transactions (10 minutes). */
export const DEFAULT_DIRECT_POST_VP_AUD_TTL_MS = 10 * 60 * 1000

type DirectPostVpAudTransaction = {
  clientId: ClientIdentifier
  state: string
  expiresAt: number
  /**
   * The request parameters an encrypted response is bound to through the
   * session_info structure of OpenID4VP §8.3.1. They are recorded once the
   * request has been created, because the nonce is minted there and the
   * response_uri is per transaction.
   */
  session?: ResponseEncryptionSessionBinding
  /**
   * The DCQL query the request carried, when it used one. The response has to be
   * checked against it, so the query has to outlive the request. A transaction
   * without one used Presentation Exchange.
   */
  dcqlQuery?: DcqlQuery
}

/** The session context needed to decrypt an encrypted Authorization Response. */
export type ResponseEncryptionSessionBinding = {
  nonce: string
  responseUri: string
}

export type DirectPostVpAudTransactionStore = {
  register: (
    clientId: ClientIdentifier,
    state: string
  ) =>
    | { ok: true; transactionId: string }
    | { ok: false; error: { error: string; error_description: string } }
  resolveExpectedAudFromWalletState: (state: string | undefined) =>
    | {
        ok: true
        aud: ClientIdentifier
        transactionId: string
        dcqlQuery?: DcqlQuery
        nonce?: string
      }
    | { ok: false; error: { error: string; error_description: string } }
  consume: (transactionId: string, state: string) => void
  /**
   * Records the request parameters an encrypted response will be bound to. The
   * request has to exist first, since it is what mints the nonce.
   */
  bindSession: (
    transactionId: string,
    session: ResponseEncryptionSessionBinding
  ) => { ok: true } | { ok: false; notFound: true }
  /**
   * Records the DCQL query the request carried, so the callback can check the
   * `vp_token` against the query that produced it.
   */
  bindDcqlQuery: (
    transactionId: string,
    query: DcqlQuery
  ) => { ok: true } | { ok: false; notFound: true }
  deleteById: (transactionId: string) => { ok: true } | { ok: false; notFound: true }
  getById: (transactionId: string) =>
    | {
        kind: 'ok'
        state: string
        clientId: ClientIdentifier
        expiresAt: number
        session?: ResponseEncryptionSessionBinding
        dcqlQuery?: DcqlQuery
      }
    | { kind: 'not_found' }
    | { kind: 'expired' }
}

/**
 * OpenID4VP `direct_post` transaction binding (see §8.2 / §13.4): server-issued `transaction_id`
 * is the primary key; OAuth `state` (wallet echoes) maps back to it for VP `aud` validation.
 */
export function createDirectPostVpAudTransactionStore(options?: {
  ttlMs?: number
}): DirectPostVpAudTransactionStore {
  const ttlMs = options?.ttlMs ?? DEFAULT_DIRECT_POST_VP_AUD_TTL_MS
  const byId = new Map<string, DirectPostVpAudTransaction>()
  const idByState = new Map<string, string>()

  const consume = (transactionId: string, state: string): void => {
    byId.delete(transactionId)
    idByState.delete(state)
  }

  const register = (
    clientId: ClientIdentifier,
    state: string
  ):
    | { ok: true; transactionId: string }
    | { ok: false; error: { error: string; error_description: string } } => {
    const existingTid = idByState.get(state)
    if (existingTid !== undefined) {
      const existingRec = byId.get(existingTid)
      if (existingRec !== undefined && Date.now() <= existingRec.expiresAt) {
        return {
          ok: false,
          error: {
            error: 'invalid_request',
            error_description: 'state is already in use for an active presentation transaction',
          },
        }
      }
      if (existingRec !== undefined) {
        consume(existingTid, existingRec.state)
      } else {
        idByState.delete(state)
      }
    }
    const transactionId = randomUUID()
    const expiresAt = Date.now() + ttlMs
    byId.set(transactionId, { clientId, state, expiresAt })
    idByState.set(state, transactionId)
    return { ok: true, transactionId }
  }

  const resolveExpectedAudFromWalletState = (
    state: string | undefined
  ):
    | {
        ok: true
        aud: ClientIdentifier
        transactionId: string
        dcqlQuery?: DcqlQuery
        nonce?: string
      }
    | { ok: false; error: { error: string; error_description: string } } => {
    if (state == null || state.trim() === '') {
      return {
        ok: false,
        error: {
          error: 'invalid_request',
          error_description: 'state is required for VP audience validation',
        },
      }
    }
    const transactionId = idByState.get(state)
    if (transactionId === undefined) {
      return {
        ok: false,
        error: {
          error: 'invalid_request',
          error_description: 'unknown or expired state',
        },
      }
    }
    const rec = byId.get(transactionId)
    if (rec === undefined) {
      idByState.delete(state)
      return {
        ok: false,
        error: {
          error: 'invalid_request',
          error_description: 'unknown or expired state',
        },
      }
    }
    if (rec.state !== state) {
      idByState.delete(state)
      consume(transactionId, rec.state)
      return {
        ok: false,
        error: {
          error: 'invalid_request',
          error_description: 'unknown or expired state',
        },
      }
    }
    if (Date.now() > rec.expiresAt) {
      consume(transactionId, state)
      return {
        ok: false,
        error: {
          error: 'invalid_request',
          error_description: 'unknown or expired state',
        },
      }
    }
    return {
      ok: true,
      aud: rec.clientId,
      transactionId,
      dcqlQuery: rec.dcqlQuery,
      nonce: rec.session?.nonce,
    }
  }

  const bindSession = (
    transactionId: string,
    session: ResponseEncryptionSessionBinding
  ): { ok: true } | { ok: false; notFound: true } => {
    const rec = byId.get(transactionId)
    if (rec === undefined) {
      return { ok: false, notFound: true }
    }
    byId.set(transactionId, { ...rec, session })
    return { ok: true }
  }

  const bindDcqlQuery = (
    transactionId: string,
    query: DcqlQuery
  ): { ok: true } | { ok: false; notFound: true } => {
    const rec = byId.get(transactionId)
    if (rec === undefined) {
      return { ok: false, notFound: true }
    }
    byId.set(transactionId, { ...rec, dcqlQuery: query })
    return { ok: true }
  }

  const deleteById = (transactionId: string): { ok: true } | { ok: false; notFound: true } => {
    const rec = byId.get(transactionId)
    if (rec === undefined) {
      return { ok: false, notFound: true }
    }
    consume(transactionId, rec.state)
    return { ok: true }
  }

  const getById = (
    transactionId: string
  ):
    | {
        kind: 'ok'
        state: string
        clientId: ClientIdentifier
        expiresAt: number
        session?: ResponseEncryptionSessionBinding
        dcqlQuery?: DcqlQuery
      }
    | { kind: 'not_found' }
    | { kind: 'expired' } => {
    const rec = byId.get(transactionId)
    if (rec === undefined) {
      return { kind: 'not_found' }
    }
    if (Date.now() > rec.expiresAt) {
      consume(transactionId, rec.state)
      return { kind: 'expired' }
    }
    return {
      kind: 'ok',
      state: rec.state,
      clientId: rec.clientId,
      expiresAt: rec.expiresAt,
      session: rec.session,
      dcqlQuery: rec.dcqlQuery,
    }
  }

  return {
    register,
    resolveExpectedAudFromWalletState,
    consume,
    bindSession,
    bindDcqlQuery,
    deleteById,
    getById,
  }
}
