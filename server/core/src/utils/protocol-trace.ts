import type { Context, MiddlewareHandler, Next } from 'hono'

/**
 * Records every HTTP exchange the sample server takes part in, so the protocol
 * flow can be watched rather than inferred from logs.
 *
 * Every OID4VCI and OID4VP message passes through this server — the wallet
 * fetches metadata, tokens and credentials from it, and posts its Authorization
 * Response back to it — so tracing here captures the whole conversation.
 *
 * It keeps request and response bodies verbatim, access tokens and
 * pre-authorized codes included. That is the point of a protocol monitor and the
 * reason this belongs in a sample server only.
 */

/** How many exchanges to keep. Older ones are dropped. */
const DEFAULT_CAPACITY = 300

/** Bodies longer than this are truncated; the entry says so. */
const MAX_BODY_LENGTH = 16_000

/** Which side of the protocol an exchange belongs to. */
export type TraceActor = 'issuer' | 'authz' | 'verifier' | 'ui'

export type TraceMessage = {
  headers: Record<string, string>
  body?: string
  /** Set when the body was pretty-printed as JSON. */
  json?: boolean
  truncated?: boolean
}

export type TraceEntry = {
  /** Monotonic, so a screen can ask for everything after what it has. */
  id: number
  at: string
  durationMs: number
  actor: TraceActor
  /** What this exchange is in protocol terms, for a reader who knows the spec. */
  step: string
  method: string
  path: string
  query?: string
  status: number
  request: TraceMessage
  response: TraceMessage
  /** Things worth pointing out, such as the algorithm an encrypted response used. */
  notes: string[]
}

export type ProtocolTrace = {
  /** Every entry, oldest first. */
  list: () => TraceEntry[]
  /** Entries recorded after `id`, for polling. */
  since: (id: number) => TraceEntry[]
  clear: () => void
  record: (entry: Omit<TraceEntry, 'id'>) => void
}

export const createProtocolTrace = (options?: { capacity?: number }): ProtocolTrace => {
  const capacity = options?.capacity ?? DEFAULT_CAPACITY
  let entries: TraceEntry[] = []
  let nextId = 1

  return {
    list: () => [...entries],
    since: (id) => entries.filter((entry) => entry.id > id),
    clear: () => {
      entries = []
    },
    record: (entry) => {
      entries.push({ ...entry, id: nextId++ })
      if (entries.length > capacity) entries = entries.slice(entries.length - capacity)
    },
  }
}

/** How each route reads in protocol terms. */
type StepRule = {
  match: (method: string, path: string) => boolean
  actor: TraceActor
  step: string
}

const stepRules: StepRule[] = [
  {
    match: (m, p) => m === 'GET' && p === '/.well-known/openid-credential-issuer',
    actor: 'issuer',
    step: 'OID4VCI · Credential Issuer Metadata',
  },
  {
    match: (m, p) => m === 'GET' && p === '/.well-known/jwt-vc-issuer',
    actor: 'issuer',
    step: 'OID4VCI · JWT VC Issuer Metadata',
  },
  {
    match: (m, p) => m === 'GET' && p === '/.well-known/oauth-authorization-server',
    actor: 'authz',
    step: 'OAuth · Authorization Server Metadata',
  },
  {
    match: (m, p) => m === 'POST' && /^\/configurations\/[^/]+\/offer$/.test(p),
    actor: 'issuer',
    step: 'OID4VCI · Credential Offer created',
  },
  {
    match: (m, p) => m === 'POST' && p === '/token',
    actor: 'authz',
    step: 'OAuth · Token Request',
  },
  { match: (m, p) => m === 'POST' && p === '/nonce', actor: 'issuer', step: 'OID4VCI · Nonce' },
  {
    match: (m, p) => m === 'POST' && p === '/credentials',
    actor: 'issuer',
    step: 'OID4VCI · Credential Request',
  },
  {
    match: (m, p) => m === 'POST' && p === '/request',
    actor: 'verifier',
    step: 'OID4VP · Authorization Request created (direct_post)',
  },
  {
    match: (m, p) => m === 'POST' && p === '/request-encrypted',
    actor: 'verifier',
    step: 'OID4VP · Authorization Request created (direct_post.jwt)',
  },
  {
    match: (m, p) => m === 'POST' && p === '/request-object',
    actor: 'verifier',
    step: 'OID4VP · Authorization Request created (signed Request Object)',
  },
  {
    match: (m, p) => m === 'GET' && p.startsWith('/request.jwt/'),
    actor: 'verifier',
    step: 'OID4VP · Request Object fetched (JAR)',
  },
  {
    match: (m, p) => m === 'POST' && /^\/callback\/[^/]+$/.test(p),
    actor: 'verifier',
    step: 'OID4VP · Authorization Response (encrypted)',
  },
  {
    match: (m, p) => m === 'POST' && (p === '/callback' || p === '/callback-kbjwt'),
    actor: 'verifier',
    step: 'OID4VP · Authorization Response',
  },
]

/** Classifies an exchange, defaulting to the screens' own traffic. */
const classify = (method: string, path: string): { actor: TraceActor; step: string } => {
  const rule = stepRules.find((candidate) => candidate.match(method, path))
  if (rule) return { actor: rule.actor, step: rule.step }
  return { actor: 'ui', step: `${method} ${path}` }
}

const base64UrlDecode = (value: string) => Buffer.from(value, 'base64url').toString('utf8')

/** Reads a compact JOSE header without verifying anything. */
const readJoseHeader = (token: string): Record<string, unknown> | undefined => {
  const [header] = token.split('.')
  if (!header) return undefined
  try {
    const parsed = JSON.parse(base64UrlDecode(header))
    return typeof parsed === 'object' && parsed !== null ? parsed : undefined
  } catch {
    return undefined
  }
}

/**
 * Points out what a reader would otherwise have to decode by hand: the header of
 * an encrypted response, the algorithm of a signed Request Object, and so on.
 */
const describe = (
  method: string,
  path: string,
  request: TraceMessage,
  response: TraceMessage
): string[] => {
  const notes: string[] = []

  if (request.headers.dpop) notes.push('Carries a DPoP proof')
  if (request.headers.authorization) {
    const [scheme] = request.headers.authorization.split(' ')
    notes.push(`Authorization: ${scheme}`)
  }

  if (method === 'POST' && /^\/callback\/[^/]+$/.test(path) && request.body) {
    const response = new URLSearchParams(request.body).get('response')
    const header = response ? readJoseHeader(response) : undefined
    if (header) {
      notes.push(
        `JWE protected header: alg=${header.alg}${header.kid ? `, kid=${header.kid}` : ''}`
      )
      if (typeof header.alg === 'string' && /^HPKE-\d$/.test(header.alg)) {
        notes.push(
          'JOSE HPKE Integrated Encryption: the encapsulated secret is the JWE Encrypted Key, ' +
            'and the initialization vector and authentication tag are empty'
        )
      }
      if (header.enc) notes.push(`Content encryption: enc=${header.enc}`)
    }
  }

  if (method === 'GET' && path.startsWith('/request.jwt/') && response.body) {
    const header = readJoseHeader(response.body.trim())
    if (header) {
      notes.push(
        `JWS protected header: alg=${header.alg}${header.typ ? `, typ=${header.typ}` : ''}` +
          (Array.isArray(header.x5c) ? `, x5c (${header.x5c.length} certificate(s))` : '')
      )
    }
  }

  return notes
}

/** Header names worth showing. The rest is transport noise. */
const interestingHeaders = new Set([
  'content-type',
  'authorization',
  'dpop',
  'dpop-nonce',
  'accept',
  'location',
  'x-presentation-transaction-id',
])

const collectHeaders = (headers: Headers): Record<string, string> => {
  const collected: Record<string, string> = {}
  headers.forEach((value, name) => {
    if (interestingHeaders.has(name.toLowerCase())) collected[name.toLowerCase()] = value
  })
  return collected
}

/** Pretty-prints JSON so the screen does not have to, and caps the length. */
const toMessage = (headers: Headers, body: string): TraceMessage => {
  const message: TraceMessage = { headers: collectHeaders(headers) }
  if (!body) return message

  let text = body
  try {
    text = JSON.stringify(JSON.parse(body), null, 2)
    message.json = true
  } catch {
    // Not JSON: a form body, a JWT or a JWE. Show it as it went over the wire.
  }

  if (text.length > MAX_BODY_LENGTH) {
    text = text.slice(0, MAX_BODY_LENGTH)
    message.truncated = true
  }
  message.body = text
  return message
}

/**
 * Records each exchange into the trace.
 *
 * Both bodies are read from clones. Reading the request through `c.req.text()`
 * would populate Hono's body cache, and a handler that later asks for
 * `formData()` gets that cached text rebuilt into a response without its
 * Content-Type — which makes form parsing fail. Cloning leaves the request the
 * handlers see untouched, and the same applies to the response going back out.
 */
export const protocolTraceMiddleware = (trace: ProtocolTrace): MiddlewareHandler => {
  return async (c: Context, next: Next) => {
    const startedAt = Date.now()
    const method = c.req.method
    const url = new URL(c.req.url)

    let requestBody = ''
    if (method !== 'GET' && method !== 'HEAD') {
      requestBody = await c.req.raw
        .clone()
        .text()
        .catch(() => '')
    }

    await next()

    let responseBody = ''
    try {
      responseBody = await c.res.clone().text()
    } catch {
      // A streamed or already-consumed response; the metadata is still worth having.
    }

    const request = toMessage(c.req.raw.headers, requestBody)
    const response = toMessage(c.res.headers, responseBody)
    const { actor, step } = classify(method, url.pathname)

    trace.record({
      at: new Date(startedAt).toISOString(),
      durationMs: Date.now() - startedAt,
      actor,
      step,
      method,
      path: url.pathname,
      query: url.search ? url.search.slice(1) : undefined,
      status: c.res.status,
      request,
      response,
      notes: describe(method, url.pathname, request, response),
    })
  }
}
