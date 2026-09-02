import {
  allowsMultiple,
  DcqlClaimsPathPointer,
  DcqlClaimsQuery,
  DcqlCredentialQuery,
  DcqlQuery,
  isRequiredSet,
} from './dcql-query.types'

/**
 * Evaluating a DCQL query against Credentials: the claims path pointer of
 * OpenID4VP 1.0 Section 7, claim selection from Section 6.4.1, and Credential
 * selection from Section 6.4.2.
 *
 * The rules are shared between the two sides of the protocol. A Wallet uses them
 * to choose what to present; a Verifier uses them to check that what came back
 * actually answers what it asked. Nothing here inspects signatures — that is the
 * job of the per-format verification providers.
 */

/** The outcome of applying a claims path pointer to a Credential. */
export type ClaimsPathResult =
  | { matched: true; values: unknown[] }
  | { matched: false; reason: string }

const isPlainObject = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value)

/**
 * Applies a claims path pointer to a JSON-based Credential
 * (Section 7.1.1).
 *
 * A pointer that cannot be resolved is reported rather than thrown: for both the
 * Wallet and the Verifier, "this claim is not in this Credential" is an ordinary
 * outcome that decides whether the Credential matches.
 */
export const resolveClaimsPath = (
  credential: unknown,
  path: DcqlClaimsPathPointer
): ClaimsPathResult => {
  let selected: unknown[] = [credential]

  for (const [index, component] of path.entries()) {
    const next: unknown[] = []

    if (typeof component === 'string') {
      for (const element of selected) {
        // A non-object under a key component is a malformed pointer for this
        // Credential, not a missing claim.
        if (!isPlainObject(element)) {
          return { matched: false, reason: `path[${index}]: expected an object at "${component}"` }
        }
        // A key that is absent simply drops that element from the selection.
        if (component in element) next.push(element[component])
      }
    } else if (component === null) {
      for (const element of selected) {
        if (!Array.isArray(element)) {
          return {
            matched: false,
            reason: `path[${index}]: expected an array for the null component`,
          }
        }
        next.push(...element)
      }
    } else {
      for (const element of selected) {
        if (!Array.isArray(element)) {
          return {
            matched: false,
            reason: `path[${index}]: expected an array at index ${component}`,
          }
        }
        if (component < element.length) next.push(element[component])
      }
    }

    selected = next
  }

  if (selected.length === 0) {
    return { matched: false, reason: 'the path selected no element' }
  }
  return { matched: true, values: selected }
}

/**
 * Whether a resolved claim satisfies the `values` restriction of a Claims Query
 * (Section 6.3): the type and the value must both match one of the entries.
 */
export const claimMatchesValues = (
  resolved: unknown[],
  expected: DcqlClaimsQuery['values']
): boolean => {
  if (!expected) return true
  return resolved.some((value) =>
    expected.some((candidate) => typeof candidate === typeof value && candidate === value)
  )
}

/** Whether one Claims Query is satisfied by the Credential. */
const claimIsPresent = (credential: unknown, claim: DcqlClaimsQuery): boolean => {
  const resolved = resolveClaimsPath(credential, claim.path)
  return resolved.matched && claimMatchesValues(resolved.values, claim.values)
}

export type ClaimSelection =
  | { satisfied: true; claims: DcqlClaimsQuery[] }
  | { satisfied: false; reason: string }

/**
 * Chooses the claims to present for one Credential Query (Section 6.4.1).
 *
 * With no `claims`, only the mandatory claims are requested and nothing needs
 * selecting. With `claims` but no `claim_sets`, every listed claim is required.
 * With both, the first satisfiable option wins, since the array order is the
 * Verifier's order of preference.
 */
export const selectClaims = (
  credentialQuery: DcqlCredentialQuery,
  credential: unknown
): ClaimSelection => {
  const claims = credentialQuery.claims
  if (!claims) return { satisfied: true, claims: [] }

  if (!credentialQuery.claim_sets) {
    const missing = claims.filter((claim) => !claimIsPresent(credential, claim))
    if (missing.length > 0) {
      return {
        satisfied: false,
        reason: `the credential does not carry ${missing.length} of the ${claims.length} requested claim(s)`,
      }
    }
    return { satisfied: true, claims }
  }

  const byId = new Map(
    claims.filter((claim) => claim.id).map((claim) => [claim.id as string, claim])
  )
  for (const option of credentialQuery.claim_sets) {
    const wanted = option
      .map((id) => byId.get(id))
      .filter((claim): claim is DcqlClaimsQuery => !!claim)
    if (wanted.length !== option.length) continue
    if (wanted.every((claim) => claimIsPresent(credential, claim))) {
      return { satisfied: true, claims: wanted }
    }
  }

  return { satisfied: false, reason: 'the credential satisfies none of the claim_sets options' }
}

/**
 * Whether a Credential satisfies the format-specific `meta` of a Credential
 * Query. Only the formats this library handles are checked; an unrecognised
 * constraint is left to the caller rather than silently treated as satisfied.
 */
export const matchesMeta = (
  credentialQuery: DcqlCredentialQuery,
  credential: unknown
): { matched: true } | { matched: false; reason: string } => {
  const meta = credentialQuery.meta ?? {}

  // SD-JWT VC: the vct claim must be one of vct_values (Appendix B.3.5).
  const vctValues = meta.vct_values
  if (Array.isArray(vctValues)) {
    const vct = isPlainObject(credential) ? credential.vct : undefined
    if (typeof vct !== 'string' || !vctValues.includes(vct)) {
      return { matched: false, reason: `vct ${JSON.stringify(vct)} is not among vct_values` }
    }
  }

  // W3C VC: one inner array of type_values must be fully present in the
  // credential's types (Appendix B.1.1).
  const typeValues = meta.type_values
  if (Array.isArray(typeValues)) {
    const vc = isPlainObject(credential) ? credential.vc : undefined
    const rawTypes = isPlainObject(vc)
      ? vc.type
      : isPlainObject(credential)
        ? credential.type
        : undefined
    const types = Array.isArray(rawTypes)
      ? rawTypes.filter((t): t is string => typeof t === 'string')
      : []
    const satisfied = typeValues.some(
      (option) => Array.isArray(option) && option.every((type) => types.includes(type as string))
    )
    if (!satisfied) {
      return {
        matched: false,
        reason: 'the credential types match none of the type_values options',
      }
    }
  }

  return { matched: true }
}

export type CredentialMatch =
  | { matched: true; claims: DcqlClaimsQuery[] }
  | { matched: false; reason: string }

/**
 * Whether one Credential answers one Credential Query: the format, the
 * format-specific metadata, and the requested claims.
 *
 * `credential` is the decoded claim set, not the encoded Credential.
 */
export const matchesCredentialQuery = (
  credentialQuery: DcqlCredentialQuery,
  credential: { format: string; claims: unknown }
): CredentialMatch => {
  if (credential.format !== credentialQuery.format) {
    return {
      matched: false,
      reason: `format ${credential.format} does not match ${credentialQuery.format}`,
    }
  }

  const meta = matchesMeta(credentialQuery, credential.claims)
  if (!meta.matched) return { matched: false, reason: meta.reason }

  const selection = selectClaims(credentialQuery, credential.claims)
  if (!selection.satisfied) return { matched: false, reason: selection.reason }

  return { matched: true, claims: selection.claims }
}

/**
 * The Credential Query ids the Wallet is expected to answer (Section 6.4.2).
 *
 * Without `credential_sets` every Credential Query must be answered. With them,
 * each required set contributes one of its options, and the optional sets are
 * left to the Wallet.
 */
export const requiredCredentialIds = (
  query: DcqlQuery
): { required: string[][]; optional: string[][] } => {
  if (!query.credential_sets) {
    return { required: query.credentials.map((credential) => [credential.id]), optional: [] }
  }

  const required: string[][] = []
  const optional: string[][] = []
  for (const set of query.credential_sets) {
    // Each set is satisfied by any one of its options.
    ;(isRequiredSet(set) ? required : optional).push(...set.options.map((option) => [...option]))
  }
  return { required, optional }
}

export type VpTokenValidation = { valid: true } | { valid: false; reason: string }

/**
 * Checks the shape of a `vp_token` against the DCQL query that produced it
 * (Section 8.1 and Section 6.4.2).
 *
 * This is structural only: that the keys name Credential Queries, that the
 * arrays are non-empty, that `multiple` is respected, and that the required
 * Credential Set Queries are answered. Whether each Presentation verifies is
 * decided elsewhere.
 */
export const validateVpTokenAgainstQuery = (
  query: DcqlQuery,
  vpToken: Record<string, unknown>
): VpTokenValidation => {
  const answered = Object.keys(vpToken)

  if (answered.length === 0) {
    return { valid: false, reason: 'vp_token is empty' }
  }

  for (const id of answered) {
    const credentialQuery = query.credentials.find((credential) => credential.id === id)
    if (!credentialQuery) {
      return {
        valid: false,
        reason: `vp_token contains "${id}", which is not a Credential Query id`,
      }
    }
    const presentations = vpToken[id]
    if (!Array.isArray(presentations) || presentations.length === 0) {
      return { valid: false, reason: `vp_token["${id}"] must be a non-empty array` }
    }
    if (presentations.length > 1 && !allowsMultiple(credentialQuery)) {
      return {
        valid: false,
        reason: `vp_token["${id}"] holds ${presentations.length} presentations but multiple was not requested`,
      }
    }
  }

  // Every required Credential Set Query needs one of its options answered in
  // full. Without credential_sets, each Credential Query is its own requirement.
  const present = new Set(answered)
  const requirements = query.credential_sets
    ? query.credential_sets.filter(isRequiredSet).map((set) => set.options)
    : query.credentials.map((credential) => [[credential.id]])

  for (const options of requirements) {
    const satisfied = options.some((option) => option.every((id) => present.has(id)))
    if (!satisfied) {
      return {
        valid: false,
        reason: `no option of a required credential query is fully answered (${JSON.stringify(options)})`,
      }
    }
  }

  return { valid: true }
}
