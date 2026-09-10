/**
 * Expansion of W3C Verifiable Credential types to IRIs.
 *
 * DCQL matches `type_values` against "the fully expanded types (IRIs) that the
 * Verifier accepts in a Presentation, after applying the `@context` to the
 * Verifiable Credential" (OpenID4VP 1.0 Appendix B.1.1). A `type` entry is a
 * term the credential's `@context` maps to an IRI, so `VerifiableCredential`
 * under the standard context is really
 * `https://www.w3.org/2018/credentials#VerifiableCredential`.
 *
 * Appendix B.1.1 also says what to do with a term no context defines: it
 * "remains unchanged, i.e., remains a relative IRI after JSON-LD processing.
 * For this reason, JSON-LD processing MAY be skipped in such cases and the
 * relative IRI is considered to be the fully expanded type". It allows
 * "alternative mechanisms to obtain the fully expanded types, as long as the
 * results are equivalent to those produced by JSON-LD processing".
 *
 * That is what this module is: a table of the contexts this library issues and
 * accepts, rather than a JSON-LD processor. A term the table does not cover is
 * returned unchanged, which is what the specification prescribes for a term
 * outside every `@context`. A deployment using its own vocabulary extends
 * `CONTEXT_TERMS` with it.
 */

/** The vocabulary the W3C Verifiable Credentials contexts define their terms in. */
const CREDENTIALS_VOCABULARY = 'https://www.w3.org/2018/credentials#'

/** The vocabulary of the W3C example context, used throughout the specifications. */
const EXAMPLES_VOCABULARY = 'https://example.org/examples#'

/**
 * Term-to-IRI mappings per `@context` URL.
 *
 * Only type terms are listed: a claims path pointer addresses claims by their
 * JSON member name and never needs expansion (Appendix B.1.2).
 */
const CONTEXT_TERMS: Record<string, Record<string, string>> = {
  'https://www.w3.org/2018/credentials/v1': {
    VerifiableCredential: `${CREDENTIALS_VOCABULARY}VerifiableCredential`,
    VerifiablePresentation: `${CREDENTIALS_VOCABULARY}VerifiablePresentation`,
  },
  'https://www.w3.org/ns/credentials/v2': {
    VerifiableCredential: `${CREDENTIALS_VOCABULARY}VerifiableCredential`,
    VerifiablePresentation: `${CREDENTIALS_VOCABULARY}VerifiablePresentation`,
    EnvelopedVerifiableCredential: `${CREDENTIALS_VOCABULARY}EnvelopedVerifiableCredential`,
  },
  'https://www.w3.org/2018/credentials/examples/v1': {
    UniversityDegreeCredential: `${EXAMPLES_VOCABULARY}UniversityDegreeCredential`,
    AlumniCredential: `${EXAMPLES_VOCABULARY}AlumniCredential`,
    BachelorDegree: `${EXAMPLES_VOCABULARY}BachelorDegree`,
  },
}

/** Whether a value is already an absolute IRI, which expansion leaves alone. */
const isAbsoluteIri = (value: string): boolean => /^[a-z][a-z0-9+.-]*:/i.test(value)

/**
 * Expands one type against the contexts a Credential declares.
 *
 * The contexts are consulted in order, as JSON-LD does, so a later context may
 * define a term an earlier one did not.
 */
export const expandCredentialType = (type: string, contexts: readonly string[]): string => {
  if (isAbsoluteIri(type)) {
    return type
  }
  for (const context of contexts) {
    const iri = CONTEXT_TERMS[context]?.[type]
    if (iri) {
      return iri
    }
  }
  // No @context defines it, so it is already its own fully expanded type.
  return type
}

/** Reads the `@context` of a Credential, tolerating the single-string form. */
export const credentialContexts = (credential: unknown): string[] => {
  if (typeof credential !== 'object' || credential === null) {
    return []
  }
  const raw = (credential as Record<string, unknown>)['@context']
  if (typeof raw === 'string') {
    return [raw]
  }
  if (Array.isArray(raw)) {
    return raw.filter((entry): entry is string => typeof entry === 'string')
  }
  return []
}

/**
 * The fully expanded types of a Credential, ready to be compared with the
 * `type_values` of a Credential Query.
 */
export const expandedCredentialTypes = (
  types: readonly string[],
  contexts: readonly string[]
): string[] => types.map((type) => expandCredentialType(type, contexts))
