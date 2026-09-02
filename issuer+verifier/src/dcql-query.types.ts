import { z } from 'zod'
import { DeepPartialUnknown } from './type.utils'

/**
 * The Digital Credentials Query Language of OpenID4VP 1.0 Section 6.
 *
 * DCQL replaces Presentation Exchange as the query language: the Verifier states
 * which Credentials and claims it wants, and the Wallet evaluates the query
 * against what it holds.
 *
 * Section 6 ends with "Implementations MUST ignore any unknown properties", so
 * every object here stays open rather than rejecting what a future extension
 * adds.
 */

/**
 * Identifiers in DCQL are restricted so they can be used as keys in the
 * `vp_token` object of the response (Section 8.1).
 */
const dcqlIdentifierSchema = z
  .string()
  .min(1)
  .regex(/^[A-Za-z0-9_-]+$/, 'must consist of alphanumeric, underscore or hyphen characters')

/**
 * A claims path pointer (Section 7): a string selects a key, a non-negative
 * integer selects an array index, and null selects every element of an array.
 */
export const claimsPathPointerSchema = z
  .array(z.union([z.string(), z.int().nonnegative(), z.null()]))
  .nonempty()

/** A Claims Query (Section 6.3). */
export const dcqlClaimsQuerySchema = z.looseObject({
  /** REQUIRED when `claim_sets` is present in the Credential Query. */
  id: dcqlIdentifierSchema.optional(),
  path: claimsPathPointerSchema,
  /**
   * Expected values for the claim. The specification is explicit that this is a
   * best-effort privacy aid and MUST NOT be relied on for security checks.
   */
  values: z
    .array(z.union([z.string(), z.int(), z.boolean()]))
    .nonempty()
    .optional(),
})

/** A Trusted Authorities Query (Section 6.1.1). */
export const dcqlTrustedAuthoritySchema = z.looseObject({
  type: z.string().min(1),
  values: z.array(z.string()).nonempty(),
})

/** A Credential Query (Section 6.1). */
export const dcqlCredentialQuerySchema = z.looseObject({
  id: dcqlIdentifierSchema,
  format: z.string().min(1),
  /** Whether more than one Credential may be returned. Defaults to false. */
  multiple: z.boolean().optional(),
  /**
   * Format-specific constraints on metadata and validity, such as `vct_values`
   * for `dc+sd-jwt` or `type_values` for `jwt_vc_json`. An empty object places
   * no constraints.
   */
  meta: z.record(z.string(), z.unknown()),
  trusted_authorities: z.array(dcqlTrustedAuthoritySchema).nonempty().optional(),
  /** Defaults to true: a Verifiable Presentation with holder binding is required. */
  require_cryptographic_holder_binding: z.boolean().optional(),
  claims: z.array(dcqlClaimsQuerySchema).nonempty().optional(),
  /** Alternative combinations of `claims` ids, most preferred first. */
  claim_sets: z.array(z.array(dcqlIdentifierSchema).nonempty()).nonempty().optional(),
})

/** A Credential Set Query (Section 6.2). */
export const dcqlCredentialSetQuerySchema = z.looseObject({
  /** Each option is a set of Credential Query ids that satisfies the use case. */
  options: z.array(z.array(dcqlIdentifierSchema).nonempty()).nonempty(),
  /** Defaults to true. */
  required: z.boolean().optional(),
})

const dcqlQueryShape = z.looseObject({
  credentials: z.array(dcqlCredentialQuerySchema).nonempty(),
  credential_sets: z.array(dcqlCredentialSetQuerySchema).nonempty().optional(),
})

/**
 * The constraints Section 6 states in prose rather than in the object shapes:
 * ids are unique, `claim_sets` needs `claims`, and every id referenced from
 * elsewhere has to exist.
 */
const dcqlQuerySchema = dcqlQueryShape.superRefine((query, ctx) => {
  const seen = new Set<string>()
  for (const [index, credential] of query.credentials.entries()) {
    if (seen.has(credential.id)) {
      ctx.addIssue({
        code: 'custom',
        path: ['credentials', index, 'id'],
        message: `Credential Query id "${credential.id}" is used more than once.`,
      })
    }
    seen.add(credential.id)

    // Section 6.1: claim_sets MUST NOT be present if claims is absent.
    if (credential.claim_sets && !credential.claims) {
      ctx.addIssue({
        code: 'custom',
        path: ['credentials', index, 'claim_sets'],
        message: 'claim_sets must not be present when claims is absent.',
      })
    }

    if (credential.claims) {
      const claimIds = new Set<string>()
      for (const [claimIndex, claim] of credential.claims.entries()) {
        if (claim.id === undefined) {
          // Section 6.3: id is REQUIRED when claim_sets is present.
          if (credential.claim_sets) {
            ctx.addIssue({
              code: 'custom',
              path: ['credentials', index, 'claims', claimIndex, 'id'],
              message: 'claims[].id is required when claim_sets is present.',
            })
          }
          continue
        }
        if (claimIds.has(claim.id)) {
          ctx.addIssue({
            code: 'custom',
            path: ['credentials', index, 'claims', claimIndex, 'id'],
            message: `Claims Query id "${claim.id}" is used more than once.`,
          })
        }
        claimIds.add(claim.id)
      }

      for (const [setIndex, set] of (credential.claim_sets ?? []).entries()) {
        for (const [idIndex, id] of set.entries()) {
          if (!claimIds.has(id)) {
            ctx.addIssue({
              code: 'custom',
              path: ['credentials', index, 'claim_sets', setIndex, idIndex],
              message: `claim_sets references unknown claims id "${id}".`,
            })
          }
        }
      }
    }
  }

  for (const [setIndex, set] of (query.credential_sets ?? []).entries()) {
    for (const [optionIndex, option] of set.options.entries()) {
      for (const [idIndex, id] of option.entries()) {
        if (!seen.has(id)) {
          ctx.addIssue({
            code: 'custom',
            path: ['credential_sets', setIndex, 'options', optionIndex, idIndex],
            message: `credential_sets references unknown Credential Query id "${id}".`,
          })
        }
      }
    }
  }
})

export type DcqlClaimsPathPointer = z.infer<typeof claimsPathPointerSchema>
export type DcqlClaimsQuery = z.infer<typeof dcqlClaimsQuerySchema>
export type DcqlTrustedAuthority = z.infer<typeof dcqlTrustedAuthoritySchema>
export type DcqlCredentialQuery = z.infer<typeof dcqlCredentialQuerySchema>
export type DcqlCredentialSetQuery = z.infer<typeof dcqlCredentialSetQuerySchema>

export type DcqlQuery = z.infer<typeof dcqlQuerySchema>
export const DcqlQuery = (value?: DeepPartialUnknown<DcqlQuery>) => dcqlQuerySchema.parse(value)
DcqlQuery.schema = dcqlQuerySchema

/** Whether the Credential Query accepts more than one Credential. */
export const allowsMultiple = (credential: DcqlCredentialQuery): boolean =>
  credential.multiple ?? false

/** Whether the Credential Query requires Cryptographic Holder Binding. */
export const requiresHolderBinding = (credential: DcqlCredentialQuery): boolean =>
  credential.require_cryptographic_holder_binding ?? true

/** Whether the Credential Set Query has to be satisfied. */
export const isRequiredSet = (set: DcqlCredentialSetQuery): boolean => set.required ?? true
