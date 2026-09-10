import assert from 'node:assert/strict'
import { describe, it } from 'node:test'
import { expandCredentialType } from '../src/credential-type-iri'
import {
  matchesCredentialQuery,
  resolveClaimsPath,
  selectClaims,
  validateVpTokenAgainstQuery,
} from '../src/dcql'
import { DcqlQuery } from '../src/dcql-query.types'

/**
 * The Credential from OpenID4VP 1.0 Section 7.3, so the path pointer cases below
 * are the ones the specification itself works through.
 */
const arthur = {
  name: 'Arthur Dent',
  address: {
    street_address: '42 Market Street',
    locality: 'Milliways',
    postal_code: '12345',
  },
  degrees: [
    { type: 'Bachelor of Science', university: 'University of Betelgeuse' },
    { type: 'Master of Science', university: 'University of Betelgeuse' },
  ],
  nationalities: ['British', 'Betelgeusian'],
}

describe('claims path pointer', () => {
  describe('the examples in Section 7.3', () => {
    it('selects a top-level claim', () => {
      const result = resolveClaimsPath(arthur, ['name'])
      assert.deepEqual(result, { matched: true, values: ['Arthur Dent'] })
    })

    it('selects an object with its sub-claims', () => {
      const result = resolveClaimsPath(arthur, ['address'])
      assert.ok(result.matched)
      assert.deepEqual(result.values, [arthur.address])
    })

    it('selects a nested claim', () => {
      const result = resolveClaimsPath(arthur, ['address', 'street_address'])
      assert.deepEqual(result, { matched: true, values: ['42 Market Street'] })
    })

    it('selects every element of an array with null', () => {
      const result = resolveClaimsPath(arthur, ['degrees', null, 'type'])
      assert.ok(result.matched)
      assert.deepEqual(result.values, ['Bachelor of Science', 'Master of Science'])
    })

    it('selects an array element by index', () => {
      const result = resolveClaimsPath(arthur, ['nationalities', 1])
      assert.deepEqual(result, { matched: true, values: ['Betelgeusian'] })
    })
  })

  describe('Section 7.1.1 processing rules', () => {
    it('reports a path that selects nothing', () => {
      const result = resolveClaimsPath(arthur, ['nickname'])
      assert.equal(result.matched, false)
    })

    it('drops elements that lack the key rather than failing', () => {
      const credential = { people: [{ name: 'a' }, { other: 'b' }, { name: 'c' }] }
      const result = resolveClaimsPath(credential, ['people', null, 'name'])
      assert.ok(result.matched)
      assert.deepEqual(result.values, ['a', 'c'])
    })

    it('drops arrays where the index does not exist', () => {
      const result = resolveClaimsPath(arthur, ['nationalities', 5])
      assert.equal(result.matched, false)
    })

    it('rejects a key component applied to a non-object', () => {
      const result = resolveClaimsPath(arthur, ['name', 'first'])
      assert.equal(result.matched, false)
      assert.ok(!result.matched && result.reason.includes('expected an object'))
    })

    it('rejects a null component applied to a non-array', () => {
      const result = resolveClaimsPath(arthur, ['address', null])
      assert.equal(result.matched, false)
      assert.ok(!result.matched && result.reason.includes('expected an array'))
    })

    it('rejects an index component applied to a non-array', () => {
      const result = resolveClaimsPath(arthur, ['address', 0])
      assert.equal(result.matched, false)
    })
  })
})

describe('claim selection (Section 6.4.1)', () => {
  const query = (claims?: unknown, claimSets?: unknown) =>
    DcqlQuery({
      credentials: [
        {
          id: 'c',
          format: 'dc+sd-jwt',
          meta: {},
          ...(claims ? { claims } : {}),
          ...(claimSets ? { claim_sets: claimSets } : {}),
        },
      ],
    }).credentials[0]

  it('requests nothing selectively disclosable when claims is absent', () => {
    const selection = selectClaims(query(), arthur)
    assert.deepEqual(selection, { satisfied: true, claims: [] })
  })

  it('requires every claim when claim_sets is absent', () => {
    const satisfied = selectClaims(query([{ path: ['name'] }, { path: ['address'] }]), arthur)
    assert.equal(satisfied.satisfied, true)

    const missing = selectClaims(query([{ path: ['name'] }, { path: ['nickname'] }]), arthur)
    assert.equal(missing.satisfied, false)
  })

  it('takes the first satisfiable claim_sets option', () => {
    const selection = selectClaims(
      query(
        [
          { id: 'nickname', path: ['nickname'] },
          { id: 'name', path: ['name'] },
        ],
        [['nickname'], ['name']]
      ),
      arthur
    )
    assert.ok(selection.satisfied)
    // The first option cannot be satisfied, so the second is used.
    assert.deepEqual(
      selection.claims.map((claim) => claim.id),
      ['name']
    )
  })

  it('returns nothing when no claim_sets option can be satisfied', () => {
    const selection = selectClaims(
      query([{ id: 'nickname', path: ['nickname'] }], [['nickname']]),
      arthur
    )
    assert.equal(selection.satisfied, false)
  })

  it('treats a claim whose value does not match as absent', () => {
    const matching = selectClaims(query([{ path: ['name'], values: ['Arthur Dent'] }]), arthur)
    assert.equal(matching.satisfied, true)

    const mismatched = selectClaims(query([{ path: ['name'], values: ['Ford Prefect'] }]), arthur)
    assert.equal(mismatched.satisfied, false)
  })

  it('matches values on type as well as value', () => {
    const credential = { age_over_18: true }
    const asBoolean = selectClaims(query([{ path: ['age_over_18'], values: [true] }]), credential)
    assert.equal(asBoolean.satisfied, true)

    // "true" is a string, so it must not match the boolean true.
    const asString = selectClaims(query([{ path: ['age_over_18'], values: ['true'] }]), credential)
    assert.equal(asString.satisfied, false)
  })
})

describe('credential query matching', () => {
  it('checks the format', () => {
    const credentialQuery = DcqlQuery({
      credentials: [{ id: 'c', format: 'dc+sd-jwt', meta: {} }],
    }).credentials[0]

    assert.equal(
      matchesCredentialQuery(credentialQuery, { format: 'jwt_vc_json', claims: {} }).matched,
      false
    )
    assert.equal(
      matchesCredentialQuery(credentialQuery, { format: 'dc+sd-jwt', claims: {} }).matched,
      true
    )
  })

  it('checks vct_values for SD-JWT VC', () => {
    const credentialQuery = DcqlQuery({
      credentials: [
        {
          id: 'c',
          format: 'dc+sd-jwt',
          meta: { vct_values: ['https://credentials.example.com/identity_credential'] },
        },
      ],
    }).credentials[0]

    const match = matchesCredentialQuery(credentialQuery, {
      format: 'dc+sd-jwt',
      claims: { vct: 'https://credentials.example.com/identity_credential' },
    })
    assert.equal(match.matched, true)

    const other = matchesCredentialQuery(credentialQuery, {
      format: 'dc+sd-jwt',
      claims: { vct: 'https://credentials.example.com/other' },
    })
    assert.equal(other.matched, false)
  })

  it('checks type_values for W3C VC', () => {
    const credentialQuery = DcqlQuery({
      credentials: [
        {
          id: 'c',
          format: 'jwt_vc_json',
          meta: { type_values: [['VerifiableCredential', 'UniversityDegreeCredential']] },
        },
      ],
    }).credentials[0]

    const match = matchesCredentialQuery(credentialQuery, {
      format: 'jwt_vc_json',
      claims: { vc: { type: ['VerifiableCredential', 'UniversityDegreeCredential'] } },
    })
    assert.equal(match.matched, true)

    // An inner array must be present in full.
    const partial = matchesCredentialQuery(credentialQuery, {
      format: 'jwt_vc_json',
      claims: { vc: { type: ['VerifiableCredential'] } },
    })
    assert.equal(partial.matched, false)
  })
})

describe('vp_token structure (Section 8.1)', () => {
  const singleQuery = DcqlQuery({
    credentials: [{ id: 'my_credential', format: 'dc+sd-jwt', meta: {} }],
  })

  it('accepts the shape the specification shows', () => {
    const result = validateVpTokenAgainstQuery(singleQuery, { my_credential: ['eyJhbGci...QMA'] })
    assert.deepEqual(result, { valid: true })
  })

  it('rejects a key that is not a Credential Query id', () => {
    const result = validateVpTokenAgainstQuery(singleQuery, { other: ['eyJ'] })
    assert.equal(result.valid, false)
  })

  it('rejects an empty vp_token', () => {
    assert.equal(validateVpTokenAgainstQuery(singleQuery, {}).valid, false)
  })

  it('rejects a value that is not a non-empty array', () => {
    assert.equal(validateVpTokenAgainstQuery(singleQuery, { my_credential: 'eyJ' }).valid, false)
    assert.equal(validateVpTokenAgainstQuery(singleQuery, { my_credential: [] }).valid, false)
  })

  it('rejects several presentations when multiple was not requested', () => {
    const result = validateVpTokenAgainstQuery(singleQuery, { my_credential: ['a', 'b'] })
    assert.equal(result.valid, false)
  })

  it('accepts several presentations when multiple is true', () => {
    const query = DcqlQuery({
      credentials: [{ id: 'my_credential', format: 'dc+sd-jwt', meta: {}, multiple: true }],
    })
    assert.equal(validateVpTokenAgainstQuery(query, { my_credential: ['a', 'b'] }).valid, true)
  })

  describe('credential_sets (Section 6.4.2)', () => {
    const query = DcqlQuery({
      credentials: [
        { id: 'pid', format: 'dc+sd-jwt', meta: {} },
        { id: 'passport', format: 'dc+sd-jwt', meta: {} },
        { id: 'nice_to_have', format: 'dc+sd-jwt', meta: {} },
      ],
      credential_sets: [
        { options: [['pid'], ['passport']] },
        { options: [['nice_to_have']], required: false },
      ],
    })

    it('accepts one option of the required set', () => {
      assert.equal(validateVpTokenAgainstQuery(query, { pid: ['a'] }).valid, true)
      assert.equal(validateVpTokenAgainstQuery(query, { passport: ['a'] }).valid, true)
    })

    it('rejects a response that answers no option of the required set', () => {
      const result = validateVpTokenAgainstQuery(query, { nice_to_have: ['a'] })
      assert.equal(result.valid, false)
    })

    it('does not require the optional set', () => {
      assert.equal(validateVpTokenAgainstQuery(query, { pid: ['a'] }).valid, true)
    })
  })
})

describe('DcqlQuery validation', () => {
  it('rejects duplicate Credential Query ids', () => {
    assert.throws(() =>
      DcqlQuery({
        credentials: [
          { id: 'c', format: 'dc+sd-jwt', meta: {} },
          { id: 'c', format: 'dc+sd-jwt', meta: {} },
        ],
      })
    )
  })

  it('rejects claim_sets without claims', () => {
    assert.throws(() =>
      DcqlQuery({
        credentials: [{ id: 'c', format: 'dc+sd-jwt', meta: {}, claim_sets: [['a']] }],
      })
    )
  })

  it('requires claims ids when claim_sets is present', () => {
    assert.throws(() =>
      DcqlQuery({
        credentials: [
          {
            id: 'c',
            format: 'dc+sd-jwt',
            meta: {},
            claims: [{ path: ['name'] }],
            claim_sets: [['a']],
          },
        ],
      })
    )
  })

  it('rejects references to unknown ids', () => {
    assert.throws(() =>
      DcqlQuery({
        credentials: [{ id: 'c', format: 'dc+sd-jwt', meta: {} }],
        credential_sets: [{ options: [['nope']] }],
      })
    )
  })

  it('rejects an identifier with illegal characters', () => {
    assert.throws(() =>
      DcqlQuery({ credentials: [{ id: 'has space', format: 'dc+sd-jwt', meta: {} }] })
    )
  })

  it('keeps unknown properties, as Section 6 requires', () => {
    const query = DcqlQuery({
      credentials: [{ id: 'c', format: 'dc+sd-jwt', meta: {}, future_property: 'kept' }],
      future_top_level: 1,
    })
    assert.equal((query.credentials[0] as Record<string, unknown>).future_property, 'kept')
    assert.equal((query as Record<string, unknown>).future_top_level, 1)
  })
})

describe('type_values expansion (Appendix B.1.1)', () => {
  const standard = ['https://www.w3.org/2018/credentials/v1']

  it('expands a term the standard context defines', () => {
    assert.equal(
      expandCredentialType('VerifiableCredential', standard),
      'https://www.w3.org/2018/credentials#VerifiableCredential'
    )
  })

  it('leaves a term no context defines unchanged', () => {
    // The specification: such a term "remains a relative IRI after JSON-LD
    // processing ... and is considered to be the fully expanded type".
    assert.equal(
      expandCredentialType('UniversityDegreeCredential', standard),
      'UniversityDegreeCredential'
    )
  })

  it('expands a term the examples context defines', () => {
    assert.equal(
      expandCredentialType('UniversityDegreeCredential', [
        ...standard,
        'https://www.w3.org/2018/credentials/examples/v1',
      ]),
      'https://example.org/examples#UniversityDegreeCredential'
    )
  })

  it('leaves an absolute IRI alone', () => {
    assert.equal(
      expandCredentialType('https://example.com/vocab#Custom', standard),
      'https://example.com/vocab#Custom'
    )
  })

  it('matches a credential on its expanded types', () => {
    const credential = {
      vc: {
        '@context': ['https://www.w3.org/2018/credentials/v1'],
        type: ['VerifiableCredential', 'UniversityDegreeCredential'],
      },
    }
    const query = (typeValues: unknown) =>
      DcqlQuery({
        credentials: [{ id: 'c', format: 'jwt_vc_json', meta: { type_values: typeValues } }],
      }).credentials[0]

    assert.equal(
      matchesCredentialQuery(
        query([
          [
            'https://www.w3.org/2018/credentials#VerifiableCredential',
            'UniversityDegreeCredential',
          ],
        ]),
        { format: 'jwt_vc_json', claims: credential }
      ).matched,
      true
    )

    // The unexpanded term is not what the credential's types expand to.
    assert.equal(
      matchesCredentialQuery(query([['VerifiableCredential']]), {
        format: 'jwt_vc_json',
        claims: credential,
      }).matched,
      false
    )
  })
})
