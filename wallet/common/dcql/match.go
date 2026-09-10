package dcql

import (
	"fmt"
)

// Applying a query to Credentials: the claims path pointer of Section 7.1.1,
// claim selection from Section 6.4.1, and Credential selection from
// Section 6.4.2.

// ResolvePath applies a claims path pointer to a JSON-based Credential and
// returns the selected elements (Section 7.1.1).
//
// A pointer that resolves to nothing is an error here, matching the
// specification's "abort processing and return an error". Callers treat that as
// "this Credential does not carry the claim" rather than as a fault.
func ResolvePath(credential any, path []PathComponent) ([]any, error) {
	selected := []any{credential}

	for index, component := range path {
		next := make([]any, 0, len(selected))

		switch component.Kind {
		case PathKey:
			for _, element := range selected {
				object, ok := element.(map[string]any)
				if !ok {
					return nil, fmt.Errorf("path[%d]: expected an object at %q", index, component.Key)
				}
				// A key that is absent drops that element from the selection.
				if value, present := object[component.Key]; present {
					next = append(next, value)
				}
			}
		case PathAll:
			for _, element := range selected {
				array, ok := element.([]any)
				if !ok {
					return nil, fmt.Errorf("path[%d]: expected an array for the null component", index)
				}
				next = append(next, array...)
			}
		case PathIndex:
			for _, element := range selected {
				array, ok := element.([]any)
				if !ok {
					return nil, fmt.Errorf("path[%d]: expected an array at index %d", index, component.Index)
				}
				// An index that does not exist drops that array.
				if component.Index < len(array) {
					next = append(next, array[component.Index])
				}
			}
		default:
			return nil, fmt.Errorf("path[%d]: unsupported component", index)
		}

		selected = next
	}

	if len(selected) == 0 {
		return nil, fmt.Errorf("the path selected no element")
	}
	return selected, nil
}

// matchesValues reports whether a resolved claim satisfies the values
// restriction of a Claims Query (Section 6.3). Both the type and the value have
// to match one of the entries.
func matchesValues(resolved []any, expected []any) bool {
	if len(expected) == 0 {
		return true
	}
	for _, value := range resolved {
		for _, candidate := range expected {
			if sameJSONValue(value, candidate) {
				return true
			}
		}
	}
	return false
}

// sameJSONValue compares two decoded JSON values by type and value. Numbers
// decode as float64, so integers from a query and from a Credential compare
// correctly without special casing.
func sameJSONValue(a, b any) bool {
	switch left := a.(type) {
	case string:
		right, ok := b.(string)
		return ok && left == right
	case bool:
		right, ok := b.(bool)
		return ok && left == right
	case float64:
		right, ok := b.(float64)
		return ok && left == right
	default:
		return false
	}
}

// claimIsPresent reports whether the Credential satisfies one Claims Query.
func claimIsPresent(credential any, claim ClaimsQuery) bool {
	resolved, err := ResolvePath(credential, claim.Path)
	if err != nil {
		return false
	}
	return matchesValues(resolved, claim.Values)
}

// SelectClaims chooses the claims to present for one Credential Query
// (Section 6.4.1).
//
// With no claims, only the mandatory claims are requested. With claims but no
// claim_sets, every listed claim is required. With both, the first satisfiable
// option wins, since the array order is the Verifier's order of preference.
func (c CredentialQuery) SelectClaims(credential any) ([]ClaimsQuery, error) {
	if len(c.Claims) == 0 {
		return nil, nil
	}

	if len(c.ClaimSets) == 0 {
		for _, claim := range c.Claims {
			if !claimIsPresent(credential, claim) {
				return nil, fmt.Errorf("the credential does not carry a requested claim")
			}
		}
		return c.Claims, nil
	}

	byID := make(map[string]ClaimsQuery, len(c.Claims))
	for _, claim := range c.Claims {
		if claim.ID != "" {
			byID[claim.ID] = claim
		}
	}

	for _, option := range c.ClaimSets {
		wanted := make([]ClaimsQuery, 0, len(option))
		satisfied := true
		for _, id := range option {
			claim, known := byID[id]
			if !known || !claimIsPresent(credential, claim) {
				satisfied = false
				break
			}
			wanted = append(wanted, claim)
		}
		if satisfied {
			return wanted, nil
		}
	}

	return nil, fmt.Errorf("the credential satisfies none of the claim_sets options")
}

// MatchesMeta reports whether a Credential satisfies the format-specific meta of
// a Credential Query. Only the formats this wallet handles are checked.
func (c CredentialQuery) MatchesMeta(credential any) error {
	claims, _ := credential.(map[string]any)

	// SD-JWT VC: the vct claim must be one of vct_values.
	if raw, present := c.Meta["vct_values"]; present {
		values, ok := raw.([]any)
		if !ok {
			return fmt.Errorf("vct_values is not an array")
		}
		vct, _ := claims["vct"].(string)
		if !containsString(values, vct) {
			return fmt.Errorf("vct %q is not among vct_values", vct)
		}
	}

	// W3C VC: type_values holds fully expanded types (IRIs), obtained by
	// applying the credential's @context to its type entries. One inner array
	// must be present in full, regardless of order or additional types
	// (Appendix B.1.1).
	if raw, present := c.Meta["type_values"]; present {
		options, ok := raw.([]any)
		if !ok {
			return fmt.Errorf("type_values is not an array")
		}
		types := credentialTypes(claims)
		matched := false
		for _, option := range options {
			wanted, ok := option.([]any)
			if !ok {
				continue
			}
			if containsAllStrings(types, wanted) {
				matched = true
				break
			}
		}
		if !matched {
			return fmt.Errorf("the expanded credential types %v match none of the type_values options", types)
		}
	}

	return nil
}

// credentialTypes reads the type array of a W3C Credential and expands each
// entry against the credential's @context, which is what type_values is
// compared with. A JWT-encoded credential nests it under the vc claim; the
// @context sits alongside the types, so both are read from the same object.
func credentialTypes(claims map[string]any) []string {
	source := claims
	if vc, ok := claims["vc"].(map[string]any); ok {
		source = vc
	}

	raw, ok := source["type"].([]any)
	if !ok {
		return nil
	}
	declared := make([]string, 0, len(raw))
	for _, value := range raw {
		if name, ok := value.(string); ok {
			declared = append(declared, name)
		}
	}
	return ExpandCredentialTypes(declared, CredentialContexts(source))
}

func containsString(values []any, wanted string) bool {
	for _, value := range values {
		if name, ok := value.(string); ok && name == wanted {
			return true
		}
	}
	return false
}

func containsAllStrings(have []string, wanted []any) bool {
	index := make(map[string]bool, len(have))
	for _, name := range have {
		index[name] = true
	}
	for _, value := range wanted {
		name, ok := value.(string)
		if !ok || !index[name] {
			return false
		}
	}
	return true
}

// Matches reports whether one Credential answers one Credential Query. The
// credential argument is the decoded claim set, not the encoded Credential.
func (c CredentialQuery) Matches(format string, credential any) error {
	if format != c.Format {
		return fmt.Errorf("format %q does not match %q", format, c.Format)
	}
	if err := c.MatchesMeta(credential); err != nil {
		return err
	}
	if _, err := c.SelectClaims(credential); err != nil {
		return err
	}
	return nil
}

// Candidate is a Credential the Wallet holds, reduced to what a query needs.
type Candidate struct {
	// Format is the Credential Format Identifier, such as dc+sd-jwt.
	Format string
	// Claims is the decoded claim set the claims path pointer applies to.
	Claims any
	// Ref carries whatever the caller needs to recover the Credential itself.
	Ref any
}

// Selection is the answer to one Credential Query.
type Selection struct {
	CredentialID string
	Candidates   []Candidate
}

// Select chooses Credentials that answer the query (Section 6.4.2).
//
// Without credential_sets every Credential Query must be answered. With them,
// each required set contributes one of its options and the optional sets are
// answered when they can be. A query that cannot be answered in full returns an
// error, since the specification requires the Wallet to return nothing rather
// than a partial response.
func (q Query) Select(held []Candidate) ([]Selection, error) {
	matches := make(map[string][]Candidate, len(q.Credentials))
	for _, credential := range q.Credentials {
		for _, candidate := range held {
			if err := credential.Matches(candidate.Format, candidate.Claims); err != nil {
				continue
			}
			matches[credential.ID] = append(matches[credential.ID], candidate)
			if !credential.AllowsMultiple() {
				break
			}
		}
	}

	answered := make([]string, 0, len(q.Credentials))
	if len(q.CredentialSets) == 0 {
		for _, credential := range q.Credentials {
			if len(matches[credential.ID]) == 0 {
				return nil, fmt.Errorf("dcql: no held credential answers Credential Query %q", credential.ID)
			}
			answered = append(answered, credential.ID)
		}
	} else {
		for _, set := range q.CredentialSets {
			chosen := firstSatisfiableOption(set.Options, matches)
			if chosen == nil {
				if set.IsRequired() {
					return nil, fmt.Errorf("dcql: no option of a required credential_sets entry can be answered")
				}
				continue
			}
			answered = append(answered, chosen...)
		}
		if len(answered) == 0 {
			return nil, fmt.Errorf("dcql: the query cannot be answered")
		}
	}

	selections := make([]Selection, 0, len(answered))
	seen := make(map[string]bool, len(answered))
	for _, id := range answered {
		if seen[id] {
			continue
		}
		seen[id] = true
		selections = append(selections, Selection{CredentialID: id, Candidates: matches[id]})
	}
	return selections, nil
}

// firstSatisfiableOption returns the first option whose Credential Queries all
// have a match, preserving the Verifier's stated order of preference.
func firstSatisfiableOption(options [][]string, matches map[string][]Candidate) []string {
	for _, option := range options {
		satisfied := true
		for _, id := range option {
			if len(matches[id]) == 0 {
				satisfied = false
				break
			}
		}
		if satisfied {
			return option
		}
	}
	return nil
}
