// Package dcql implements the Digital Credentials Query Language of OpenID4VP
// 1.0 Section 6, together with the claims path pointer of Section 7.
//
// DCQL replaces Presentation Exchange as the query language: the Verifier states
// which Credentials and claims it wants, and the Wallet evaluates the query
// against what it holds. This package covers parsing a query, applying it to a
// Credential's claim set, and choosing which Credentials answer it.
//
// Nothing here inspects signatures. Whether a Credential is valid is decided by
// the verifier plugins; this package only decides whether it is what was asked
// for.
package dcql

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// identifierPattern is what Section 6.1 allows for Credential Query and Claims
// Query ids, so that they can be used as keys in the vp_token object.
var identifierPattern = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// Query is a DCQL query (Section 6).
type Query struct {
	Credentials    []CredentialQuery    `json:"credentials"`
	CredentialSets []CredentialSetQuery `json:"credential_sets,omitempty"`
}

// CredentialQuery is a request for a presentation of one or more matching
// Credentials (Section 6.1).
type CredentialQuery struct {
	ID     string `json:"id"`
	Format string `json:"format"`
	// Multiple reports whether more than one Credential may be returned.
	// Absent means false.
	Multiple *bool `json:"multiple,omitempty"`
	// Meta carries format-specific constraints, such as vct_values for
	// dc+sd-jwt or type_values for jwt_vc_json. Empty means no constraint.
	Meta               map[string]any     `json:"meta"`
	TrustedAuthorities []TrustedAuthority `json:"trusted_authorities,omitempty"`
	// RequireCryptographicHolderBinding is true when absent.
	RequireCryptographicHolderBinding *bool         `json:"require_cryptographic_holder_binding,omitempty"`
	Claims                            []ClaimsQuery `json:"claims,omitempty"`
	// ClaimSets lists alternative combinations of Claims Query ids, most
	// preferred first.
	ClaimSets [][]string `json:"claim_sets,omitempty"`
}

// AllowsMultiple reports whether the query accepts more than one Credential.
func (c CredentialQuery) AllowsMultiple() bool {
	return c.Multiple != nil && *c.Multiple
}

// RequiresHolderBinding reports whether Cryptographic Holder Binding is
// required, which is the default.
func (c CredentialQuery) RequiresHolderBinding() bool {
	return c.RequireCryptographicHolderBinding == nil || *c.RequireCryptographicHolderBinding
}

// TrustedAuthority identifies an authority the Verifier accepts (Section 6.1.1).
type TrustedAuthority struct {
	Type   string   `json:"type"`
	Values []string `json:"values"`
}

// CredentialSetQuery constrains which combinations of Credentials satisfy the
// use case (Section 6.2).
type CredentialSetQuery struct {
	// Options each list Credential Query ids that together satisfy the set.
	Options [][]string `json:"options"`
	// Required is true when absent.
	Required *bool `json:"required,omitempty"`
}

// IsRequired reports whether the set has to be satisfied, which is the default.
func (c CredentialSetQuery) IsRequired() bool {
	return c.Required == nil || *c.Required
}

// ClaimsQuery selects a claim within a Credential (Section 6.3).
type ClaimsQuery struct {
	// ID is required when the Credential Query carries claim_sets.
	ID   string          `json:"id,omitempty"`
	Path []PathComponent `json:"path"`
	// Values restricts the accepted values. The specification is explicit that
	// this is a best-effort privacy aid, not a security check.
	Values []any `json:"values,omitempty"`
}

// PathComponentKind distinguishes the three forms a claims path component takes.
type PathComponentKind int

const (
	// PathKey selects a claim by name.
	PathKey PathComponentKind = iota
	// PathIndex selects one element of an array.
	PathIndex
	// PathAll selects every element of an array, written as null.
	PathAll
)

// PathComponent is one element of a claims path pointer (Section 7): a string,
// a non-negative integer, or null.
type PathComponent struct {
	Kind  PathComponentKind
	Key   string
	Index int
}

// UnmarshalJSON accepts the three forms Section 7 allows and rejects anything
// else, which is what "abort processing and return an error" requires.
func (p *PathComponent) UnmarshalJSON(data []byte) error {
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "null" {
		*p = PathComponent{Kind: PathAll}
		return nil
	}

	var key string
	if err := json.Unmarshal(data, &key); err == nil {
		*p = PathComponent{Kind: PathKey, Key: key}
		return nil
	}

	var index int
	if err := json.Unmarshal(data, &index); err == nil {
		if index < 0 {
			return fmt.Errorf("dcql: claims path index %d is negative", index)
		}
		*p = PathComponent{Kind: PathIndex, Index: index}
		return nil
	}

	return fmt.Errorf("dcql: claims path component %s is not a string, a non-negative integer or null", trimmed)
}

// MarshalJSON writes the component back in the form it was read.
func (p PathComponent) MarshalJSON() ([]byte, error) {
	switch p.Kind {
	case PathKey:
		return json.Marshal(p.Key)
	case PathIndex:
		return json.Marshal(p.Index)
	default:
		return []byte("null"), nil
	}
}

// String renders a path component for error messages.
func (p PathComponent) String() string {
	switch p.Kind {
	case PathKey:
		return p.Key
	case PathIndex:
		return fmt.Sprintf("%d", p.Index)
	default:
		return "null"
	}
}

// Parse reads a DCQL query and checks the constraints Section 6 states in prose.
func Parse(data []byte) (*Query, error) {
	var query Query
	if err := json.Unmarshal(data, &query); err != nil {
		return nil, fmt.Errorf("dcql: failed to parse the query: %w", err)
	}
	if err := query.Validate(); err != nil {
		return nil, err
	}
	return &query, nil
}

// Validate checks the requirements Section 6 expresses outside the object
// shapes: ids are present and unique, claim_sets needs claims, and every
// referenced id exists.
func (q Query) Validate() error {
	if len(q.Credentials) == 0 {
		return fmt.Errorf("dcql: credentials must not be empty")
	}

	ids := make(map[string]bool, len(q.Credentials))
	for _, credential := range q.Credentials {
		if !identifierPattern.MatchString(credential.ID) {
			return fmt.Errorf("dcql: %q is not a usable Credential Query id", credential.ID)
		}
		if ids[credential.ID] {
			return fmt.Errorf("dcql: Credential Query id %q is used more than once", credential.ID)
		}
		ids[credential.ID] = true

		if credential.Format == "" {
			return fmt.Errorf("dcql: Credential Query %q has no format", credential.ID)
		}
		if len(credential.ClaimSets) > 0 && len(credential.Claims) == 0 {
			return fmt.Errorf("dcql: Credential Query %q has claim_sets without claims", credential.ID)
		}

		claimIDs := make(map[string]bool, len(credential.Claims))
		for _, claim := range credential.Claims {
			if len(claim.Path) == 0 {
				return fmt.Errorf("dcql: a Claims Query in %q has an empty path", credential.ID)
			}
			if claim.ID == "" {
				if len(credential.ClaimSets) > 0 {
					return fmt.Errorf("dcql: Credential Query %q uses claim_sets, so every claim needs an id", credential.ID)
				}
				continue
			}
			if !identifierPattern.MatchString(claim.ID) {
				return fmt.Errorf("dcql: %q is not a usable Claims Query id", claim.ID)
			}
			if claimIDs[claim.ID] {
				return fmt.Errorf("dcql: Claims Query id %q is used more than once", claim.ID)
			}
			claimIDs[claim.ID] = true
		}

		for _, set := range credential.ClaimSets {
			if len(set) == 0 {
				return fmt.Errorf("dcql: Credential Query %q has an empty claim_sets option", credential.ID)
			}
			for _, id := range set {
				if !claimIDs[id] {
					return fmt.Errorf("dcql: claim_sets of %q references unknown claims id %q", credential.ID, id)
				}
			}
		}
	}

	for _, set := range q.CredentialSets {
		if len(set.Options) == 0 {
			return fmt.Errorf("dcql: a Credential Set Query has no options")
		}
		for _, option := range set.Options {
			if len(option) == 0 {
				return fmt.Errorf("dcql: a Credential Set Query option is empty")
			}
			for _, id := range option {
				if !ids[id] {
					return fmt.Errorf("dcql: credential_sets references unknown Credential Query id %q", id)
				}
			}
		}
	}

	return nil
}

// CredentialQueryByID returns the Credential Query with the given id.
func (q Query) CredentialQueryByID(id string) (CredentialQuery, bool) {
	for _, credential := range q.Credentials {
		if credential.ID == id {
			return credential, true
		}
	}
	return CredentialQuery{}, false
}
