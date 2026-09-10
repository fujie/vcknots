package dcql_test

import (
	"encoding/json"
	"testing"

	"github.com/trustknots/vcknots/wallet/common/dcql"
)

// arthur is the Credential from OpenID4VP 1.0 Section 7.3, so the path pointer
// cases below are the ones the specification itself works through.
const arthur = `{
  "name": "Arthur Dent",
  "address": {
    "street_address": "42 Market Street",
    "locality": "Milliways",
    "postal_code": "12345"
  },
  "degrees": [
    {"type": "Bachelor of Science", "university": "University of Betelgeuse"},
    {"type": "Master of Science", "university": "University of Betelgeuse"}
  ],
  "nationalities": ["British", "Betelgeusian"]
}`

func decode(t *testing.T, document string) any {
	t.Helper()

	var value any
	if err := json.Unmarshal([]byte(document), &value); err != nil {
		t.Fatalf("failed to decode the fixture: %v", err)
	}
	return value
}

func path(t *testing.T, document string) []dcql.PathComponent {
	t.Helper()

	var components []dcql.PathComponent
	if err := json.Unmarshal([]byte(document), &components); err != nil {
		t.Fatalf("failed to decode the path %s: %v", document, err)
	}
	return components
}

func TestResolvePathSpecificationExamples(t *testing.T) {
	credential := decode(t, arthur)

	tests := []struct {
		name string
		path string
		want []any
	}{
		{"a top-level claim", `["name"]`, []any{"Arthur Dent"}},
		{"a nested claim", `["address", "street_address"]`, []any{"42 Market Street"}},
		{"every element of an array", `["degrees", null, "type"]`, []any{"Bachelor of Science", "Master of Science"}},
		{"an array element by index", `["nationalities", 1]`, []any{"Betelgeusian"}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := dcql.ResolvePath(credential, path(t, test.path))
			if err != nil {
				t.Fatalf("failed to resolve: %v", err)
			}
			if len(got) != len(test.want) {
				t.Fatalf("selected %d element(s), want %d", len(got), len(test.want))
			}
			for i := range got {
				if got[i] != test.want[i] {
					t.Errorf("element %d = %v, want %v", i, got[i], test.want[i])
				}
			}
		})
	}

	t.Run("an object with its sub-claims", func(t *testing.T) {
		got, err := dcql.ResolvePath(credential, path(t, `["address"]`))
		if err != nil {
			t.Fatalf("failed to resolve: %v", err)
		}
		if _, ok := got[0].(map[string]any); !ok || len(got) != 1 {
			t.Errorf("selected %v", got)
		}
	})
}

func TestResolvePathProcessingRules(t *testing.T) {
	credential := decode(t, arthur)

	t.Run("drops elements that lack the key rather than failing", func(t *testing.T) {
		value := decode(t, `{"people": [{"name": "a"}, {"other": "b"}, {"name": "c"}]}`)
		got, err := dcql.ResolvePath(value, path(t, `["people", null, "name"]`))
		if err != nil {
			t.Fatalf("failed to resolve: %v", err)
		}
		if len(got) != 2 || got[0] != "a" || got[1] != "c" {
			t.Errorf("selected %v, want [a c]", got)
		}
	})

	failing := map[string]string{
		"a path that selects nothing":               `["nickname"]`,
		"an index that does not exist":              `["nationalities", 5]`,
		"a key component applied to a non-object":   `["name", "first"]`,
		"a null component applied to a non-array":   `["address", null]`,
		"an index component applied to a non-array": `["address", 0]`,
	}
	for name, pointer := range failing {
		t.Run(name, func(t *testing.T) {
			if _, err := dcql.ResolvePath(credential, path(t, pointer)); err == nil {
				t.Fatal("the path resolved despite being unusable")
			}
		})
	}
}

func TestPathComponentRejectsUnusableForms(t *testing.T) {
	for _, document := range []string{`[-1]`, `[1.5]`, `[true]`, `[{}]`} {
		t.Run(document, func(t *testing.T) {
			var components []dcql.PathComponent
			if err := json.Unmarshal([]byte(document), &components); err == nil {
				t.Fatalf("%s parsed as a claims path pointer", document)
			}
		})
	}
}

// parseQuery is a shorthand for the query fixtures below.
func parseQuery(t *testing.T, document string) *dcql.Query {
	t.Helper()

	query, err := dcql.Parse([]byte(document))
	if err != nil {
		t.Fatalf("failed to parse the query: %v", err)
	}
	return query
}

func TestSelectClaims(t *testing.T) {
	credential := decode(t, arthur)

	t.Run("requests nothing selectively disclosable when claims is absent", func(t *testing.T) {
		query := parseQuery(t, `{"credentials":[{"id":"c","format":"dc+sd-jwt","meta":{}}]}`)
		claims, err := query.Credentials[0].SelectClaims(credential)
		if err != nil || len(claims) != 0 {
			t.Errorf("claims = %v, err = %v", claims, err)
		}
	})

	t.Run("requires every claim when claim_sets is absent", func(t *testing.T) {
		query := parseQuery(t, `{"credentials":[{"id":"c","format":"dc+sd-jwt","meta":{},
			"claims":[{"path":["name"]},{"path":["address"]}]}]}`)
		if _, err := query.Credentials[0].SelectClaims(credential); err != nil {
			t.Errorf("unexpected error: %v", err)
		}

		missing := parseQuery(t, `{"credentials":[{"id":"c","format":"dc+sd-jwt","meta":{},
			"claims":[{"path":["name"]},{"path":["nickname"]}]}]}`)
		if _, err := missing.Credentials[0].SelectClaims(credential); err == nil {
			t.Error("a missing claim was accepted")
		}
	})

	t.Run("takes the first satisfiable claim_sets option", func(t *testing.T) {
		query := parseQuery(t, `{"credentials":[{"id":"c","format":"dc+sd-jwt","meta":{},
			"claims":[{"id":"nickname","path":["nickname"]},{"id":"name","path":["name"]}],
			"claim_sets":[["nickname"],["name"]]}]}`)

		claims, err := query.Credentials[0].SelectClaims(credential)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// The first option cannot be satisfied, so the second is used.
		if len(claims) != 1 || claims[0].ID != "name" {
			t.Errorf("claims = %v", claims)
		}
	})

	t.Run("matches values on type as well as value", func(t *testing.T) {
		value := decode(t, `{"age_over_18": true}`)

		boolean := parseQuery(t, `{"credentials":[{"id":"c","format":"dc+sd-jwt","meta":{},
			"claims":[{"path":["age_over_18"],"values":[true]}]}]}`)
		if _, err := boolean.Credentials[0].SelectClaims(value); err != nil {
			t.Errorf("the boolean value did not match: %v", err)
		}

		text := parseQuery(t, `{"credentials":[{"id":"c","format":"dc+sd-jwt","meta":{},
			"claims":[{"path":["age_over_18"],"values":["true"]}]}]}`)
		if _, err := text.Credentials[0].SelectClaims(value); err == nil {
			t.Error(`the string "true" matched the boolean true`)
		}
	})
}

func TestMatchesMeta(t *testing.T) {
	t.Run("vct_values for SD-JWT VC", func(t *testing.T) {
		query := parseQuery(t, `{"credentials":[{"id":"c","format":"dc+sd-jwt",
			"meta":{"vct_values":["https://credentials.example.com/identity_credential"]}}]}`)

		match := decode(t, `{"vct":"https://credentials.example.com/identity_credential"}`)
		if err := query.Credentials[0].MatchesMeta(match); err != nil {
			t.Errorf("the matching vct was rejected: %v", err)
		}

		other := decode(t, `{"vct":"https://credentials.example.com/other"}`)
		if err := query.Credentials[0].MatchesMeta(other); err == nil {
			t.Error("a different vct was accepted")
		}
	})

	t.Run("type_values for W3C VC", func(t *testing.T) {
		query := parseQuery(t, `{"credentials":[{"id":"c","format":"jwt_vc_json",
			"meta":{"type_values":[["VerifiableCredential","UniversityDegreeCredential"]]}}]}`)

		match := decode(t, `{"vc":{"type":["VerifiableCredential","UniversityDegreeCredential"]}}`)
		if err := query.Credentials[0].MatchesMeta(match); err != nil {
			t.Errorf("the matching types were rejected: %v", err)
		}

		// An inner array must be present in full.
		partial := decode(t, `{"vc":{"type":["VerifiableCredential"]}}`)
		if err := query.Credentials[0].MatchesMeta(partial); err == nil {
			t.Error("a partial type match was accepted")
		}
	})
}

func TestSelect(t *testing.T) {
	degree := dcql.Candidate{
		Format: "jwt_vc_json",
		Claims: decode(t, `{"vc":{"type":["VerifiableCredential","UniversityDegreeCredential"],
			"credentialSubject":{"given_name":"test"}}}`),
		Ref: "degree",
	}
	identity := dcql.Candidate{
		Format: "dc+sd-jwt",
		Claims: decode(t, `{"vct":"https://credentials.example.com/identity_credential","given_name":"test"}`),
		Ref:    "identity",
	}

	t.Run("answers every Credential Query when credential_sets is absent", func(t *testing.T) {
		query := parseQuery(t, `{"credentials":[
			{"id":"degree","format":"jwt_vc_json","meta":{}},
			{"id":"identity","format":"dc+sd-jwt","meta":{}}]}`)

		selections, err := query.Select([]dcql.Candidate{degree, identity})
		if err != nil {
			t.Fatalf("selection failed: %v", err)
		}
		if len(selections) != 2 {
			t.Fatalf("selected %d queries, want 2", len(selections))
		}
	})

	t.Run("refuses a partial answer", func(t *testing.T) {
		query := parseQuery(t, `{"credentials":[
			{"id":"degree","format":"jwt_vc_json","meta":{}},
			{"id":"passport","format":"dc+sd-jwt","meta":{"vct_values":["https://example.com/passport"]}}]}`)

		if _, err := query.Select([]dcql.Candidate{degree, identity}); err == nil {
			t.Fatal("a query that cannot be answered in full returned a selection")
		}
	})

	t.Run("satisfies a required set with one option", func(t *testing.T) {
		query := parseQuery(t, `{"credentials":[
			{"id":"degree","format":"jwt_vc_json","meta":{}},
			{"id":"passport","format":"dc+sd-jwt","meta":{"vct_values":["https://example.com/passport"]}}],
			"credential_sets":[{"options":[["passport"],["degree"]]}]}`)

		selections, err := query.Select([]dcql.Candidate{degree, identity})
		if err != nil {
			t.Fatalf("selection failed: %v", err)
		}
		// The first option has no match, so the second answers the set.
		if len(selections) != 1 || selections[0].CredentialID != "degree" {
			t.Errorf("selections = %v", selections)
		}
	})

	t.Run("skips an optional set that cannot be answered", func(t *testing.T) {
		query := parseQuery(t, `{"credentials":[
			{"id":"degree","format":"jwt_vc_json","meta":{}},
			{"id":"passport","format":"dc+sd-jwt","meta":{"vct_values":["https://example.com/passport"]}}],
			"credential_sets":[{"options":[["degree"]]},{"options":[["passport"]],"required":false}]}`)

		selections, err := query.Select([]dcql.Candidate{degree, identity})
		if err != nil {
			t.Fatalf("selection failed: %v", err)
		}
		if len(selections) != 1 || selections[0].CredentialID != "degree" {
			t.Errorf("selections = %v", selections)
		}
	})

	t.Run("returns one candidate unless multiple is requested", func(t *testing.T) {
		second := identity
		second.Ref = "identity-2"

		single := parseQuery(t, `{"credentials":[{"id":"identity","format":"dc+sd-jwt","meta":{}}]}`)
		selections, err := single.Select([]dcql.Candidate{identity, second})
		if err != nil {
			t.Fatalf("selection failed: %v", err)
		}
		if len(selections[0].Candidates) != 1 {
			t.Errorf("selected %d candidates without multiple", len(selections[0].Candidates))
		}

		many := parseQuery(t, `{"credentials":[{"id":"identity","format":"dc+sd-jwt","meta":{},"multiple":true}]}`)
		selections, err = many.Select([]dcql.Candidate{identity, second})
		if err != nil {
			t.Fatalf("selection failed: %v", err)
		}
		if len(selections[0].Candidates) != 2 {
			t.Errorf("selected %d candidates with multiple", len(selections[0].Candidates))
		}
	})
}

func TestValidate(t *testing.T) {
	invalid := map[string]string{
		"no credentials":            `{"credentials":[]}`,
		"duplicate ids":             `{"credentials":[{"id":"c","format":"f","meta":{}},{"id":"c","format":"f","meta":{}}]}`,
		"claim_sets without claims": `{"credentials":[{"id":"c","format":"f","meta":{},"claim_sets":[["a"]]}]}`,
		"claim_sets without ids": `{"credentials":[{"id":"c","format":"f","meta":{},
			"claims":[{"path":["name"]}],"claim_sets":[["a"]]}]}`,
		"unknown credential_sets id": `{"credentials":[{"id":"c","format":"f","meta":{}}],
			"credential_sets":[{"options":[["nope"]]}]}`,
		"illegal identifier": `{"credentials":[{"id":"has space","format":"f","meta":{}}]}`,
		"missing format":     `{"credentials":[{"id":"c","meta":{}}]}`,
	}

	for name, document := range invalid {
		t.Run(name, func(t *testing.T) {
			if _, err := dcql.Parse([]byte(document)); err == nil {
				t.Fatal("an invalid query parsed")
			}
		})
	}

	t.Run("keeps a valid query", func(t *testing.T) {
		query := parseQuery(t, `{"credentials":[{"id":"c","format":"dc+sd-jwt","meta":{},
			"claims":[{"id":"a","path":["name"]}],"claim_sets":[["a"]]}]}`)
		if _, found := query.CredentialQueryByID("c"); !found {
			t.Error("the credential query is missing")
		}
	})
}

// Appendix B.1.1: type_values holds fully expanded types, obtained by applying
// the credential's @context. A term no context defines stays as it is and is
// already its own fully expanded type.
func TestExpandCredentialType(t *testing.T) {
	standard := []string{"https://www.w3.org/2018/credentials/v1"}

	tests := []struct {
		name           string
		credentialType string
		contexts       []string
		want           string
	}{
		{
			name:           "a term the standard context defines",
			credentialType: "VerifiableCredential",
			contexts:       standard,
			want:           "https://www.w3.org/2018/credentials#VerifiableCredential",
		},
		{
			name:           "a term no context defines stays as it is",
			credentialType: "UniversityDegreeCredential",
			contexts:       standard,
			want:           "UniversityDegreeCredential",
		},
		{
			name:           "a term the examples context defines",
			credentialType: "UniversityDegreeCredential",
			contexts:       append(standard, "https://www.w3.org/2018/credentials/examples/v1"),
			want:           "https://example.org/examples#UniversityDegreeCredential",
		},
		{
			name:           "an absolute IRI is left alone",
			credentialType: "https://example.com/vocab#Custom",
			contexts:       standard,
			want:           "https://example.com/vocab#Custom",
		},
		{
			name:           "no context at all",
			credentialType: "VerifiableCredential",
			contexts:       nil,
			want:           "VerifiableCredential",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := dcql.ExpandCredentialType(test.credentialType, test.contexts); got != test.want {
				t.Errorf("dcql.ExpandCredentialType() = %q, want %q", got, test.want)
			}
		})
	}
}

// The Credential this wallet is issued in the sample flow: the standard context
// only, so VerifiableCredential expands and UniversityDegreeCredential does not.
func TestMatchesMetaUsesExpandedTypes(t *testing.T) {
	credential := map[string]any{
		"vc": map[string]any{
			"@context": []any{"https://www.w3.org/2018/credentials/v1"},
			"type":     []any{"VerifiableCredential", "UniversityDegreeCredential"},
		},
	}

	expanded := dcql.CredentialQuery{Meta: map[string]any{
		"type_values": []any{[]any{
			"https://www.w3.org/2018/credentials#VerifiableCredential",
			"UniversityDegreeCredential",
		}},
	}}
	if err := expanded.MatchesMeta(credential); err != nil {
		t.Errorf("the expanded types should match: %v", err)
	}

	// The unexpanded term is not what the credential's types expand to.
	unexpanded := dcql.CredentialQuery{Meta: map[string]any{
		"type_values": []any{[]any{"VerifiableCredential"}},
	}}
	if err := unexpanded.MatchesMeta(credential); err == nil {
		t.Error("an unexpanded VerifiableCredential must not match an expanded type")
	}
}
