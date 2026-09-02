package wallet

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/trustknots/vcknots/wallet/common/dcql"
	"github.com/trustknots/vcknots/wallet/credential"
	"github.com/trustknots/vcknots/wallet/credstore/types"
)

// Selecting Credentials with DCQL (OpenID4VP 1.0 Section 6.4). The evaluation
// itself is covered in common/dcql; what these tests pin is the step in between:
// turning a stored Credential into something a query can be applied to, and
// reporting the Credential Query id the response has to be keyed by.

// encodeJWT builds a JWT whose payload is the given claim set. Nothing here
// verifies signatures, so the signature is a placeholder.
func encodeJWT(t *testing.T, claims map[string]any) []byte {
	t.Helper()

	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("failed to encode the claims: %v", err)
	}
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256"}`))
	return []byte(header + "." + base64.RawURLEncoding.EncodeToString(payload) + ".signature")
}

func savedSDJwtVC(t *testing.T, claims map[string]any, disclosures string) *SavedCredential {
	t.Helper()

	raw := append(encodeJWT(t, claims), []byte(disclosures)...)
	return &SavedCredential{
		Entry: &types.CredentialEntry{
			Id:       "entry",
			Raw:      raw,
			MimeType: string(credential.SDJwtVC),
		},
	}
}

func TestDecodeCredentialClaims(t *testing.T) {
	t.Run("reads a JWT payload", func(t *testing.T) {
		claims, err := decodeCredentialClaims(encodeJWT(t, map[string]any{"vct": "pid"}))
		if err != nil {
			t.Fatalf("failed to decode the credential: %v", err)
		}
		object, ok := claims.(map[string]any)
		if !ok || object["vct"] != "pid" {
			t.Errorf("claims = %v, want the JWT payload", claims)
		}
	})

	t.Run("stops at the first tilde of an SD-JWT VC", func(t *testing.T) {
		raw := append(encodeJWT(t, map[string]any{"vct": "pid"}), []byte("~WyJhIl0~WyJiIl0~")...)
		claims, err := decodeCredentialClaims(raw)
		if err != nil {
			t.Fatalf("failed to decode the credential: %v", err)
		}
		object, _ := claims.(map[string]any)
		if object["vct"] != "pid" {
			t.Errorf("claims = %v, want the issuer-signed payload", claims)
		}
	})

	t.Run("reports a credential that is not a JWT", func(t *testing.T) {
		if _, err := decodeCredentialClaims([]byte("not-a-jwt")); err == nil {
			t.Error("decoding a non-JWT credential should fail")
		}
	})
}

func TestSelectCredentialsByDCQL(t *testing.T) {
	pid := savedSDJwtVC(t, map[string]any{
		"vct":         "https://credentials.example.com/identity_credential",
		"given_name":  "Arthur",
		"family_name": "Dent",
	}, "~WyJhIl0~")
	other := savedSDJwtVC(t, map[string]any{"vct": "https://credentials.example.com/other"}, "")

	query := func(t *testing.T, body string) *dcql.Query {
		t.Helper()
		parsed, err := dcql.Parse([]byte(body))
		if err != nil {
			t.Fatalf("failed to parse the query: %v", err)
		}
		return parsed
	}

	w := &Wallet{}

	t.Run("returns the matching credential and its Credential Query id", func(t *testing.T) {
		selected, flavor, credentialQueryID, err := w.selectCredentialsByDCQL(query(t, `{
			"credentials": [{
				"id": "my_credential",
				"format": "dc+sd-jwt",
				"meta": {"vct_values": ["https://credentials.example.com/identity_credential"]},
				"claims": [{"path": ["given_name"]}]
			}]
		}`), []*SavedCredential{other, pid})
		if err != nil {
			t.Fatalf("selection failed: %v", err)
		}
		if credentialQueryID != "my_credential" {
			t.Errorf("Credential Query id = %q, want my_credential", credentialQueryID)
		}
		if len(selected) != 1 || selected[0] != pid {
			t.Errorf("selected %d credentials, want the matching one", len(selected))
		}
		if flavor == nil || *flavor != credential.SDJwtVC {
			t.Errorf("flavor = %v, want %v", flavor, credential.SDJwtVC)
		}
	})

	t.Run("reports a query no held credential answers", func(t *testing.T) {
		_, _, _, err := w.selectCredentialsByDCQL(query(t, `{
			"credentials": [{
				"id": "my_credential",
				"format": "dc+sd-jwt",
				"meta": {"vct_values": ["https://credentials.example.com/nothing"]}
			}]
		}`), []*SavedCredential{pid})
		if err == nil {
			t.Error("a query that cannot be answered should fail rather than present nothing")
		}
	})

	t.Run("reports a query needing several Credential Queries answered", func(t *testing.T) {
		_, _, _, err := w.selectCredentialsByDCQL(query(t, `{
			"credentials": [
				{"id": "a", "format": "dc+sd-jwt", "meta": {}},
				{"id": "b", "format": "dc+sd-jwt", "meta": {}}
			]
		}`), []*SavedCredential{pid, other})
		if err == nil {
			t.Fatal("answering two Credential Queries is not supported and should be reported")
		}
	})

	t.Run("skips credentials it cannot decode", func(t *testing.T) {
		broken := &SavedCredential{Entry: &types.CredentialEntry{
			Id:       "broken",
			Raw:      []byte("not-a-jwt"),
			MimeType: string(credential.SDJwtVC),
		}}
		selected, _, _, err := w.selectCredentialsByDCQL(query(t, `{
			"credentials": [{"id": "my_credential", "format": "dc+sd-jwt", "meta": {}}]
		}`), []*SavedCredential{broken, pid})
		if err != nil {
			t.Fatalf("selection failed: %v", err)
		}
		if len(selected) != 1 || selected[0] != pid {
			t.Errorf("selected %d credentials, want only the decodable one", len(selected))
		}
	})
}
