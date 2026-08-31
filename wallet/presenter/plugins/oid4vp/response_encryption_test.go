package oid4vp

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/trustknots/vcknots/wallet/common/hpke"
	"github.com/trustknots/vcknots/wallet/common/jwks"
	"github.com/trustknots/vcknots/wallet/presenter/types"
)

// TestSessionInfoMatchesSpecificationExamples pins the session_info encoding
// against the non-normative examples of OID4VP 1.1 Section 8.3.1, which the
// specification also gives in hexadecimal.
func TestSessionInfoMatchesSpecificationExamples(t *testing.T) {
	const nonce = "exc7gBkxjx1rdc9udRrveKvSsJIq80avlXeLHhGwqtA"

	t.Run("direct_post.jwt", func(t *testing.T) {
		got := RedirectSessionInfo("x509_san_dns:example.com", nonce, "https://example.com/response")

		const want = "4f70656e49443456502d7369ff783530395f73616e5f646e733a6578616d706c65" +
			"2e636f6dff6578633767426b786a7831726463397564527276654b7653734a49713830" +
			"61766c58654c48684777717441ff68747470733a2f2f6578616d706c652e636f6d2f72" +
			"6573706f6e7365"
		if hex.EncodeToString(got) != want {
			t.Errorf("session_info = %s\nwant %s", hex.EncodeToString(got), want)
		}
	})

	t.Run("dc_api.jwt", func(t *testing.T) {
		got := DCAPISessionInfo("https://example.com", nonce)

		const want = "4f70656e494434565044434150492d7369ff68747470733a2f2f6578616d706c652e" +
			"636f6dff6578633767426b786a7831726463397564527276654b7653734a4971383061" +
			"766c58654c48684777717441"
		if hex.EncodeToString(got) != want {
			t.Errorf("session_info = %s\nwant %s", hex.EncodeToString(got), want)
		}
	})
}

func TestSessionInfoForRequest(t *testing.T) {
	tests := []struct {
		name    string
		request *types.PresentationRequest
		want    []byte
	}{
		{
			name: "direct_post.jwt uses the response endpoint",
			request: &types.PresentationRequest{
				ResponseMode: "direct_post.jwt",
				ClientID:     "x509_san_dns:example.com",
				Nonce:        "n",
				ResponseURI:  "https://example.com/response",
			},
			want: RedirectSessionInfo("x509_san_dns:example.com", "n", "https://example.com/response"),
		},
		{
			name: "dc_api.jwt uses the origin",
			request: &types.PresentationRequest{
				ResponseMode: "dc_api.jwt",
				ClientID:     "x509_san_dns:example.com",
				Nonce:        "n",
				Origin:       "https://example.com",
			},
			want: DCAPISessionInfo("https://example.com", "n"),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := sessionInfoForRequest(test.request); string(got) != string(test.want) {
				t.Errorf("session_info = %q, want %q", got, test.want)
			}
		})
	}
}

// TestEncryptAuthorizationResponseWithHPKE walks the full Section 8.3 path and
// then decrypts as the Verifier would, recomputing session_info from the request
// parameters it issued.
func TestEncryptAuthorizationResponseWithHPKE(t *testing.T) {
	for _, alg := range hpke.SupportedAlgorithms {
		t.Run(string(alg), func(t *testing.T) {
			privateKey, publicJWK := newEncryptionKey(t, alg, "verifier-enc")

			request := &types.PresentationRequest{
				ResponseMode: "direct_post.jwt",
				ClientID:     "x509_san_dns:verifier.example.com",
				Nonce:        "n-0S6_WzA2Mj",
				ResponseURI:  "https://verifier.example.com/response",
				State:        "state-123",
			}
			metadata := &VerifierMetadata{Jwks: jwks.Set{Keys: []jwks.Key{publicJWK}}}

			presenter := &Oid4vpPresenter{}
			compact, err := presenter.createEncryptedResponse("vp-token", types.PresentationSubmission{ID: "submission-1", DefinitionID: "definition-1"}, request, metadata)
			if err != nil {
				t.Fatalf("failed to create the encrypted response: %v", err)
			}

			header, payload, err := hpke.DecryptJWE(compact, privateKey, sessionInfoForRequest(request))
			if err != nil {
				t.Fatalf("the verifier failed to decrypt the response: %v", err)
			}
			if header["alg"] != string(alg) {
				t.Errorf("alg header = %v, want %q", header["alg"], alg)
			}
			// Section 8.3 requires the kid of the selected key so the Verifier
			// knows which of its keys to decrypt with.
			if header["kid"] != "verifier-enc" {
				t.Errorf("kid header = %v, want %q", header["kid"], "verifier-enc")
			}
			if _, present := header["enc"]; present {
				t.Error("the protected header carries enc, which Integrated Encryption forbids")
			}

			var response map[string]any
			if err := json.Unmarshal(payload, &response); err != nil {
				t.Fatalf("failed to parse the decrypted response: %v", err)
			}
			if response["vp_token"] != "vp-token" {
				t.Errorf("vp_token = %v", response["vp_token"])
			}
			if response["state"] != "state-123" {
				t.Errorf("state = %v", response["state"])
			}
		})
	}
}

// TestEncryptedResponseIsBoundToTheSession is the reason Section 8.3.1 exists:
// a response captured from one session must not decrypt in another.
func TestEncryptedResponseIsBoundToTheSession(t *testing.T) {
	privateKey, publicJWK := newEncryptionKey(t, hpke.HPKE0, "verifier-enc")
	metadata := &VerifierMetadata{Jwks: jwks.Set{Keys: []jwks.Key{publicJWK}}}

	request := &types.PresentationRequest{
		ResponseMode: "direct_post.jwt",
		ClientID:     "x509_san_dns:verifier.example.com",
		Nonce:        "nonce-a",
		ResponseURI:  "https://verifier.example.com/response",
	}

	presenter := &Oid4vpPresenter{}
	compact, err := presenter.createEncryptedResponse("vp-token", types.PresentationSubmission{}, request, metadata)
	if err != nil {
		t.Fatalf("failed to create the encrypted response: %v", err)
	}

	replayed := []struct {
		name string
		info []byte
	}{
		{"different nonce", RedirectSessionInfo(request.ClientID, "nonce-b", request.ResponseURI)},
		{"different client_id", RedirectSessionInfo("x509_san_dns:attacker.example.com", request.Nonce, request.ResponseURI)},
		{"different response_uri", RedirectSessionInfo(request.ClientID, request.Nonce, "https://attacker.example.com/response")},
	}
	for _, test := range replayed {
		t.Run(test.name, func(t *testing.T) {
			if _, _, err := hpke.DecryptJWE(compact, privateKey, test.info); err == nil {
				t.Fatal("the response decrypted under a session it was not issued for")
			}
		})
	}
}

func TestSelectResponseEncryptionKey(t *testing.T) {
	hpkeKey := jwks.Key{KeyID: "hpke", Use: "enc", Algorithm: string(hpke.HPKE0), Raw: json.RawMessage(`{}`)}
	ecdhKey := jwks.Key{KeyID: "ecdh", Use: "enc", Algorithm: "ECDH-ES", Raw: json.RawMessage(`{}`)}

	tests := []struct {
		name         string
		keys         []jwks.Key
		preferredAlg string
		wantKeyID    string
		wantErr      bool
	}{
		{
			name:      "HPKE wins over ECDH-ES because it binds the session",
			keys:      []jwks.Key{ecdhKey, hpkeKey},
			wantKeyID: "hpke",
		},
		{
			name:         "an explicitly requested algorithm narrows the choice",
			keys:         []jwks.Key{ecdhKey, hpkeKey},
			preferredAlg: "ECDH-ES",
			wantKeyID:    "ecdh",
		},
		{
			name: "signing keys are not candidates",
			keys: []jwks.Key{
				{KeyID: "sig", Use: "sig", Algorithm: "ES256"},
				hpkeKey,
			},
			wantKeyID: "hpke",
		},
		{
			name:    "a key without alg is not a candidate",
			keys:    []jwks.Key{{KeyID: "no-alg", Use: "enc"}},
			wantErr: true,
		},
		{
			name: "an HPKE algorithm this build cannot perform is not a candidate",
			// HPKE-5 needs DHKEM(X448).
			keys:    []jwks.Key{{KeyID: "x448", Use: "enc", Algorithm: "HPKE-5"}},
			wantErr: true,
		},
		{
			name:    "an empty jwks is an error",
			keys:    nil,
			wantErr: true,
		},
		{
			name: "the preferred HPKE suite wins among HPKE keys",
			keys: []jwks.Key{
				{KeyID: "p521", Use: "enc", Algorithm: string(hpke.HPKE2)},
				hpkeKey,
			},
			wantKeyID: "hpke",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			selected, err := selectResponseEncryptionKey(jwks.Set{Keys: test.keys}, test.preferredAlg)
			if test.wantErr {
				if err == nil {
					t.Fatalf("expected an error, selected %q", selected.key.KeyID)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if selected.key.KeyID != test.wantKeyID {
				t.Errorf("selected key %q, want %q", selected.key.KeyID, test.wantKeyID)
			}
		})
	}
}

func TestContentEncryptionAlgorithm(t *testing.T) {
	tests := []struct {
		name     string
		metadata VerifierMetadata
		want     string
	}{
		{
			name: "the OID4VP 1.1 metadata is preferred",
			metadata: VerifierMetadata{
				EncryptedResponseEncValuesSupported: []string{"A256GCM", "A128GCM"},
				AuthorizationEncryptedResponseEnc:   "A128CBC-HS256",
			},
			want: "A256GCM",
		},
		{
			name: "unsupported values are skipped",
			metadata: VerifierMetadata{
				EncryptedResponseEncValuesSupported: []string{"XC20P", "A128CBC-HS256"},
			},
			want: "A128CBC-HS256",
		},
		{
			name:     "the draft 24 metadata is the fallback",
			metadata: VerifierMetadata{AuthorizationEncryptedResponseEnc: "A256GCM"},
			want:     "A256GCM",
		},
		{
			name:     "the specification default applies when nothing is published",
			metadata: VerifierMetadata{},
			want:     defaultResponseContentEncryption,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := test.metadata.contentEncryptionAlgorithm(); got != test.want {
				t.Errorf("enc = %q, want %q", got, test.want)
			}
		})
	}
}

// TestVerifierMetadataToleratesUnusableKeys guards the reason this package keeps
// its own JWK model: a verifier that publishes an X25519 encryption key must not
// make the whole client_metadata unparseable.
func TestVerifierMetadataToleratesUnusableKeys(t *testing.T) {
	const clientMetadata = `{
	  "jwks": {
	    "keys": [
	      {"kty":"OKP","crv":"X25519","use":"enc","alg":"HPKE-3","kid":"x25519",
	       "x":"WPX7wnwq10hFNK9aDSyG1QlLswE_CJY14LdhcFUIVVc"},
	      {"kty":"EC","crv":"P-256","use":"sig","alg":"ES256","kid":"sig",
	       "x":"YO4epjifD-KWeq1sL2tNmm36BhXnkJ0He-WqMYrp9Fk",
	       "y":"Hekpm0zfK7C-YccH5iBjcIXgf6YdUvNUac_0At55Okk"}
	    ]
	  },
	  "encrypted_response_enc_values_supported": ["A128GCM"]
	}`

	var metadata VerifierMetadata
	if err := json.Unmarshal([]byte(clientMetadata), &metadata); err != nil {
		t.Fatalf("failed to parse client_metadata carrying an X25519 key: %v", err)
	}
	if len(metadata.Jwks.Keys) != 2 {
		t.Fatalf("parsed %d keys, want 2", len(metadata.Jwks.Keys))
	}

	selected, err := selectResponseEncryptionKey(metadata.Jwks, "")
	if err != nil {
		t.Fatalf("failed to select an encryption key: %v", err)
	}
	if selected.key.KeyID != "x25519" {
		t.Errorf("selected key %q, want %q", selected.key.KeyID, "x25519")
	}
}

func TestEncryptAuthorizationResponseWithECDHES(t *testing.T) {
	// P-256 key from the OID4VP Section 8.3 example.
	const verifierJWK = `{"kty":"EC","kid":"ac","use":"enc","crv":"P-256","alg":"ECDH-ES",
	  "x":"YO4epjifD-KWeq1sL2tNmm36BhXnkJ0He-WqMYrp9Fk",
	  "y":"Hekpm0zfK7C-YccH5iBjcIXgf6YdUvNUac_0At55Okk"}`

	var key jwks.Key
	if err := json.Unmarshal([]byte(verifierJWK), &key); err != nil {
		t.Fatalf("failed to parse the verifier JWK: %v", err)
	}

	metadata := &VerifierMetadata{
		Jwks:                                jwks.Set{Keys: []jwks.Key{key}},
		EncryptedResponseEncValuesSupported: []string{"A128GCM"},
	}

	compact, err := encryptAuthorizationResponse(map[string]any{"vp_token": "vp"}, metadata, nil)
	if err != nil {
		t.Fatalf("failed to encrypt with ECDH-ES: %v", err)
	}

	parts := strings.Split(compact, ".")
	if len(parts) != 5 {
		t.Fatalf("compact serialization has %d parts, want 5", len(parts))
	}
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("failed to decode the protected header: %v", err)
	}
	var header map[string]any
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		t.Fatalf("failed to parse the protected header: %v", err)
	}
	if header["alg"] != "ECDH-ES" || header["enc"] != "A128GCM" || header["kid"] != "ac" {
		t.Errorf("header = %v", header)
	}
}

// newEncryptionKey generates a key pair for alg and returns the private key
// together with the public JWK a Verifier would publish for it.
func newEncryptionKey(t *testing.T, alg hpke.Algorithm, kid string) (*ecdh.PrivateKey, jwks.Key) {
	t.Helper()

	suite, err := alg.Suite()
	if err != nil {
		t.Fatalf("failed to resolve the suite for %s: %v", alg, err)
	}
	curve, err := suite.Curve()
	if err != nil {
		t.Fatalf("failed to resolve the curve for %s: %v", alg, err)
	}
	privateKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate a key pair: %v", err)
	}

	encode := base64.RawURLEncoding.EncodeToString
	point := privateKey.PublicKey().Bytes()

	var raw string
	if curve == ecdh.X25519() {
		raw = fmt.Sprintf(`{"kty":"OKP","crv":"X25519","use":"enc","alg":%q,"kid":%q,"x":%q}`,
			alg, kid, encode(point))
	} else {
		// Strip the SEC 1 uncompressed point prefix and split the coordinates.
		coordinate := (len(point) - 1) / 2
		raw = fmt.Sprintf(`{"kty":"EC","crv":%q,"use":"enc","alg":%q,"kid":%q,"x":%q,"y":%q}`,
			jwkCurveName(t, alg), alg, kid, encode(point[1:1+coordinate]), encode(point[1+coordinate:]))
	}

	var key jwks.Key
	if err := json.Unmarshal([]byte(raw), &key); err != nil {
		t.Fatalf("failed to parse the generated JWK: %v", err)
	}
	return privateKey, key
}

func jwkCurveName(t *testing.T, alg hpke.Algorithm) string {
	t.Helper()

	suite, err := alg.Suite()
	if err != nil {
		t.Fatalf("failed to resolve the suite for %s: %v", alg, err)
	}
	curve, err := suite.Curve()
	if err != nil {
		t.Fatalf("failed to resolve the curve for %s: %v", alg, err)
	}
	switch curve {
	case ecdh.P256():
		return "P-256"
	case ecdh.P384():
		return "P-384"
	case ecdh.P521():
		return "P-521"
	default:
		t.Fatalf("no JWK curve name for %s", alg)
		return ""
	}
}
