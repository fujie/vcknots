package oid4vp

import (
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/trustknots/vcknots/wallet/common/hpke"
	"github.com/trustknots/vcknots/wallet/common/jwks"
	"github.com/trustknots/vcknots/wallet/presenter/types"
)

// interopVectorPath points at a file shared with the TypeScript verifier in
// issuer+verifier, which decrypts the same vectors. Pinning both
// implementations to one set of bytes is what keeps them interoperable.
var interopVectorPath = filepath.Join("..", "..", "..", "..", "testdata", "oid4vp-hpke-interop.json")

// interopVector is one encrypted Authorization Response together with
// everything a Verifier needs to decrypt it.
type interopVector struct {
	Alg        string          `json:"alg"`
	PrivateJWK json.RawMessage `json:"privateJwk"`
	Session    interopSession  `json:"session"`
	// Response is the value of the "response" parameter, a JWE Compact
	// Serialization produced by the wallet.
	Response string `json:"response"`
	// Payload is what decrypting Response must yield.
	Payload map[string]any `json:"payload"`
}

// interopSession mirrors the session context that OID4VP Section 8.3.1 binds
// the response to.
type interopSession struct {
	ResponseMode string `json:"responseMode"`
	ClientID     string `json:"clientId,omitempty"`
	Nonce        string `json:"nonce"`
	ResponseURI  string `json:"responseUri,omitempty"`
	Origin       string `json:"origin,omitempty"`
}

func (s interopSession) presentationRequest(metadata *VerifierMetadata) *types.PresentationRequest {
	return &types.PresentationRequest{
		ResponseMode:   s.ResponseMode,
		ClientID:       s.ClientID,
		Nonce:          s.Nonce,
		ResponseURI:    s.ResponseURI,
		Origin:         s.Origin,
		State:          "state-1",
		ClientMetadata: metadata,
	}
}

// TestOID4VPHPKEInteropVectors decrypts the shared vectors. Running it with
// VCKNOTS_UPDATE_INTEROP_VECTORS=1 regenerates them from the wallet's own
// encryption path; the TypeScript suite then has to agree with the new bytes.
func TestOID4VPHPKEInteropVectors(t *testing.T) {
	if os.Getenv("VCKNOTS_UPDATE_INTEROP_VECTORS") == "1" {
		writeInteropVectors(t)
	}

	data, err := os.ReadFile(interopVectorPath)
	if err != nil {
		t.Fatalf("failed to read the interop vectors: %v", err)
	}
	var vectors []interopVector
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatalf("failed to parse the interop vectors: %v", err)
	}
	if len(vectors) == 0 {
		t.Fatal("the interop vector file is empty")
	}

	for _, vector := range vectors {
		t.Run(fmt.Sprintf("%s/%s", vector.Alg, vector.Session.ResponseMode), func(t *testing.T) {
			var key jwks.Key
			if err := json.Unmarshal(vector.PrivateJWK, &key); err != nil {
				t.Fatalf("failed to parse the verifier private JWK: %v", err)
			}
			privateKey, err := key.ECDHPrivateKey()
			if err != nil {
				t.Fatalf("failed to convert the verifier private JWK: %v", err)
			}

			info := sessionInfoForRequest(vector.Session.presentationRequest(nil))
			header, payload, err := hpke.DecryptJWE(vector.Response, privateKey, info)
			if err != nil {
				t.Fatalf("failed to decrypt the vector: %v", err)
			}
			if header["alg"] != vector.Alg {
				t.Errorf("alg header = %v, want %q", header["alg"], vector.Alg)
			}

			var decoded map[string]any
			if err := json.Unmarshal(payload, &decoded); err != nil {
				t.Fatalf("failed to parse the decrypted payload: %v", err)
			}
			for name, want := range vector.Payload {
				if decoded[name] != want {
					t.Errorf("payload[%q] = %v, want %v", name, decoded[name], want)
				}
			}

			// Section 8.1 defines presentation_submission as an object, so the
			// JSON payload has to carry it as one rather than as encoded text.
			submission, ok := decoded["presentation_submission"].(map[string]any)
			if !ok {
				t.Fatalf("presentation_submission = %T, want a JSON object", decoded["presentation_submission"])
			}
			if submission["id"] != "submission-1" {
				t.Errorf("presentation_submission.id = %v", submission["id"])
			}
		})
	}
}

func writeInteropVectors(t *testing.T) {
	t.Helper()

	sessions := []interopSession{
		{
			ResponseMode: string(OAuthAuthzReqResponseModeDirectPostJWT),
			ClientID:     "x509_san_dns:verifier.example.com",
			Nonce:        "n-0S6_WzA2Mj",
			ResponseURI:  "https://verifier.example.com/callback",
		},
		{
			ResponseMode: string(OAuthAuthzReqResponseModeDCAPIJWT),
			Nonce:        "n-0S6_WzA2Mj",
			Origin:       "https://verifier.example.com",
		},
	}

	presenter := &Oid4vpPresenter{}
	vectors := make([]interopVector, 0, len(hpke.SupportedAlgorithms)*len(sessions))

	for _, alg := range hpke.SupportedAlgorithms {
		for _, session := range sessions {
			privateJWK, publicJWK := interopKeyPair(t, alg, fmt.Sprintf("verifier-%s", alg))
			metadata := &VerifierMetadata{Jwks: jwks.Set{Keys: []jwks.Key{publicJWK}}}

			request := session.presentationRequest(metadata)
			response, err := presenter.createEncryptedResponse("a-vp-token", types.PresentationSubmission{ID: "submission-1", DefinitionID: "definition-1"}, request, metadata)
			if err != nil {
				t.Fatalf("failed to encrypt a %s vector: %v", alg, err)
			}

			vectors = append(vectors, interopVector{
				Alg:        string(alg),
				PrivateJWK: privateJWK,
				Session:    session,
				Response:   response,
				// Only the scalar members go here; presentation_submission is a
				// JSON object and is checked separately.
				Payload: map[string]any{
					"vp_token": "a-vp-token",
					"state":    "state-1",
				},
			})
		}
	}

	encoded, err := json.MarshalIndent(vectors, "", "  ")
	if err != nil {
		t.Fatalf("failed to encode the interop vectors: %v", err)
	}
	if err := os.WriteFile(interopVectorPath, append(encoded, '\n'), 0o644); err != nil {
		t.Fatalf("failed to write the interop vectors: %v", err)
	}
	t.Logf("regenerated %d interop vectors in %s", len(vectors), interopVectorPath)
}

// interopKeyPair generates a key pair for alg and returns it as a private JWK
// and as the public JWK a Verifier would publish.
func interopKeyPair(t *testing.T, alg hpke.Algorithm, kid string) (json.RawMessage, jwks.Key) {
	t.Helper()

	privateKey, publicKey := newEncryptionKey(t, alg, kid)

	encode := base64.RawURLEncoding.EncodeToString
	var privateJWK string
	if privateKey.Curve() == ecdh.X25519() {
		privateJWK = fmt.Sprintf(`{"kty":"OKP","crv":"X25519","use":"enc","alg":%q,"kid":%q,"x":%q,"d":%q}`,
			alg, kid, publicKey.X, encode(privateKey.Bytes()))
	} else {
		privateJWK = fmt.Sprintf(`{"kty":"EC","crv":%q,"use":"enc","alg":%q,"kid":%q,"x":%q,"y":%q,"d":%q}`,
			publicKey.Curve, alg, kid, publicKey.X, publicKey.Y, encode(privateKey.Bytes()))
	}

	return json.RawMessage(privateJWK), publicKey
}
