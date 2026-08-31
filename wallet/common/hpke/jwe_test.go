package hpke_test

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/trustknots/vcknots/wallet/common/hpke"
	"github.com/trustknots/vcknots/wallet/common/jwks"
)

// joseVector mirrors one entry of the test vector file published alongside
// draft-ietf-jose-hpke-encrypt.
type joseVector struct {
	Alg string          `json:"alg"`
	JWK json.RawMessage `json:"jwk"`

	Flattened struct {
		Protected    string `json:"protected"`
		AAD          string `json:"aad"`
		EncryptedKey string `json:"encrypted_key"`
		Ciphertext   string `json:"ciphertext"`
	} `json:"flattened"`

	Compact string `json:"compact"`
}

func loadJOSEVectors(t *testing.T) []joseVector {
	t.Helper()

	data, err := os.ReadFile("testdata/jose-vectors.json")
	if err != nil {
		t.Fatalf("failed to read the JOSE HPKE test vectors: %v", err)
	}
	var vectors []joseVector
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatalf("failed to parse the JOSE HPKE test vectors: %v", err)
	}
	if len(vectors) == 0 {
		t.Fatal("the JOSE HPKE test vector file is empty")
	}
	return vectors
}

func privateKeyFromJWK(t *testing.T, raw json.RawMessage) *ecdh.PrivateKey {
	t.Helper()

	var key jwks.Key
	if err := json.Unmarshal(raw, &key); err != nil {
		t.Fatalf("failed to parse the JWK: %v", err)
	}
	privateKey, err := key.ECDHPrivateKey()
	if err != nil {
		t.Fatalf("failed to convert the JWK: %v", err)
	}
	return privateKey
}

// TestDecryptJWEAgainstDraftVectors decrypts the JWE Compact Serialization
// examples published with draft-ietf-jose-hpke-encrypt. They pin the key
// schedule, the AAD binding and the compact layout against an independent
// implementation.
func TestDecryptJWEAgainstDraftVectors(t *testing.T) {
	covered := map[string]bool{}

	for _, vector := range loadJOSEVectors(t) {
		if !hpke.Algorithm(vector.Alg).Supported() {
			continue
		}

		t.Run(vector.Alg, func(t *testing.T) {
			privateKey := privateKeyFromJWK(t, vector.JWK)

			// The compact examples carry no HPKE info; the flattened ones use a
			// JWE AAD, which the Compact Serialization cannot express.
			header, plaintext, err := hpke.DecryptJWE(vector.Compact, privateKey, nil)
			if err != nil {
				t.Fatalf("failed to decrypt the %s compact vector: %v", vector.Alg, err)
			}
			if header["alg"] != vector.Alg {
				t.Errorf("alg header = %v, want %q", header["alg"], vector.Alg)
			}
			if len(plaintext) == 0 {
				t.Error("decrypted an empty plaintext")
			}
		})
		covered[vector.Alg] = true
	}

	for _, alg := range hpke.SupportedAlgorithms {
		if !covered[string(alg)] {
			t.Errorf("no draft test vector covered %s", alg)
		}
	}
}

// TestDecryptJWERejectsWrongInfo is the property OpenID4VP Section 8.3.1 relies
// on: because session_info is the HPKE info parameter, a response encrypted for
// one session cannot be decrypted with another session's context.
func TestDecryptJWERejectsWrongInfo(t *testing.T) {
	for _, alg := range hpke.SupportedAlgorithms {
		t.Run(string(alg), func(t *testing.T) {
			publicKey, privateKey := generateKeyPair(t, alg)

			compact, err := hpke.EncryptJWE(alg, publicKey, map[string]any{"kid": "k1"}, []byte("session-a"), []byte(`{"vp_token":"x"}`))
			if err != nil {
				t.Fatalf("failed to encrypt: %v", err)
			}

			if _, _, err := hpke.DecryptJWE(compact, privateKey, []byte("session-b")); err == nil {
				t.Fatal("decryption succeeded with a different HPKE info value")
			}

			header, plaintext, err := hpke.DecryptJWE(compact, privateKey, []byte("session-a"))
			if err != nil {
				t.Fatalf("failed to decrypt with the matching info: %v", err)
			}
			if header["kid"] != "k1" {
				t.Errorf("kid header = %v, want %q", header["kid"], "k1")
			}
			if string(plaintext) != `{"vp_token":"x"}` {
				t.Errorf("plaintext = %q", plaintext)
			}
		})
	}
}

func TestEncryptJWECompactLayout(t *testing.T) {
	publicKey, _ := generateKeyPair(t, hpke.HPKE0)

	compact, err := hpke.EncryptJWE(hpke.HPKE0, publicKey, nil, nil, []byte("payload"))
	if err != nil {
		t.Fatalf("failed to encrypt: %v", err)
	}

	parts := strings.Split(compact, ".")
	if len(parts) != 5 {
		t.Fatalf("compact serialization has %d parts, want 5", len(parts))
	}
	// Integrated Encryption leaves the initialization vector and the
	// authentication tag empty.
	if parts[2] != "" || parts[4] != "" {
		t.Errorf("initialization vector = %q and authentication tag = %q, want both empty", parts[2], parts[4])
	}

	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("failed to decode the protected header: %v", err)
	}
	var header map[string]any
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		t.Fatalf("failed to parse the protected header: %v", err)
	}
	if header["alg"] != string(hpke.HPKE0) {
		t.Errorf("alg header = %v, want %q", header["alg"], hpke.HPKE0)
	}
	if _, present := header["enc"]; present {
		t.Error("the protected header carries enc, which Integrated Encryption forbids")
	}
}

func TestEncryptJWERejectsEncHeader(t *testing.T) {
	publicKey, _ := generateKeyPair(t, hpke.HPKE0)

	if _, err := hpke.EncryptJWE(hpke.HPKE0, publicKey, map[string]any{"enc": "A128GCM"}, nil, []byte("payload")); err == nil {
		t.Fatal("encryption accepted an enc header parameter")
	}
}

func TestEncryptJWERejectsUnsupportedAlgorithm(t *testing.T) {
	publicKey, _ := generateKeyPair(t, hpke.HPKE0)

	// HPKE-5 is defined by the draft but needs X448.
	if _, err := hpke.EncryptJWE("HPKE-5", publicKey, nil, nil, []byte("payload")); err == nil {
		t.Fatal("encryption accepted HPKE-5, which uses an unimplemented KEM")
	}
	if !hpke.IsAlgorithm("HPKE-5") {
		t.Error("HPKE-5 should still be recognised as a JOSE HPKE algorithm")
	}
	if hpke.IsAlgorithm("ECDH-ES") {
		t.Error("ECDH-ES should not be recognised as a JOSE HPKE algorithm")
	}
}

func TestDecryptJWERejectsMalformedSerialization(t *testing.T) {
	publicKey, privateKey := generateKeyPair(t, hpke.HPKE0)

	compact, err := hpke.EncryptJWE(hpke.HPKE0, publicKey, nil, nil, []byte("payload"))
	if err != nil {
		t.Fatalf("failed to encrypt: %v", err)
	}
	parts := strings.Split(compact, ".")

	tests := map[string]string{
		"too few parts":                strings.Join(parts[:4], "."),
		"non-empty initialization vec": strings.Join([]string{parts[0], parts[1], "AAAAAAAAAAAAAAAA", parts[3], parts[4]}, "."),
		"non-empty tag":                strings.Join([]string{parts[0], parts[1], parts[2], parts[3], "AAAAAAAAAAAAAAAA"}, "."),
		"tampered ciphertext":          strings.Join([]string{parts[0], parts[1], parts[2], base64.RawURLEncoding.EncodeToString([]byte("tampered")), parts[4]}, "."),
	}

	for name, compact := range tests {
		t.Run(name, func(t *testing.T) {
			if _, _, err := hpke.DecryptJWE(compact, privateKey, nil); err == nil {
				t.Fatal("decryption accepted a malformed serialization")
			}
		})
	}
}

func generateKeyPair(t *testing.T, alg hpke.Algorithm) (*ecdh.PublicKey, *ecdh.PrivateKey) {
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
	return privateKey.PublicKey(), privateKey
}
