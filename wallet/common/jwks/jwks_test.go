package jwks_test

import (
	"encoding/json"
	"testing"

	"github.com/trustknots/vcknots/wallet/common/jwks"
)

// TestSetKeepsKeysGoJoseCannotParse is the behaviour this package exists for.
// The set below mixes an X25519 encryption key, which go-jose rejects, with an
// ordinary P-256 key.
func TestSetKeepsKeysGoJoseCannotParse(t *testing.T) {
	const document = `{"keys":[
	  {"kty":"OKP","crv":"X25519","kid":"jc","use":"enc","alg":"HPKE-3",
	   "x":"WPX7wnwq10hFNK9aDSyG1QlLswE_CJY14LdhcFUIVVc"},
	  {"kty":"EC","kid":"ac","use":"enc","crv":"P-256","alg":"ECDH-ES",
	   "x":"YO4epjifD-KWeq1sL2tNmm36BhXnkJ0He-WqMYrp9Fk",
	   "y":"Hekpm0zfK7C-YccH5iBjcIXgf6YdUvNUac_0At55Okk"}
	]}`

	var set jwks.Set
	if err := json.Unmarshal([]byte(document), &set); err != nil {
		t.Fatalf("failed to parse the JWK Set: %v", err)
	}
	if len(set.Keys) != 2 {
		t.Fatalf("parsed %d keys, want 2", len(set.Keys))
	}

	x25519, found := set.ByKeyID("jc")
	if !found {
		t.Fatal("the X25519 key is missing from the set")
	}
	if _, err := x25519.ECDHPublicKey(); err != nil {
		t.Errorf("failed to convert the X25519 key for ECDH: %v", err)
	}
	if _, err := x25519.JOSE(); err == nil {
		t.Error("go-jose unexpectedly accepted the X25519 key")
	}

	p256, found := set.ByKeyID("ac")
	if !found {
		t.Fatal("the P-256 key is missing from the set")
	}
	if _, err := p256.ECDHPublicKey(); err != nil {
		t.Errorf("failed to convert the P-256 key for ECDH: %v", err)
	}
	if _, err := p256.JOSE(); err != nil {
		t.Errorf("go-jose rejected the P-256 key: %v", err)
	}
}

func TestECDHKeyRoundTrip(t *testing.T) {
	// The HPKE-0 private key from draft-ietf-jose-hpke-encrypt Appendix A.1.
	const privateJWK = `{"kty":"EC","crv":"P-256",
	  "x":"qy-BxXhaelX9Fqe8muRTu8HhseHYgMMGxyfAnIy0MC0",
	  "y":"ctfHN7Y4pkj7vZI-sgJ6BqsYwG-PDnB8j7TsfzHHJOI",
	  "d":"aAKxBMAkNm2AZDGv7LN5yodDwahJ5rKbrgiiz3dUIH4",
	  "alg":"HPKE-0","use":"enc","kid":"KfvD-eYaynUKba0ow-v9uoEV-twV6mYDyiAOWO6LoPM"}`

	var key jwks.Key
	if err := json.Unmarshal([]byte(privateJWK), &key); err != nil {
		t.Fatalf("failed to parse the JWK: %v", err)
	}

	privateKey, err := key.ECDHPrivateKey()
	if err != nil {
		t.Fatalf("failed to convert the private key: %v", err)
	}
	publicKey, err := key.ECDHPublicKey()
	if err != nil {
		t.Fatalf("failed to convert the public key: %v", err)
	}
	if !privateKey.PublicKey().Equal(publicKey) {
		t.Error("the public key does not match the one derived from d")
	}
}

func TestKeyConversionErrors(t *testing.T) {
	tests := map[string]string{
		"unsupported curve":       `{"kty":"EC","crv":"secp256k1","x":"AA","y":"AA"}`,
		"unsupported key type":    `{"kty":"RSA","n":"AA","e":"AQAB"}`,
		"Ed25519 is not for ECDH": `{"kty":"OKP","crv":"Ed25519","x":"AA"}`,
		"coordinate wrong length": `{"kty":"EC","crv":"P-256","x":"AA","y":"AA"}`,
		"coordinate not base64":   `{"kty":"OKP","crv":"X25519","x":"not base64!!"}`,
		"missing coordinate":      `{"kty":"OKP","crv":"X25519"}`,
	}

	for name, document := range tests {
		t.Run(name, func(t *testing.T) {
			var key jwks.Key
			if err := json.Unmarshal([]byte(document), &key); err != nil {
				t.Fatalf("failed to parse the JWK: %v", err)
			}
			if _, err := key.ECDHPublicKey(); err == nil {
				t.Fatal("the key converted despite being unusable for ECDH")
			}
		})
	}
}

func TestECDHPrivateKeyRequiresPrivatePart(t *testing.T) {
	var key jwks.Key
	if err := json.Unmarshal([]byte(`{"kty":"OKP","crv":"X25519","kid":"pub","x":"WPX7wnwq10hFNK9aDSyG1QlLswE_CJY14LdhcFUIVVc"}`), &key); err != nil {
		t.Fatalf("failed to parse the JWK: %v", err)
	}
	if _, err := key.ECDHPrivateKey(); err == nil {
		t.Fatal("a public-only key produced a private key")
	}
}

func TestSetMarshalRoundTrip(t *testing.T) {
	const document = `{"keys":[{"alg":"HPKE-3","crv":"X25519","kid":"jc","kty":"OKP","use":"enc","x":"WPX7wnwq10hFNK9aDSyG1QlLswE_CJY14LdhcFUIVVc"}]}`

	var set jwks.Set
	if err := json.Unmarshal([]byte(document), &set); err != nil {
		t.Fatalf("failed to parse the JWK Set: %v", err)
	}

	encoded, err := json.Marshal(set)
	if err != nil {
		t.Fatalf("failed to marshal the JWK Set: %v", err)
	}
	if string(encoded) != document {
		t.Errorf("round trip produced\n%s\nwant\n%s", encoded, document)
	}
}
