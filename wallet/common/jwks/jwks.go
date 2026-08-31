// Package jwks models JSON Web Keys and JWK Sets leniently.
//
// go-jose rejects a whole JWK Set when it contains a key it cannot represent as
// a Go crypto type. OpenID4VP verifier metadata routinely carries such keys:
// X25519 encryption keys are legal there, and a verifier may offer several
// encryption keys so that wallets can pick one they support. Failing to parse
// the entire client_metadata because of a key the wallet was never going to use
// would be the wrong outcome, so this package keeps every key as raw JSON plus
// the members needed to select one, and converts on demand.
package jwks

import (
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/go-jose/go-jose/v4"
)

// Key is a single JWK. Raw holds the key exactly as it arrived, so a conversion
// that this package does not implement can still be handed to another library.
type Key struct {
	Raw json.RawMessage

	KeyType   string // "kty"
	Curve     string // "crv"
	KeyID     string // "kid"
	Use       string // "use"
	Algorithm string // "alg"

	X string // "x"
	Y string // "y"
	D string // "d"
}

// Set is a JWK Set.
type Set struct {
	Keys []Key
}

type keyMembers struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	X   string `json:"x"`
	Y   string `json:"y"`
	D   string `json:"d"`
}

// UnmarshalJSON parses a JWK without validating the key material, so that an
// unusable key does not take the rest of the document with it.
func (k *Key) UnmarshalJSON(data []byte) error {
	var members keyMembers
	if err := json.Unmarshal(data, &members); err != nil {
		return fmt.Errorf("jwks: failed to parse JWK: %w", err)
	}

	*k = Key{
		Raw:       append(json.RawMessage(nil), data...),
		KeyType:   members.Kty,
		Curve:     members.Crv,
		KeyID:     members.Kid,
		Use:       members.Use,
		Algorithm: members.Alg,
		X:         members.X,
		Y:         members.Y,
		D:         members.D,
	}
	return nil
}

// MarshalJSON writes the key back out unchanged.
func (k Key) MarshalJSON() ([]byte, error) {
	if len(k.Raw) > 0 {
		return k.Raw, nil
	}
	return json.Marshal(keyMembers{
		Kty: k.KeyType, Crv: k.Curve, Kid: k.KeyID,
		Use: k.Use, Alg: k.Algorithm, X: k.X, Y: k.Y, D: k.D,
	})
}

// UnmarshalJSON parses a JWK Set, skipping entries that are not JSON objects
// rather than failing the whole set.
func (s *Set) UnmarshalJSON(data []byte) error {
	var raw struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("jwks: failed to parse JWK Set: %w", err)
	}

	keys := make([]Key, 0, len(raw.Keys))
	for _, entry := range raw.Keys {
		var key Key
		if err := key.UnmarshalJSON(entry); err != nil {
			continue
		}
		keys = append(keys, key)
	}
	s.Keys = keys
	return nil
}

// MarshalJSON writes the set back out.
func (s Set) MarshalJSON() ([]byte, error) {
	keys := s.Keys
	if keys == nil {
		keys = []Key{}
	}
	return json.Marshal(struct {
		Keys []Key `json:"keys"`
	}{Keys: keys})
}

// ByKeyID returns the first key with the given "kid".
func (s Set) ByKeyID(kid string) (Key, bool) {
	for _, key := range s.Keys {
		if key.KeyID == kid {
			return key, true
		}
	}
	return Key{}, false
}

// ECDHPublicKey converts an EC or OKP key into a public key usable for ECDH.
// Only the curves HPKE needs are handled: P-256, P-384, P-521 and X25519.
func (k Key) ECDHPublicKey() (*ecdh.PublicKey, error) {
	curve, coordinateSize, err := k.ecdhCurve()
	if err != nil {
		return nil, err
	}

	x, err := decodeCoordinate(k.X, "x", coordinateSize)
	if err != nil {
		return nil, err
	}

	var point []byte
	if k.KeyType == "OKP" {
		point = x
	} else {
		y, err := decodeCoordinate(k.Y, "y", coordinateSize)
		if err != nil {
			return nil, err
		}
		// SEC 1 uncompressed point encoding, which is what ecdh expects.
		point = append(append([]byte{0x04}, x...), y...)
	}

	publicKey, err := curve.NewPublicKey(point)
	if err != nil {
		return nil, fmt.Errorf("jwks: invalid %s public key: %w", k.Curve, err)
	}
	return publicKey, nil
}

// ECDHPrivateKey converts an EC or OKP key that carries a "d" member into a
// private key usable for ECDH.
func (k Key) ECDHPrivateKey() (*ecdh.PrivateKey, error) {
	curve, coordinateSize, err := k.ecdhCurve()
	if err != nil {
		return nil, err
	}
	if k.D == "" {
		return nil, fmt.Errorf("jwks: key %q holds no private part", k.KeyID)
	}

	d, err := decodeCoordinate(k.D, "d", coordinateSize)
	if err != nil {
		return nil, err
	}

	privateKey, err := curve.NewPrivateKey(d)
	if err != nil {
		return nil, fmt.Errorf("jwks: invalid %s private key: %w", k.Curve, err)
	}
	return privateKey, nil
}

// ecdhCurve maps the JWK key type and curve onto an ecdh curve, returning the
// byte length each coordinate must have on that curve.
func (k Key) ecdhCurve() (ecdh.Curve, int, error) {
	switch k.KeyType {
	case "EC":
		switch k.Curve {
		case "P-256":
			return ecdh.P256(), 32, nil
		case "P-384":
			return ecdh.P384(), 48, nil
		case "P-521":
			return ecdh.P521(), 66, nil
		}
	case "OKP":
		if k.Curve == "X25519" {
			return ecdh.X25519(), 32, nil
		}
	}
	return nil, 0, fmt.Errorf("jwks: key type %q with curve %q cannot be used for ECDH", k.KeyType, k.Curve)
}

func decodeCoordinate(value, name string, size int) ([]byte, error) {
	if value == "" {
		return nil, fmt.Errorf("jwks: JWK member %q is missing", name)
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("jwks: JWK member %q is not base64url: %w", name, err)
	}
	if len(decoded) != size {
		return nil, fmt.Errorf("jwks: JWK member %q is %d bytes, expected %d", name, len(decoded), size)
	}
	return decoded, nil
}

// JOSE converts the key into a go-jose JWK, for the algorithms that library
// implements. Keys it cannot represent, X25519 among them, return an error.
func (k Key) JOSE() (jose.JSONWebKey, error) {
	var key jose.JSONWebKey
	if err := key.UnmarshalJSON(k.Raw); err != nil {
		return jose.JSONWebKey{}, fmt.Errorf("jwks: key %q is not usable with go-jose: %w", k.KeyID, err)
	}
	return key, nil
}
