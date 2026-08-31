package hpke

import (
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// EncryptJWE encrypts plaintext to recipient and returns a JWE Compact
// Serialization built with HPKE Integrated Encryption
// (draft-ietf-jose-hpke-encrypt Section 5).
//
// header supplies the JWE Protected Header parameters other than "alg", which
// this function sets. A "kid" belongs there whenever the recipient key carries
// one. The header must not carry "enc": in Integrated Encryption no separate
// content encryption algorithm exists.
//
// info becomes the HPKE info parameter. OpenID4VP 1.1 Section 8.3.1 puts the
// session_info structure there so that decryption fails closed when the session
// the response belongs to does not match.
func EncryptJWE(alg Algorithm, recipient *ecdh.PublicKey, header map[string]any, info, plaintext []byte) (string, error) {
	suite, err := alg.Suite()
	if err != nil {
		return "", err
	}

	protectedHeader := make(map[string]any, len(header)+1)
	for name, value := range header {
		protectedHeader[name] = value
	}
	if _, present := protectedHeader["enc"]; present {
		return "", fmt.Errorf("hpke: the enc header parameter must not be present with Integrated Encryption")
	}
	protectedHeader["alg"] = string(alg)

	headerJSON, err := json.Marshal(protectedHeader)
	if err != nil {
		return "", fmt.Errorf("hpke: failed to marshal the JWE protected header: %w", err)
	}
	encodedHeader := base64.RawURLEncoding.EncodeToString(headerJSON)

	// Step 15 of draft-ietf-jose-hpke-encrypt Section 7.1: with the Compact
	// Serialization the Additional Authenticated Data is the encoded protected
	// header, which is what binds the header to the ciphertext.
	enc, ciphertext, err := suite.Seal(recipient, info, []byte(encodedHeader), plaintext)
	if err != nil {
		return "", err
	}

	// The JWE Initialization Vector and the JWE Authentication Tag are the empty
	// octet sequence, so the third and fifth components stay empty.
	return strings.Join([]string{
		encodedHeader,
		base64.RawURLEncoding.EncodeToString(enc),
		"",
		base64.RawURLEncoding.EncodeToString(ciphertext),
		"",
	}, "."), nil
}

// DecryptJWE reverses EncryptJWE. It returns the JWE Protected Header alongside
// the plaintext so the caller can inspect parameters such as "kid".
//
// The algorithm is taken from the header rather than from the caller, but a
// recipient key on the wrong curve, a tampered header or a mismatched info value
// all fail here instead of yielding a plaintext.
func DecryptJWE(compact string, recipient *ecdh.PrivateKey, info []byte) (map[string]any, []byte, error) {
	parts := strings.Split(compact, ".")
	if len(parts) != 5 {
		return nil, nil, fmt.Errorf("hpke: expected 5 JWE compact serialization parts, got %d", len(parts))
	}
	encodedHeader, encodedEnc, encodedIV, encodedCiphertext, encodedTag := parts[0], parts[1], parts[2], parts[3], parts[4]

	if encodedIV != "" {
		return nil, nil, fmt.Errorf("hpke: the JWE initialization vector must be empty with Integrated Encryption")
	}
	if encodedTag != "" {
		return nil, nil, fmt.Errorf("hpke: the JWE authentication tag must be empty with Integrated Encryption")
	}

	headerJSON, err := base64.RawURLEncoding.DecodeString(encodedHeader)
	if err != nil {
		return nil, nil, fmt.Errorf("hpke: failed to decode the JWE protected header: %w", err)
	}
	var header map[string]any
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, nil, fmt.Errorf("hpke: failed to parse the JWE protected header: %w", err)
	}

	alg, _ := header["alg"].(string)
	suite, err := Algorithm(alg).Suite()
	if err != nil {
		return nil, nil, err
	}
	if _, present := header["enc"]; present {
		return nil, nil, fmt.Errorf("hpke: the enc header parameter must not be present with Integrated Encryption")
	}

	enc, err := base64.RawURLEncoding.DecodeString(encodedEnc)
	if err != nil {
		return nil, nil, fmt.Errorf("hpke: failed to decode the encapsulated secret: %w", err)
	}
	ciphertext, err := base64.RawURLEncoding.DecodeString(encodedCiphertext)
	if err != nil {
		return nil, nil, fmt.Errorf("hpke: failed to decode the ciphertext: %w", err)
	}

	plaintext, err := suite.Open(recipient, enc, info, []byte(encodedHeader), ciphertext)
	if err != nil {
		return nil, nil, err
	}
	return header, plaintext, nil
}
