package hpke

import "fmt"

// Algorithm is a JWE "alg" header parameter value defined by
// draft-ietf-jose-hpke-encrypt for Integrated Encryption.
//
// The "-KE" (Key Encryption) variants are intentionally not modelled here.
// OpenID4VP 1.1 Section 8.3.1 describes response encryption in terms of the
// Integrated Encryption mode, where the session_info structure becomes the HPKE
// info parameter.
type Algorithm string

const (
	// HPKE0 is DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-128-GCM.
	HPKE0 Algorithm = "HPKE-0"
	// HPKE1 is DHKEM(P-384, HKDF-SHA384), HKDF-SHA384, AES-256-GCM.
	HPKE1 Algorithm = "HPKE-1"
	// HPKE2 is DHKEM(P-521, HKDF-SHA512), HKDF-SHA512, AES-256-GCM.
	HPKE2 Algorithm = "HPKE-2"
	// HPKE3 is DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM.
	HPKE3 Algorithm = "HPKE-3"
	// HPKE4 is DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20Poly1305.
	HPKE4 Algorithm = "HPKE-4"
	// HPKE7 is DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-256-GCM.
	HPKE7 Algorithm = "HPKE-7"
)

// suites maps every Integrated Encryption algorithm this package implements to
// its ciphersuite. HPKE-5 and HPKE-6 are defined by the draft but use
// DHKEM(X448), which the Go standard library does not provide.
var suites = map[Algorithm]Suite{
	HPKE0: {KEM: KEMP256HKDFSHA256, KDF: KDFHKDFSHA256, AEAD: AEADAES128GCM},
	HPKE1: {KEM: KEMP384HKDFSHA384, KDF: KDFHKDFSHA384, AEAD: AEADAES256GCM},
	HPKE2: {KEM: KEMP521HKDFSHA512, KDF: KDFHKDFSHA512, AEAD: AEADAES256GCM},
	HPKE3: {KEM: KEMX25519HKDFSHA256, KDF: KDFHKDFSHA256, AEAD: AEADAES128GCM},
	HPKE4: {KEM: KEMX25519HKDFSHA256, KDF: KDFHKDFSHA256, AEAD: AEADChaCha20Poly1305},
	HPKE7: {KEM: KEMP256HKDFSHA256, KDF: KDFHKDFSHA256, AEAD: AEADAES256GCM},
}

// SupportedAlgorithms lists the Integrated Encryption algorithms this package
// implements, most preferred first. The order reflects how widely deployed each
// suite is: HPKE-0 is the interoperability baseline in OpenID4VP deployments.
var SupportedAlgorithms = []Algorithm{HPKE0, HPKE7, HPKE3, HPKE4, HPKE1, HPKE2}

// Suite returns the ciphersuite behind an Integrated Encryption algorithm.
func (a Algorithm) Suite() (Suite, error) {
	suite, ok := suites[a]
	if !ok {
		return Suite{}, fmt.Errorf("hpke: unsupported JOSE HPKE algorithm %q", string(a))
	}
	return suite, nil
}

// Supported reports whether this package can encrypt and decrypt with the
// algorithm.
func (a Algorithm) Supported() bool {
	_, ok := suites[a]
	return ok
}

// IsAlgorithm reports whether an "alg" value names a JOSE HPKE algorithm,
// including the ones this package does not implement. Callers use it to tell an
// HPKE response apart from an ECDH-ES one before deciding which code path to
// take, so that an unimplemented HPKE algorithm surfaces as an explicit error
// rather than being mistaken for something else.
func IsAlgorithm(alg string) bool {
	switch Algorithm(alg) {
	case HPKE0, HPKE1, HPKE2, HPKE3, HPKE4, HPKE7:
		return true
	}
	// The remaining names from the draft that this package does not implement.
	switch alg {
	case "HPKE-5", "HPKE-6",
		"HPKE-0-KE", "HPKE-1-KE", "HPKE-2-KE", "HPKE-3-KE", "HPKE-5-KE", "HPKE-7-KE":
		return true
	}
	return false
}
