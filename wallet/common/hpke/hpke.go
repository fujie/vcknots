// Package hpke implements Hybrid Public Key Encryption (RFC 9180) in base mode
// together with its JOSE binding, "Use of Hybrid Public Key Encryption (HPKE)
// with JSON Web Encryption (JWE)" (draft-ietf-jose-hpke-encrypt).
//
// Only the Integrated Encryption key management mode is implemented, which is
// the mode OpenID4VP 1.1 Section 8.3.1 builds on when encrypting Authorization
// Responses. In that mode the JWE Encrypted Key carries the HPKE encapsulated
// secret and no separate content encryption algorithm ("enc") is involved.
package hpke

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"hash"

	"golang.org/x/crypto/chacha20poly1305"
)

// hpkeVersion is the version label that prefixes every labeled KDF input
// (RFC 9180 Section 4).
const hpkeVersion = "HPKE-v1"

// modeBase is the HPKE mode used by JOSE HPKE: no pre-shared key and no sender
// authentication (RFC 9180 Section 5.1).
const modeBase byte = 0x00

// KEM identifies an HPKE Key Encapsulation Mechanism from the IANA HPKE
// registry. X448 based KEMs are deliberately absent: the Go standard library
// offers no X448 implementation.
type KEM uint16

const (
	// KEMP256HKDFSHA256 is DHKEM(P-256, HKDF-SHA256).
	KEMP256HKDFSHA256 KEM = 0x0010
	// KEMP384HKDFSHA384 is DHKEM(P-384, HKDF-SHA384).
	KEMP384HKDFSHA384 KEM = 0x0011
	// KEMP521HKDFSHA512 is DHKEM(P-521, HKDF-SHA512).
	KEMP521HKDFSHA512 KEM = 0x0012
	// KEMX25519HKDFSHA256 is DHKEM(X25519, HKDF-SHA256).
	KEMX25519HKDFSHA256 KEM = 0x0020
)

// KDF identifies an HPKE Key Derivation Function from the IANA HPKE registry.
type KDF uint16

const (
	// KDFHKDFSHA256 is HKDF-SHA256.
	KDFHKDFSHA256 KDF = 0x0001
	// KDFHKDFSHA384 is HKDF-SHA384.
	KDFHKDFSHA384 KDF = 0x0002
	// KDFHKDFSHA512 is HKDF-SHA512.
	KDFHKDFSHA512 KDF = 0x0003
)

// AEAD identifies an HPKE AEAD from the IANA HPKE registry.
type AEAD uint16

const (
	// AEADAES128GCM is AES-128-GCM.
	AEADAES128GCM AEAD = 0x0001
	// AEADAES256GCM is AES-256-GCM.
	AEADAES256GCM AEAD = 0x0002
	// AEADChaCha20Poly1305 is ChaCha20Poly1305.
	AEADChaCha20Poly1305 AEAD = 0x0003
)

// Suite is an HPKE ciphersuite: the KEM, KDF and AEAD triple that both parties
// agree on out of band. In JOSE HPKE the "alg" header parameter names the suite.
type Suite struct {
	KEM  KEM
	KDF  KDF
	AEAD AEAD
}

// Curve returns the elliptic curve the suite's KEM operates on. It is exported
// so callers can check a recipient key against the suite before encrypting.
func (s Suite) Curve() (ecdh.Curve, error) {
	return s.KEM.curve()
}

// Seal performs a single-shot HPKE encryption in base mode (RFC 9180 Section
// 6.1). It returns the encapsulated secret and the ciphertext.
func (s Suite) Seal(recipient *ecdh.PublicKey, info, aad, plaintext []byte) (enc, ciphertext []byte, err error) {
	if recipient == nil {
		return nil, nil, fmt.Errorf("hpke: recipient public key is nil")
	}

	shared, enc, err := s.encap(recipient)
	if err != nil {
		return nil, nil, err
	}

	aead, nonce, err := s.aeadForContext(shared, info)
	if err != nil {
		return nil, nil, err
	}

	return enc, aead.Seal(nil, nonce, plaintext, aad), nil
}

// Open reverses Seal. The info and aad values must match the ones the sender
// used; anything else fails authentication rather than returning wrong data.
func (s Suite) Open(recipient *ecdh.PrivateKey, enc, info, aad, ciphertext []byte) ([]byte, error) {
	if recipient == nil {
		return nil, fmt.Errorf("hpke: recipient private key is nil")
	}

	shared, err := s.decap(recipient, enc)
	if err != nil {
		return nil, err
	}

	aead, nonce, err := s.aeadForContext(shared, info)
	if err != nil {
		return nil, err
	}

	plaintext, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("hpke: decryption failed: %w", err)
	}
	return plaintext, nil
}

// encap implements DHKEM Encap (RFC 9180 Section 4.1).
func (s Suite) encap(pkR *ecdh.PublicKey) (shared, enc []byte, err error) {
	curve, err := s.KEM.curve()
	if err != nil {
		return nil, nil, err
	}
	if pkR.Curve() != curve {
		return nil, nil, fmt.Errorf("hpke: recipient key is on a different curve than KEM 0x%04x expects", uint16(s.KEM))
	}

	skE, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("hpke: failed to generate ephemeral key: %w", err)
	}

	dh, err := skE.ECDH(pkR)
	if err != nil {
		return nil, nil, fmt.Errorf("hpke: key agreement failed: %w", err)
	}

	enc = skE.PublicKey().Bytes()
	shared, err = s.KEM.extractAndExpand(dh, concat(enc, pkR.Bytes()))
	if err != nil {
		return nil, nil, err
	}
	return shared, enc, nil
}

// decap implements DHKEM Decap (RFC 9180 Section 4.1).
func (s Suite) decap(skR *ecdh.PrivateKey, enc []byte) ([]byte, error) {
	curve, err := s.KEM.curve()
	if err != nil {
		return nil, err
	}
	if skR.Curve() != curve {
		return nil, fmt.Errorf("hpke: recipient key is on a different curve than KEM 0x%04x expects", uint16(s.KEM))
	}

	pkE, err := curve.NewPublicKey(enc)
	if err != nil {
		return nil, fmt.Errorf("hpke: invalid encapsulated secret: %w", err)
	}

	dh, err := skR.ECDH(pkE)
	if err != nil {
		return nil, fmt.Errorf("hpke: key agreement failed: %w", err)
	}

	return s.KEM.extractAndExpand(dh, concat(enc, skR.PublicKey().Bytes()))
}

// aeadForContext runs the base-mode key schedule (RFC 9180 Section 5.1) and
// returns the AEAD together with the nonce for sequence number 0. Single-shot
// encryption never advances the sequence number, so the base nonce is used
// unchanged.
func (s Suite) aeadForContext(shared, info []byte) (cipher.AEAD, []byte, error) {
	kdf, err := s.KDF.params()
	if err != nil {
		return nil, nil, err
	}
	aeadParams, err := s.AEAD.params()
	if err != nil {
		return nil, nil, err
	}

	suiteID := s.suiteID()

	// An empty psk_id and an empty psk are what mode_base prescribes.
	pskIDHash, err := labeledExtract(kdf, suiteID, nil, "psk_id_hash", nil)
	if err != nil {
		return nil, nil, err
	}
	infoHash, err := labeledExtract(kdf, suiteID, nil, "info_hash", info)
	if err != nil {
		return nil, nil, err
	}
	keyScheduleContext := concat([]byte{modeBase}, pskIDHash, infoHash)

	secret, err := labeledExtract(kdf, suiteID, shared, "secret", nil)
	if err != nil {
		return nil, nil, err
	}
	key, err := labeledExpand(kdf, suiteID, secret, "key", keyScheduleContext, aeadParams.keySize)
	if err != nil {
		return nil, nil, err
	}
	baseNonce, err := labeledExpand(kdf, suiteID, secret, "base_nonce", keyScheduleContext, aeadParams.nonceSize)
	if err != nil {
		return nil, nil, err
	}

	aead, err := aeadParams.new(key)
	if err != nil {
		return nil, nil, err
	}
	return aead, baseNonce, nil
}

// suiteID is the ciphersuite identifier mixed into the key schedule
// (RFC 9180 Section 5.1).
func (s Suite) suiteID() []byte {
	id := make([]byte, 0, 10)
	id = append(id, "HPKE"...)
	id = binary.BigEndian.AppendUint16(id, uint16(s.KEM))
	id = binary.BigEndian.AppendUint16(id, uint16(s.KDF))
	return binary.BigEndian.AppendUint16(id, uint16(s.AEAD))
}

// curve maps a KEM to the ecdh curve it performs Diffie-Hellman on.
func (k KEM) curve() (ecdh.Curve, error) {
	switch k {
	case KEMP256HKDFSHA256:
		return ecdh.P256(), nil
	case KEMP384HKDFSHA384:
		return ecdh.P384(), nil
	case KEMP521HKDFSHA512:
		return ecdh.P521(), nil
	case KEMX25519HKDFSHA256:
		return ecdh.X25519(), nil
	default:
		return nil, fmt.Errorf("hpke: unsupported KEM 0x%04x", uint16(k))
	}
}

// kdf returns the KDF that is baked into the KEM. It is independent of the
// suite's KDF, which is only used by the key schedule.
func (k KEM) kdf() (KDF, error) {
	switch k {
	case KEMP256HKDFSHA256, KEMX25519HKDFSHA256:
		return KDFHKDFSHA256, nil
	case KEMP384HKDFSHA384:
		return KDFHKDFSHA384, nil
	case KEMP521HKDFSHA512:
		return KDFHKDFSHA512, nil
	default:
		return 0, fmt.Errorf("hpke: unsupported KEM 0x%04x", uint16(k))
	}
}

// secretSize is Nsecret, the length of the KEM shared secret.
func (k KEM) secretSize() (int, error) {
	switch k {
	case KEMP256HKDFSHA256, KEMX25519HKDFSHA256:
		return 32, nil
	case KEMP384HKDFSHA384:
		return 48, nil
	case KEMP521HKDFSHA512:
		return 64, nil
	default:
		return 0, fmt.Errorf("hpke: unsupported KEM 0x%04x", uint16(k))
	}
}

// extractAndExpand derives the KEM shared secret (RFC 9180 Section 4.1).
func (k KEM) extractAndExpand(dh, kemContext []byte) ([]byte, error) {
	kdfID, err := k.kdf()
	if err != nil {
		return nil, err
	}
	kdf, err := kdfID.params()
	if err != nil {
		return nil, err
	}
	secretSize, err := k.secretSize()
	if err != nil {
		return nil, err
	}

	suiteID := binary.BigEndian.AppendUint16([]byte("KEM"), uint16(k))

	eaePRK, err := labeledExtract(kdf, suiteID, nil, "eae_prk", dh)
	if err != nil {
		return nil, err
	}
	return labeledExpand(kdf, suiteID, eaePRK, "shared_secret", kemContext, secretSize)
}

type kdfParams struct {
	newHash func() hash.Hash
}

func (k KDF) params() (kdfParams, error) {
	switch k {
	case KDFHKDFSHA256:
		return kdfParams{newHash: sha256.New}, nil
	case KDFHKDFSHA384:
		return kdfParams{newHash: sha512.New384}, nil
	case KDFHKDFSHA512:
		return kdfParams{newHash: sha512.New}, nil
	default:
		return kdfParams{}, fmt.Errorf("hpke: unsupported KDF 0x%04x", uint16(k))
	}
}

type aeadParams struct {
	keySize   int
	nonceSize int
	new       func(key []byte) (cipher.AEAD, error)
}

func (a AEAD) params() (aeadParams, error) {
	switch a {
	case AEADAES128GCM:
		return aeadParams{keySize: 16, nonceSize: 12, new: newAESGCM}, nil
	case AEADAES256GCM:
		return aeadParams{keySize: 32, nonceSize: 12, new: newAESGCM}, nil
	case AEADChaCha20Poly1305:
		return aeadParams{keySize: 32, nonceSize: 12, new: newChaCha20Poly1305}, nil
	default:
		return aeadParams{}, fmt.Errorf("hpke: unsupported AEAD 0x%04x", uint16(a))
	}
}

func newAESGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("hpke: failed to create AES cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("hpke: failed to create GCM: %w", err)
	}
	return aead, nil
}

func newChaCha20Poly1305(key []byte) (cipher.AEAD, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("hpke: failed to create ChaCha20Poly1305: %w", err)
	}
	return aead, nil
}

// labeledExtract is LabeledExtract from RFC 9180 Section 4.
func labeledExtract(kdf kdfParams, suiteID, salt []byte, label string, ikm []byte) ([]byte, error) {
	labeledIKM := concat([]byte(hpkeVersion), suiteID, []byte(label), ikm)
	prk, err := hkdf.Extract(kdf.newHash, labeledIKM, salt)
	if err != nil {
		return nil, fmt.Errorf("hpke: HKDF extract failed: %w", err)
	}
	return prk, nil
}

// labeledExpand is LabeledExpand from RFC 9180 Section 4.
func labeledExpand(kdf kdfParams, suiteID, prk []byte, label string, info []byte, length int) ([]byte, error) {
	if length < 0 || length > 0xFFFF {
		return nil, fmt.Errorf("hpke: invalid expand length %d", length)
	}
	labeledInfo := binary.BigEndian.AppendUint16(nil, uint16(length))
	labeledInfo = concat(labeledInfo, []byte(hpkeVersion), suiteID, []byte(label), info)

	out, err := hkdf.Expand(kdf.newHash, prk, string(labeledInfo), length)
	if err != nil {
		return nil, fmt.Errorf("hpke: HKDF expand failed: %w", err)
	}
	return out, nil
}

func concat(parts ...[]byte) []byte {
	size := 0
	for _, part := range parts {
		size += len(part)
	}
	out := make([]byte, 0, size)
	for _, part := range parts {
		out = append(out, part...)
	}
	return out
}
