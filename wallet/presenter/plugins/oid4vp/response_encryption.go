package oid4vp

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/go-jose/go-jose/v4"
	"github.com/trustknots/vcknots/wallet/common/hpke"
	"github.com/trustknots/vcknots/wallet/common/jwks"
	"github.com/trustknots/vcknots/wallet/presenter/types"
)

// defaultResponseContentEncryption is the JWE "enc" value OID4VP 1.1 Section 8.3
// falls back to when the Verifier does not publish
// encrypted_response_enc_values_supported. It does not apply to JOSE HPKE, where
// no separate content encryption algorithm exists.
const defaultResponseContentEncryption = "A128GCM"

// sessionInfoPrefixRedirect and sessionInfoPrefixDCAPI are the fixed labels that
// open the session_info structure of OID4VP 1.1 Section 8.3.1. Which one applies
// depends on how the presentation was invoked.
const (
	sessionInfoPrefixRedirect = "OpenID4VP-si"
	sessionInfoPrefixDCAPI    = "OpenID4VPDCAPI-si"
)

// sessionInfoSeparator is the 0xFF byte that delimits the session_info fields.
const sessionInfoSeparator = 0xFF

// RedirectSessionInfo builds the session_info structure for the response modes
// that are invoked through redirects, direct_post.jwt among them:
//
//	session_info = ASCII("OpenID4VP-si") || BYTE(255) || ASCII(clientId) ||
//	               BYTE(255) || ASCII(nonce) || BYTE(255) || ASCII(responseUri)
//
// clientID is the client_id request parameter including its Client Identifier
// Prefix, and responseURI is whichever of response_uri or redirect_uri the
// Response Mode uses.
//
// The Wallet and the Verifier compute this independently and feed it to HPKE as
// the info parameter, so a response encrypted for one session cannot be
// decrypted in the context of another: decryption fails closed rather than
// yielding a credential that was bound to different session data.
func RedirectSessionInfo(clientID, nonce, responseURI string) []byte {
	return buildSessionInfo(sessionInfoPrefixRedirect, clientID, nonce, responseURI)
}

// DCAPISessionInfo builds the session_info structure for the dc_api.jwt Response
// Mode:
//
//	session_info = ASCII("OpenID4VPDCAPI-si") || BYTE(255) || ASCII(origin) ||
//	               BYTE(255) || ASCII(nonce)
//
// origin is the Origin of the request and must not carry the "origin:" prefix.
func DCAPISessionInfo(origin, nonce string) []byte {
	return buildSessionInfo(sessionInfoPrefixDCAPI, origin, nonce)
}

func buildSessionInfo(prefix string, fields ...string) []byte {
	info := []byte(prefix)
	for _, field := range fields {
		info = append(info, sessionInfoSeparator)
		info = append(info, field...)
	}
	return info
}

// sessionInfoForRequest returns the session_info structure that matches the
// Response Mode of the request.
func sessionInfoForRequest(req *types.PresentationRequest) []byte {
	if req == nil {
		return nil
	}

	if OAuthAuthzReqResponseMode(req.ResponseMode) == OAuthAuthzReqResponseModeDCAPIJWT {
		// The Digital Credentials API identifies the session by the Origin of
		// the request rather than by a response endpoint.
		return DCAPISessionInfo(req.Origin, req.Nonce)
	}
	return RedirectSessionInfo(req.ClientID, req.Nonce, req.ResponseURI)
}

// responseEncryptionKey is the Verifier public key an Authorization Response is
// encrypted to, together with the JWE "alg" that the key pins.
type responseEncryptionKey struct {
	key jwks.Key
	alg string
}

// selectResponseEncryptionKey picks the key to encrypt the Authorization
// Response to, following OID4VP 1.1 Section 8.3: keys whose "use" is absent or
// "enc" are candidates, the "alg" member must be present, and the JWE "alg" is
// the one the key declares.
//
// When the Verifier offers several usable keys the JOSE HPKE ones win. HPKE
// binds the response to the session through the info parameter of Section
// 8.3.1, which the ECDH-ES algorithms have no equivalent for.
func selectResponseEncryptionKey(set jwks.Set, preferredAlg string) (responseEncryptionKey, error) {
	var hpkeCandidates, joseCandidates []responseEncryptionKey
	var skipped []string

	for _, key := range set.Keys {
		if key.Use != "" && key.Use != "enc" {
			skipped = append(skipped, fmt.Sprintf("%q has use %q", key.KeyID, key.Use))
			continue
		}
		if key.Algorithm == "" {
			skipped = append(skipped, fmt.Sprintf("%q declares no alg", key.KeyID))
			continue
		}

		candidate := responseEncryptionKey{key: key, alg: key.Algorithm}
		switch {
		case hpke.Algorithm(key.Algorithm).Supported():
			hpkeCandidates = append(hpkeCandidates, candidate)
		case hpke.IsAlgorithm(key.Algorithm):
			// A JOSE HPKE algorithm this build cannot perform, such as one of
			// the X448 suites or a Key Encryption variant.
			skipped = append(skipped, fmt.Sprintf("%q uses unsupported JOSE HPKE alg %q", key.KeyID, key.Algorithm))
		case isSupportedJWEKeyAlgorithm(key.Algorithm):
			joseCandidates = append(joseCandidates, candidate)
		default:
			skipped = append(skipped, fmt.Sprintf("%q uses unsupported alg %q", key.KeyID, key.Algorithm))
		}
	}

	candidates := append(append([]responseEncryptionKey{}, hpkeCandidates...), joseCandidates...)
	if len(candidates) == 0 {
		if len(skipped) > 0 {
			return responseEncryptionKey{}, fmt.Errorf("no usable response encryption key in the verifier jwks: %s", strings.Join(skipped, "; "))
		}
		return responseEncryptionKey{}, fmt.Errorf("the verifier jwks holds no response encryption key")
	}

	// An explicitly requested algorithm, which is how the draft-24
	// authorization_encrypted_response_alg metadata reaches this code, narrows
	// the choice rather than replacing it.
	if preferredAlg != "" {
		for _, candidate := range candidates {
			if candidate.alg == preferredAlg {
				return candidate, nil
			}
		}
	}

	// Preferring HPKE over ECDH-ES also means preferring the suite the wallet
	// lists first among the HPKE algorithms it implements.
	if len(hpkeCandidates) > 1 {
		for _, alg := range hpke.SupportedAlgorithms {
			for _, candidate := range hpkeCandidates {
				if candidate.alg == string(alg) {
					return candidate, nil
				}
			}
		}
	}

	return candidates[0], nil
}

// encryptAuthorizationResponse encrypts the Authorization Response parameters
// and returns the JWE Compact Serialization that goes into the "response"
// parameter (OID4VP 1.1 Section 8.3).
//
// sessionInfo is the session_info structure of Section 8.3.1. It is used only by
// the JOSE HPKE algorithms; the ECDH-ES algorithms have nowhere to put it.
func encryptAuthorizationResponse(payload map[string]any, metadata *VerifierMetadata, sessionInfo []byte) (string, error) {
	if metadata == nil {
		return "", fmt.Errorf("verifier metadata is not available for response encryption")
	}
	if len(metadata.Jwks.Keys) == 0 {
		return "", fmt.Errorf("verifier jwks is not available for response encryption")
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("failed to marshal the authorization response: %w", err)
	}

	selected, err := selectResponseEncryptionKey(metadata.Jwks, metadata.AuthorizationEncryptedResponseAlg)
	if err != nil {
		return "", err
	}

	if alg := hpke.Algorithm(selected.alg); alg.Supported() {
		return encryptWithHPKE(alg, selected.key, payloadBytes, sessionInfo)
	}
	return encryptWithJWEKeyAgreement(selected, metadata.contentEncryptionAlgorithm(), payloadBytes)
}

// encryptWithHPKE produces the response JWE using JOSE HPKE Integrated
// Encryption, which is the mode OID4VP 1.1 Section 8.3.1 builds on.
func encryptWithHPKE(alg hpke.Algorithm, key jwks.Key, payload, sessionInfo []byte) (string, error) {
	publicKey, err := key.ECDHPublicKey()
	if err != nil {
		return "", fmt.Errorf("verifier encryption key %q is unusable: %w", key.KeyID, err)
	}

	header := map[string]any{}
	// Section 8.3 requires echoing the kid so the Verifier can tell which of its
	// keys the response was encrypted to.
	if key.KeyID != "" {
		header["kid"] = key.KeyID
	}

	compact, err := hpke.EncryptJWE(alg, publicKey, header, sessionInfo, payload)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt the authorization response with %s: %w", alg, err)
	}
	return compact, nil
}

// encryptWithJWEKeyAgreement produces the response JWE using the ECDH-ES family,
// which OID4VP has supported since before JOSE HPKE existed.
func encryptWithJWEKeyAgreement(selected responseEncryptionKey, contentEnc string, payload []byte) (string, error) {
	keyAlg, err := parseJWEKeyAlgorithm(selected.alg)
	if err != nil {
		return "", err
	}
	contentEncryption, err := parseJWEContentEncryption(contentEnc)
	if err != nil {
		return "", err
	}

	joseKey, err := selected.key.JOSE()
	if err != nil {
		return "", fmt.Errorf("verifier encryption key %q is unusable: %w", selected.key.KeyID, err)
	}

	encrypter, err := jose.NewEncrypter(
		contentEncryption,
		jose.Recipient{
			Algorithm: keyAlg,
			Key:       joseKey.Key,
			KeyID:     joseKey.KeyID,
		},
		nil,
	)
	if err != nil {
		return "", fmt.Errorf("failed to create encrypter: %w", err)
	}

	jwe, err := encrypter.Encrypt(payload)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt the authorization response: %w", err)
	}

	serialized, err := jwe.CompactSerialize()
	if err != nil {
		return "", fmt.Errorf("failed to serialize JWE: %w", err)
	}
	return serialized, nil
}

// contentEncryptionAlgorithm returns the JWE "enc" value to use with the
// ECDH-ES algorithms, preferring the OID4VP 1.1 metadata over its draft-24
// predecessor and falling back to the default the specification allows.
func (v *VerifierMetadata) contentEncryptionAlgorithm() string {
	for _, enc := range v.EncryptedResponseEncValuesSupported {
		if _, err := parseJWEContentEncryption(enc); err == nil {
			return enc
		}
	}
	if v.AuthorizationEncryptedResponseEnc != "" {
		return v.AuthorizationEncryptedResponseEnc
	}
	return defaultResponseContentEncryption
}

func isSupportedJWEKeyAlgorithm(alg string) bool {
	_, err := parseJWEKeyAlgorithm(alg)
	return err == nil
}

func parseJWEKeyAlgorithm(alg string) (jose.KeyAlgorithm, error) {
	switch alg {
	case "ECDH-ES":
		return jose.ECDH_ES, nil
	case "ECDH-ES+A128KW":
		return jose.ECDH_ES_A128KW, nil
	case "ECDH-ES+A192KW":
		return jose.ECDH_ES_A192KW, nil
	case "ECDH-ES+A256KW":
		return jose.ECDH_ES_A256KW, nil
	default:
		return "", fmt.Errorf("unsupported encryption algorithm: %s", alg)
	}
}

func parseJWEContentEncryption(enc string) (jose.ContentEncryption, error) {
	switch enc {
	case "A128GCM":
		return jose.A128GCM, nil
	case "A192GCM":
		return jose.A192GCM, nil
	case "A256GCM":
		return jose.A256GCM, nil
	case "A128CBC-HS256":
		return jose.A128CBC_HS256, nil
	case "A192CBC-HS384":
		return jose.A192CBC_HS384, nil
	case "A256CBC-HS512":
		return jose.A256CBC_HS512, nil
	default:
		return "", fmt.Errorf("unsupported encryption encoding: %s", enc)
	}
}
