package oid4vp

import (
	"fmt"

	"github.com/go-jose/go-jose/v4"
	"github.com/trustknots/vcknots/wallet/common/dcql"
	"github.com/trustknots/vcknots/wallet/common/jwks"
)

// PresentationDefinition represents a presentation definition
type PresentationDefinition struct {
	ID string `json:"id"`
}

// OAuthAuthzRequest represents a OAuth 2.0 Authorization Request
// These fields are defined in RFC6749 and OIDC.
type OAuthAuthzRequest struct {
	ResponseType string                    `json:"response_type"`          // required
	ClientID     string                    `json:"client_id"`              // required
	RedirectURI  string                    `json:"redirect_uri,omitempty"` // optional
	Scope        string                    `json:"scope,omitempty"`        // optional
	State        string                    `json:"state,omitempty"`        // conditional required in OID4VP
	Nonce        string                    `json:"nonce"`                  // required in OIDC
	ResponseMode OAuthAuthzReqResponseMode `json:"response_mode"`          // required in OID4VP, but optional in OIDC
}

type OAuthAuthzReqResponseMode string

const (
	// OAuthAuthzReqResponseModeQuery indicates that the authorization response should be returned in the query string
	OAuthAuthzReqResponseModeQuery OAuthAuthzReqResponseMode = "query"
	// OAuthAuthzReqResponseModeFragment indicates that the authorization response should be returned in the fragment component of the redirect URI
	OAuthAuthzReqResponseModeFragment OAuthAuthzReqResponseMode = "fragment"
	// OAuthAuthzReqResponseModeDirectPost indicates that the authorization response should be returned as a direct POST
	// newly defined in OID4VP
	OAuthAuthzReqResponseModeDirectPost OAuthAuthzReqResponseMode = "direct_post"
	// OAuthAuthzReqResponseModeDirectPostJWT is direct_post with the response
	// encrypted as defined in OID4VP Section 8.3.
	OAuthAuthzReqResponseModeDirectPostJWT OAuthAuthzReqResponseMode = "direct_post.jwt"
	// OAuthAuthzReqResponseModeDCAPI indicates that the authorization response is
	// returned through the Digital Credentials API, unencrypted.
	OAuthAuthzReqResponseModeDCAPI OAuthAuthzReqResponseMode = "dc_api"
	// OAuthAuthzReqResponseModeDCAPIJWT is dc_api with the response encrypted as
	// defined in OID4VP Section 8.3.
	OAuthAuthzReqResponseModeDCAPIJWT OAuthAuthzReqResponseMode = "dc_api.jwt"
)

// RequiresEncryptedResponse reports whether the Response Mode is one of the
// ".jwt" variants, for which OID4VP Section 8.3 requires the Authorization
// Response to be encrypted.
func (m OAuthAuthzReqResponseMode) RequiresEncryptedResponse() bool {
	return m == OAuthAuthzReqResponseModeDirectPostJWT || m == OAuthAuthzReqResponseModeDCAPIJWT
}

// UsesResponseURI reports whether the Response Mode delivers the Authorization
// Response to response_uri rather than to redirect_uri.
func (m OAuthAuthzReqResponseMode) UsesResponseURI() bool {
	return m == OAuthAuthzReqResponseModeDirectPost || m == OAuthAuthzReqResponseModeDirectPostJWT
}

// OAuthAuthorizationResponse represents a OAuth 2.0 Authorization Response
// These fields are defined in RFC6749.
type OAuthAuthorizationResponse struct {
	Code  string `json:"code"`            // required
	State string `json:"state,omitempty"` // required if the state parameter was present in the client authorization request
}

// OAuthErrorResponse represents a OAuth 2.0 Error Response
// These fields are defined in RFC6749.
type OAuthAuthzErrorResponse struct {
	Error            OAuthAuthzError `json:"error"`                       // required
	ErrorDescription string          `json:"error_description,omitempty"` // optional
	ErrorURI         string          `json:"error_uri,omitempty"`         // optional
	State            string          `json:"state,omitempty"`             // required if the state parameter was present in the client authorization request
}

type OAuthAuthzError string

const (
	// InvalidRequestError indicates that the request is missing a required parameter, includes an unsupported parameter or parameter value, or is otherwise malformed.
	InvalidRequestError OAuthAuthzError = "invalid_request"
	// UnauthorizedClientError indicates that the client is not authorized to request an authorization code using this method.
	UnauthorizedClientError OAuthAuthzError = "unauthorized_client"
	// AccessDeniedError indicates that the resource owner or authorization server denied the request.
	AccessDeniedError OAuthAuthzError = "access_denied"
	// UnsupportedResponseTypeError indicates that the authorization server does not support obtaining an authorization code using this method.
	UnsupportedResponseTypeError OAuthAuthzError = "unsupported_response_type"
	// InvalidScopeError indicates that the requested scope is invalid, unknown, or malformed.
	InvalidScopeError OAuthAuthzError = "invalid_scope"
	// ServerError indicates that the authorization server encountered an unexpected condition that prevented it from fulfilling the request. (This error code is needed because a 500 Internal Server Error HTTP status code cannot be returned to the client via a HTTP redirect.)
	ServerError OAuthAuthzError = "server_error"
	// TemporarilyUnavailableError indicates that the authorization server is currently unable to handle the request due to a temporary overloading or maintenance of the server. (This error code is needed because a 503 Service Unavailable HTTP status code cannot be returned to the client via a HTTP redirect.)
	TemporarilyUnavailableError OAuthAuthzError = "temporarily_unavailable"
)

// CredentialPresentationRequest represents a OAuth 2.0 Authorization Request
// with a presentation definition for OID4VP.
// These fields are defined in the OID4VP specification and RFC6749.
type CredentialPresentationRequest struct {
	*OAuthAuthzRequest
	// PresentationDefinition carries a Presentation Exchange query. OpenID4VP
	// 1.0 removed Presentation Exchange in favour of DCQL, so exactly one of
	// this and DCQLQuery is set.
	PresentationDefinition *PresentationDefinition `json:"presentation_definition,omitempty"`
	// DCQLQuery carries the Digital Credentials Query Language query of
	// OpenID4VP 1.0 Section 6.
	DCQLQuery                *dcql.Query       `json:"dcql_query,omitempty"`
	ClientMetadata           *VerifierMetadata `json:"client_metadata,omitempty"`             // optional
	TransactionData          []string          `json:"transaction_data,omitempty"`            // optional, to be implemented
	TransactionDataHashesAlg string            `json:"transaction_data_hashes_alg,omitempty"` // optional, hash algorithm for transaction_data_hashes
	VerifierInfo             []any             `json:"verifier_info,omitempty"`               // optional, to be implemented
	ResponseURI              string            `json:"response_uri,omitempty"`                // optional
}

type RequestURIMethod string

const (
	// RequestURIMethodGET indicates that the request_uri should be fetched using HTTP GET
	RequestURIMethodGET RequestURIMethod = "get"
	// RequestURIMethodPOST indicates that the request_uri should be fetched using HTTP POST
	RequestURIMethodPOST RequestURIMethod = "post"
)

// VerifierMetadata represents the Verifier Metadata (Client Metadata) in OID4VP.
// These fields are defined in RFC7591 and the OID4VP specification, and stated as optional.
type VerifierMetadata struct {
	RedirectURIs                      []string `json:"redirect_uris,omitempty"`
	TokenEndpointAuthMethod           string   `json:"token_endpoint_auth_method,omitempty"`
	GrantTypes                        []string `json:"grant_types,omitempty"`
	ResponseTypes                     []string `json:"response_types,omitempty"`
	ClientName                        string   `json:"client_name,omitempty"`
	ClientURI                         string   `json:"client_uri,omitempty"`
	LogoURI                           string   `json:"logo_uri,omitempty"`
	Scope                             string   `json:"scope,omitempty"`
	Contacts                          []string `json:"contacts,omitempty"`
	ToSURI                            string   `json:"tos_uri,omitempty"`
	PolicyURI                         string   `json:"policy_uri,omitempty"`
	JwksURI                           string   `json:"jwks_uri,omitempty"`
	Jwks                              jwks.Set `json:"jwks,omitempty"`
	SoftwareID                        string   `json:"software_id,omitempty"`
	SoftwareVersion                   string   `json:"software_version,omitempty"`
	AuthorizationEncryptedResponseAlg string   `json:"authorization_encrypted_response_alg,omitempty"`
	AuthorizationEncryptedResponseEnc string   `json:"authorization_encrypted_response_enc,omitempty"`

	// VPFormatsSupported lists the Credential Formats the Verifier accepts,
	// keyed by Credential Format Identifier (OID4VP 1.0 Section 11.1). Each
	// value carries format-specific members: alg_values for jwt_vc_json,
	// sd-jwt_alg_values and kb-jwt_alg_values for dc+sd-jwt (Appendix B).
	VPFormatsSupported map[string]any `json:"vp_formats_supported,omitempty"`

	// VPFormats is the name this parameter had before 1.0 renamed it to
	// vp_formats_supported. It is read so that a Verifier still on a draft is
	// understood, and is never sent.
	VPFormats map[string]any `json:"vp_formats,omitempty"`

	// EncryptedResponseEncValuesSupported lists the JWE "enc" values the
	// Verifier accepts for the encrypted Authorization Response, replacing
	// authorization_encrypted_response_enc in OID4VP 1.1. It has no effect when
	// JOSE HPKE Integrated Encryption is used, because that mode has no separate
	// content encryption algorithm.
	EncryptedResponseEncValuesSupported []string `json:"encrypted_response_enc_values_supported,omitempty"`
}

// SupportedFormats returns the Credential Formats the Verifier accepts.
//
// OID4VP 1.0 calls this vp_formats_supported; a Verifier still on a pre-final
// draft sends vp_formats instead, so that is accepted as a fallback.
func (v *VerifierMetadata) SupportedFormats() map[string]any {
	if v == nil {
		return nil
	}
	if len(v.VPFormatsSupported) > 0 {
		return v.VPFormatsSupported
	}
	return v.VPFormats
}

// UsesDCQL reports whether the request carries a DCQL query rather than a
// Presentation Exchange presentation_definition.
func (r *CredentialPresentationRequest) UsesDCQL() bool {
	return r != nil && r.DCQLQuery != nil
}

func (v *VerifierMetadata) FetchKeyWithKID(kid string) (jose.JSONWebKey, error) {
	key, found := v.Jwks.ByKeyID(kid)
	if !found {
		return jose.JSONWebKey{}, fmt.Errorf("key with kid %s not found", kid)
	}
	return key.JOSE()
}

// GrantTypes supported by the OID4VP plugin
type GrantTypes string

const (
	// AuthorizationCodeGrantType represents the authorization_code grant type
	AuthorizationCodeGrantType GrantTypes = "authorization_code"
	// RefreshTokenGrantType represents the refresh_token grant type
	RefreshTokenGrantType GrantTypes = "refresh_token"
)

type CredentialPresentationRequestBuilder interface {
	WithQueryParams(params map[string][]string) *CredentialPresentationRequestBuilder
	WithRequestObject(obj string) *CredentialPresentationRequestBuilder
	WithRequestObjectURI(uri string, method RequestURIMethod) *CredentialPresentationRequestBuilder
	Build() (*CredentialPresentationRequest, error)
}
