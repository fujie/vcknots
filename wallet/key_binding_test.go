package wallet

import (
	"testing"

	"github.com/trustknots/vcknots/wallet/common/dcql"
	"github.com/trustknots/vcknots/wallet/presenter/plugins/oid4vp"
	sdjwtvc "github.com/trustknots/vcknots/wallet/serializer/plugins/sdjwtvc"
)

// An SD-JWT VC presented over OID4VP carries a Key Binding JWT unless the DCQL
// query turns Cryptographic Holder Binding off: require_cryptographic_holder_binding
// defaults to true (OpenID4VP 1.0 Section 6.1). Without the binding a
// conformant Verifier rejects the presentation, and the KB-JWT's aud and nonce
// are the Client Identifier and request nonce (Appendix B.3.6).
func TestApplyOID4VPRequestOptionsKeyBinding(t *testing.T) {
	on, off := true, false

	request := func(query *dcql.Query) *oid4vp.CredentialPresentationRequest {
		return &oid4vp.CredentialPresentationRequest{
			OAuthAuthzRequest: &oid4vp.OAuthAuthzRequest{
				ClientID: "redirect_uri:https://verifier.example.com/callback",
				Nonce:    "n-0S6_WzA2Mj",
			},
			DCQLQuery: query,
		}
	}
	query := func(binding *bool) *dcql.Query {
		return &dcql.Query{Credentials: []dcql.CredentialQuery{{
			ID:                                "c",
			Format:                            "dc+sd-jwt",
			RequireCryptographicHolderBinding: binding,
		}}}
	}

	tests := []struct {
		name string
		req  *oid4vp.CredentialPresentationRequest
		want bool
	}{
		{name: "DCQL leaves holder binding at its default", req: request(query(nil)), want: true},
		{name: "DCQL asks for holder binding", req: request(query(&on)), want: true},
		{name: "DCQL turns holder binding off", req: request(query(&off)), want: false},
		{name: "a request without DCQL keeps the binding", req: request(nil), want: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			options := &sdjwtvc.SdJwtVcPresentationOptions{}
			applyOID4VPRequestOptions(test.req, options, "c")

			if options.RequireKeyBinding != test.want {
				t.Errorf("RequireKeyBinding = %v, want %v", options.RequireKeyBinding, test.want)
			}
			if options.Audience != test.req.ClientID {
				t.Errorf("Audience = %q, want the Client Identifier %q", options.Audience, test.req.ClientID)
			}
			if options.Nonce != test.req.Nonce {
				t.Errorf("Nonce = %q, want the request nonce %q", options.Nonce, test.req.Nonce)
			}
		})
	}
}

// A request may carry several Credential Queries with different binding
// requirements. Only the query the presentation answers decides: a decoy query
// turning binding off must not strip the Key Binding JWT from a credential
// whose own query requires one.
func TestHolderBindingFollowsTheAnsweredCredentialQuery(t *testing.T) {
	off := false
	req := &oid4vp.CredentialPresentationRequest{
		OAuthAuthzRequest: &oid4vp.OAuthAuthzRequest{
			ClientID: "redirect_uri:https://verifier.example.com/callback",
			Nonce:    "n-0S6_WzA2Mj",
		},
		DCQLQuery: &dcql.Query{Credentials: []dcql.CredentialQuery{
			{ID: "bound", Format: "dc+sd-jwt"},
			{ID: "unbound", Format: "dc+sd-jwt", RequireCryptographicHolderBinding: &off},
		}},
	}

	tests := []struct {
		answered string
		want     bool
	}{
		{answered: "bound", want: true},
		{answered: "unbound", want: false},
		// An id the request does not contain cannot turn binding off.
		{answered: "not-in-the-request", want: true},
	}

	for _, test := range tests {
		t.Run(test.answered, func(t *testing.T) {
			options := &sdjwtvc.SdJwtVcPresentationOptions{}
			applyOID4VPRequestOptions(req, options, test.answered)
			if options.RequireKeyBinding != test.want {
				t.Errorf("RequireKeyBinding = %v, want %v when answering %q", options.RequireKeyBinding, test.want, test.answered)
			}
		})
	}
}
