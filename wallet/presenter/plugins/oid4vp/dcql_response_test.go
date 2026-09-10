package oid4vp

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/trustknots/vcknots/wallet/common/hpke"
	"github.com/trustknots/vcknots/wallet/common/jwks"
	"github.com/trustknots/vcknots/wallet/presenter/types"
)

// The shape of the Authorization Response changed with OpenID4VP 1.0: vp_token
// became an object keyed by the Credential Query id, and presentation_submission
// was removed. These tests pin the DCQL shape and confirm the parameter is not
// sent on either path.

// captureResponse posts a presentation to a server that records the form body.
func captureResponse(t *testing.T, request *types.PresentationRequest) url.Values {
	t.Helper()

	received := make(chan url.Values, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("failed to read the response body: %v", err)
			return
		}
		values, err := url.ParseQuery(string(body))
		if err != nil {
			t.Errorf("the response body is not form encoded: %v", err)
			return
		}
		received <- values
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	endpoint, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("failed to parse the endpoint: %v", err)
	}

	presenter := &Oid4vpPresenter{}
	if _, err := presenter.Present(types.Oid4vp, *endpoint, []byte("a.presentation.jwt"), request); err != nil {
		t.Fatalf("Present() returned an error: %v", err)
	}

	return <-received
}

func TestPresentSendsDCQLVPToken(t *testing.T) {
	form := captureResponse(t, &types.PresentationRequest{
		State:             "state-1",
		CredentialQueryID: "my_credential",
	})

	var vpToken map[string][]string
	if err := json.Unmarshal([]byte(form.Get("vp_token")), &vpToken); err != nil {
		t.Fatalf("vp_token is not a JSON object: %v", err)
	}

	presentations, present := vpToken["my_credential"]
	if !present {
		t.Fatalf("vp_token has no entry for the Credential Query id, got %v", vpToken)
	}
	if len(presentations) != 1 || presentations[0] != "a.presentation.jwt" {
		t.Errorf("vp_token entry = %v, want one presentation", presentations)
	}

	if _, present := form["presentation_submission"]; present {
		t.Error("a DCQL response must not carry presentation_submission")
	}
	if form.Get("state") != "state-1" {
		t.Errorf("state = %q, want state-1", form.Get("state"))
	}
}

// A request that carried no DCQL query still gets a bare Presentation as
// vp_token, but never a presentation_submission: OpenID4VP 1.0 removed the
// parameter, so this wallet does not send it on any path.
func TestPresentWithoutDCQLSendsNoSubmission(t *testing.T) {
	form := captureResponse(t, &types.PresentationRequest{State: "state-1"})

	if form.Get("vp_token") != "a.presentation.jwt" {
		t.Errorf("vp_token = %q, want the presentation itself", form.Get("vp_token"))
	}
	if _, present := form["presentation_submission"]; present {
		t.Error("presentation_submission was removed in OpenID4VP 1.0 and must not be sent")
	}
}

// TestEncryptedResponseCarriesTheDCQLVPToken checks the same rules on the
// encrypted path of Section 8.3, where the payload is JSON rather than a form
// body, by decrypting the response as the Verifier would.
func TestEncryptedResponseCarriesTheDCQLVPToken(t *testing.T) {
	privateKey, publicJWK := newEncryptionKey(t, hpke.HPKE0, "verifier-enc")
	metadata := &VerifierMetadata{Jwks: jwks.Set{Keys: []jwks.Key{publicJWK}}}

	request := &types.PresentationRequest{
		ResponseMode:      "direct_post.jwt",
		ClientID:          "x509_san_dns:verifier.example.com",
		Nonce:             "n-0S6_WzA2Mj",
		ResponseURI:       "https://verifier.example.com/response",
		CredentialQueryID: "my_credential",
	}

	presenter := &Oid4vpPresenter{}
	compact, err := presenter.createEncryptedResponse("a.presentation.jwt", request, metadata)
	if err != nil {
		t.Fatalf("failed to create the encrypted response: %v", err)
	}

	_, payload, err := hpke.DecryptJWE(compact, privateKey, sessionInfoForRequest(request))
	if err != nil {
		t.Fatalf("the verifier failed to decrypt the response: %v", err)
	}

	var response struct {
		VPToken                map[string][]string `json:"vp_token"`
		PresentationSubmission json.RawMessage     `json:"presentation_submission"`
	}
	if err := json.Unmarshal(payload, &response); err != nil {
		t.Fatalf("failed to parse the decrypted response: %v", err)
	}

	presentations, present := response.VPToken["my_credential"]
	if !present || len(presentations) != 1 || presentations[0] != "a.presentation.jwt" {
		t.Errorf("vp_token = %v, want one presentation under the Credential Query id", response.VPToken)
	}
	if response.PresentationSubmission != nil {
		t.Errorf("presentation_submission was removed in OpenID4VP 1.0, got %s", response.PresentationSubmission)
	}
}
