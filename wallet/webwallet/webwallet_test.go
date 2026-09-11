package webwallet

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	credstoreTypes "github.com/trustknots/vcknots/wallet/credstore/types"
)

func newTestService(t *testing.T) *Service {
	t.Helper()

	// A temporary store per test keeps the cases independent of each other and
	// of whatever the machine's wallet already holds.
	service, err := New(Options{})
	if err != nil {
		t.Fatalf("failed to create the wallet service: %v", err)
	}
	t.Cleanup(func() {
		if err := service.Close(); err != nil {
			t.Errorf("failed to close the wallet service: %v", err)
		}
	})
	return service
}

func TestParseCredentialOffer(t *testing.T) {
	const offerJSON = `{
	  "credential_issuer": "http://localhost:8080",
	  "credential_configuration_ids": ["UniversityDegreeCredential"],
	  "grants": {
	    "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
	      "pre-authorized_code": "the-code"
	    }
	  }
	}`

	tests := map[string]string{
		"offer URI":  "openid-credential-offer://?credential_offer=" + url.QueryEscape(offerJSON),
		"bare JSON":  offerJSON,
		"whitespace": "  " + offerJSON + "  ",
	}

	for name, raw := range tests {
		t.Run(name, func(t *testing.T) {
			offer, err := ParseCredentialOffer(raw)
			if err != nil {
				t.Fatalf("failed to parse the offer: %v", err)
			}
			if offer.CredentialIssuer.String() != "http://localhost:8080" {
				t.Errorf("credential_issuer = %q", offer.CredentialIssuer)
			}
			if len(offer.CredentialConfigurationIDs) != 1 ||
				offer.CredentialConfigurationIDs[0] != "UniversityDegreeCredential" {
				t.Errorf("credential_configuration_ids = %v", offer.CredentialConfigurationIDs)
			}
			grant := offer.Grants["urn:ietf:params:oauth:grant-type:pre-authorized_code"]
			if grant == nil || grant.PreAuthorizedCode != "the-code" {
				t.Errorf("pre-authorized_code was not carried through: %+v", grant)
			}
		})
	}
}

func TestParseCredentialOfferRejectsUnusableInput(t *testing.T) {
	tests := map[string]string{
		"empty":              "",
		"wrong scheme":       "https://example.com/?credential_offer=%7B%7D",
		"no offer parameter": "openid-credential-offer://?credential_offer_uri=https://example.com/offer",
		"not JSON":           "openid-credential-offer://?credential_offer=not-json",
		"no issuer":          `{"credential_configuration_ids":["x"]}`,
	}

	for name, raw := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseCredentialOffer(raw); err == nil {
				t.Fatal("the offer parsed despite being unusable")
			}
		})
	}
}

func TestHandlerServesThePage(t *testing.T) {
	response := httptest.NewRecorder()
	newTestService(t).Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/", nil))

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", response.Code)
	}
	if contentType := response.Header().Get("Content-Type"); !strings.HasPrefix(contentType, "text/html") {
		t.Errorf("Content-Type = %q", contentType)
	}
	for _, expected := range []string{"Receive a credential", "Present a credential", "/api/receive"} {
		if !strings.Contains(response.Body.String(), expected) {
			t.Errorf("the page does not mention %q", expected)
		}
	}
}

func TestHandlerReportsStatus(t *testing.T) {
	response := httptest.NewRecorder()
	newTestService(t).Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/status", nil))

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", response.Code)
	}

	var body struct {
		HolderKeyID         string `json:"holderKeyId"`
		HolderKeyAlg        string `json:"holderKeyAlg"`
		HolderKeyThumbprint string `json:"holderKeyThumbprint"`
		CredentialCount     int    `json:"credentialCount"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("failed to parse the status: %v", err)
	}
	if body.HolderKeyID == "" || body.HolderKeyThumbprint == "" {
		t.Errorf("the status carries no holder key: %+v", body)
	}
	if body.HolderKeyAlg != "ES256" {
		t.Errorf("holderKeyAlg = %q, want ES256", body.HolderKeyAlg)
	}
	if body.CredentialCount != 0 {
		t.Errorf("a fresh wallet reports %d credentials", body.CredentialCount)
	}
}

func TestHandlerListsCredentials(t *testing.T) {
	response := httptest.NewRecorder()
	newTestService(t).Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/credentials", nil))

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", response.Code)
	}
	var body struct {
		Credentials []credentialView `json:"credentials"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("failed to parse the credential list: %v", err)
	}
	if len(body.Credentials) != 0 {
		t.Errorf("a fresh wallet holds %d credentials", len(body.Credentials))
	}
}

// TestHandlerRejectsUnusableRequests checks that a caller mistake is reported as
// such rather than surfacing as a server fault, which matters because the
// screens show these messages verbatim.
func TestHandlerRejectsUnusableRequests(t *testing.T) {
	handler := newTestService(t).Handler()

	tests := []struct {
		name string
		path string
		body string
	}{
		{"receive without an offer", "/api/receive", `{"offer":""}`},
		{"receive a malformed offer", "/api/receive", `{"offer":"not-an-offer"}`},
		{"receive with a broken body", "/api/receive", `{`},
		{"present without a request", "/api/present", `{"request":"  "}`},
		{"present a malformed request", "/api/present", `{"request":"not-a-request"}`},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, test.path, strings.NewReader(test.body))
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)

			if response.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 (body: %s)", response.Code, response.Body.String())
			}
			var body map[string]any
			if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
				t.Fatalf("the error is not JSON: %v", err)
			}
			if body["error"] == nil {
				t.Errorf("the error carries no message: %v", body)
			}
		})
	}
}

func TestCredentialViewDecodesJwtVc(t *testing.T) {
	claims := map[string]any{
		"iss": "http://localhost:8080",
		"vc": map[string]any{
			"type":              []any{"VerifiableCredential", "UniversityDegreeCredential"},
			"credentialSubject": map[string]any{"given_name": "test", "family_name": "taro"},
		},
	}

	view := newCredentialView(&credstoreTypes.CredentialEntry{
		Id:         "entry-1",
		MimeType:   "application/jwt",
		ReceivedAt: time.Now(),
		Raw:        []byte(fakeJWT(t, claims)),
	})

	if got := strings.Join(view.Types, ","); got != "VerifiableCredential,UniversityDegreeCredential" {
		t.Errorf("types = %q", got)
	}
	if view.Claims["given_name"] != "test" {
		t.Errorf("claims = %v", view.Claims)
	}
}

func TestCredentialViewDecodesSdJwtVc(t *testing.T) {
	claims := map[string]any{
		"iss":        "http://localhost:8080",
		"vct":        "https://credentials.example.com/identity_credential",
		"given_name": "test",
	}

	// An SD-JWT VC is the issuer-signed JWT followed by its disclosures.
	raw := fakeJWT(t, claims) + "~WyJzYWx0IiwiZmFtaWx5X25hbWUiLCJ0YXJvIl0~"

	view := newCredentialView(&credstoreTypes.CredentialEntry{
		Id:         "entry-2",
		MimeType:   "application/dc+sd-jwt",
		ReceivedAt: time.Now(),
		Raw:        []byte(raw),
	})

	if len(view.Types) != 1 || view.Types[0] != "https://credentials.example.com/identity_credential" {
		t.Errorf("types = %v", view.Types)
	}
	if view.Claims["given_name"] != "test" {
		t.Errorf("claims = %v", view.Claims)
	}
	// The registered claims are not credential subject data.
	if _, present := view.Claims["iss"]; present {
		t.Errorf("iss leaked into the displayed claims: %v", view.Claims)
	}
}

func TestCredentialViewSurvivesUndecodableCredentials(t *testing.T) {
	view := newCredentialView(&credstoreTypes.CredentialEntry{
		Id:       "entry-3",
		MimeType: "application/octet-stream",
		Raw:      []byte("not a credential"),
	})

	if view.ID != "entry-3" || view.Raw != "not a credential" {
		t.Errorf("the entry was not carried through: %+v", view)
	}
	if view.Types != nil || view.Claims != nil {
		t.Errorf("undecodable content produced claims: %+v", view)
	}
}

// fakeJWT builds an unsigned token for the decoding tests. The display path
// never verifies a signature; that happened when the credential was received.
func fakeJWT(t *testing.T, claims map[string]any) string {
	t.Helper()

	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("failed to encode the claims: %v", err)
	}
	encode := base64.RawURLEncoding.EncodeToString
	return encode([]byte(`{"alg":"ES256","typ":"JWT"}`)) + "." + encode(payload) + ".c2ln"
}

func TestTraceRecordsWhatTheWalletSent(t *testing.T) {
	// An issuer that answers whatever the wallet asks, so a round trip can be
	// recorded without a real issuance flow.
	issuer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer issuer.Close()

	trace := NewTrace()
	client := &http.Client{Transport: trace.Transport(http.DefaultTransport)}

	request, err := http.NewRequest(http.MethodPost, issuer.URL+"/token",
		strings.NewReader("grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code"))
	if err != nil {
		t.Fatalf("failed to build the request: %v", err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("DPoP", "a-proof")

	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("the request failed: %v", err)
	}
	defer response.Body.Close()

	// The caller must still be able to read the body the transport read first.
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("failed to read the response: %v", err)
	}
	if !strings.Contains(string(body), `"ok"`) {
		t.Errorf("the response body did not survive tracing: %q", body)
	}

	entries := trace.List()
	if len(entries) != 1 {
		t.Fatalf("recorded %d entries, want 1", len(entries))
	}
	entry := entries[0]
	if entry.Step != "OAuth · Token Request" {
		t.Errorf("step = %q", entry.Step)
	}
	if entry.Status != http.StatusOK {
		t.Errorf("status = %d", entry.Status)
	}
	if !strings.Contains(entry.Request.Body, "pre-authorized_code") {
		t.Errorf("the request body was not recorded: %q", entry.Request.Body)
	}
	if !entry.Response.JSON {
		t.Error("the JSON response was not recognised as JSON")
	}
	if !slices.Contains(entry.Notes, "Carries a DPoP proof") {
		t.Errorf("notes = %v", entry.Notes)
	}
}

func TestTraceNotesTheEncryptedResponseHeader(t *testing.T) {
	verifier := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer verifier.Close()

	trace := NewTrace()
	client := &http.Client{Transport: trace.Transport(http.DefaultTransport)}

	// A JOSE HPKE compact serialization, as the wallet posts for direct_post.jwt.
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HPKE-0","kid":"verifier-enc"}`))
	form := url.Values{"response": {header + ".ZW5j..Y2lwaGVy."}}

	response, err := client.Post(verifier.URL+"/callback/tx-1",
		"application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("the request failed: %v", err)
	}
	defer response.Body.Close()

	entries := trace.List()
	if len(entries) != 1 {
		t.Fatalf("recorded %d entries, want 1", len(entries))
	}
	entry := entries[0]
	if entry.Step != "OID4VP · Authorization Response sent" {
		t.Errorf("step = %q", entry.Step)
	}

	notes := strings.Join(entry.Notes, "\n")
	if !strings.Contains(notes, "alg=HPKE-0") || !strings.Contains(notes, "kid=verifier-enc") {
		t.Errorf("the JWE header was not described: %v", entry.Notes)
	}
	if !strings.Contains(notes, "Integrated Encryption") {
		t.Errorf("the encryption mode was not explained: %v", entry.Notes)
	}
}

func TestTraceSinceAndClear(t *testing.T) {
	trace := NewTrace()
	for range 3 {
		trace.record(TraceEntry{Step: "step"})
	}

	if got := len(trace.List()); got != 3 {
		t.Fatalf("recorded %d entries, want 3", got)
	}
	if got := len(trace.Since(1)); got != 2 {
		t.Errorf("Since(1) returned %d entries, want 2", got)
	}
	if got := len(trace.Since(3)); got != 0 {
		t.Errorf("Since(3) returned %d entries, want 0", got)
	}

	trace.Clear()
	if got := len(trace.List()); got != 0 {
		t.Errorf("Clear left %d entries", got)
	}
}

func TestHandlerServesTheTrace(t *testing.T) {
	service := newTestService(t)
	service.trace.record(TraceEntry{Step: "OAuth · Token Request", Method: http.MethodPost})

	response := httptest.NewRecorder()
	service.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/trace", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", response.Code)
	}

	var body struct {
		Entries []TraceEntry `json:"entries"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("failed to parse the trace: %v", err)
	}
	if len(body.Entries) != 1 || body.Entries[0].Step != "OAuth · Token Request" {
		t.Fatalf("entries = %+v", body.Entries)
	}

	cleared := httptest.NewRecorder()
	service.Handler().ServeHTTP(cleared, httptest.NewRequest(http.MethodDelete, "/api/trace", nil))
	if cleared.Code != http.StatusOK {
		t.Fatalf("clear returned %d", cleared.Code)
	}
	if got := len(service.trace.List()); got != 0 {
		t.Errorf("the trace still holds %d entries", got)
	}
}

// OID4VCI 1.0 Section 4.1: a Credential Offer carries "a single URI query
// parameter, either credential_offer or credential_offer_uri", the second
// referencing "a resource containing a JSON object with the Credential Offer
// parameters".
func TestParseCredentialOfferByReference(t *testing.T) {
	offer := `{"credential_issuer":"https://issuer.example.com",` +
		`"credential_configuration_ids":["ParticipationTicket"],` +
		`"grants":{"urn:ietf:params:oauth:grant-type:pre-authorized_code":` +
		`{"pre-authorized_code":"code-1"}}}`

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		_, _ = w.Write([]byte(offer))
	}))
	defer server.Close()

	// The test server speaks https with its own certificate, so the wallet's
	// default client has to trust it for the fetch to succeed.
	previous := http.DefaultTransport
	http.DefaultTransport = server.Client().Transport
	defer func() { http.DefaultTransport = previous }()

	uri := credentialOfferScheme + "://?credential_offer_uri=" + url.QueryEscape(server.URL+"/offers/1")
	parsed, err := ParseCredentialOffer(uri)
	if err != nil {
		t.Fatalf("a by-reference offer should be accepted: %v", err)
	}
	if got := parsed.CredentialIssuer.String(); got != "https://issuer.example.com" {
		t.Errorf("credential_issuer = %q", got)
	}
	if len(parsed.CredentialConfigurationIDs) != 1 ||
		parsed.CredentialConfigurationIDs[0] != "ParticipationTicket" {
		t.Errorf("credential_configuration_ids = %v", parsed.CredentialConfigurationIDs)
	}
}

func TestParseCredentialOfferRejectsBothParameters(t *testing.T) {
	uri := credentialOfferScheme + "://?credential_offer=%7B%7D&credential_offer_uri=" +
		url.QueryEscape("https://issuer.example.com/offers/1")
	if _, err := ParseCredentialOffer(uri); err == nil {
		t.Error("Section 4.1 forbids carrying both parameters")
	}
}

func TestParseCredentialOfferRejectsNonHTTPSReference(t *testing.T) {
	t.Setenv("VCKNOTS_HTTP_ALLOWED", "false")
	t.Setenv("VCKNOTS_DEBUG", "false")
	uri := credentialOfferScheme + "://?credential_offer_uri=" +
		url.QueryEscape("ftp://issuer.example.com/offers/1")
	if _, err := ParseCredentialOffer(uri); err == nil {
		t.Error("credential_offer_uri must use the https scheme")
	}
}

func TestParseCredentialOfferRejectsNeitherParameter(t *testing.T) {
	if _, err := ParseCredentialOffer(credentialOfferScheme + "://?state=1"); err == nil {
		t.Error("an offer with neither parameter should be rejected")
	}
}
