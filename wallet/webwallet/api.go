package webwallet

import (
	"crypto"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/trustknots/vcknots/wallet"
	credstoreTypes "github.com/trustknots/vcknots/wallet/credstore/types"
	receiverTypes "github.com/trustknots/vcknots/wallet/receiver/types"
)

// Handler returns the HTTP surface of the wallet: one page and the JSON
// endpoints it drives.
func (s *Service) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /{$}", s.handlePage)
	mux.HandleFunc("GET /api/status", s.handleStatus)
	mux.HandleFunc("GET /api/credentials", s.handleCredentials)
	mux.HandleFunc("POST /api/receive", s.handleReceive)
	mux.HandleFunc("POST /api/present", s.handlePresent)
	mux.HandleFunc("GET /api/trace", s.handleTrace)
	mux.HandleFunc("DELETE /api/trace", s.handleClearTrace)

	return mux
}

// credentialView is one stored credential as the screens and the end-to-end
// test consume it.
type credentialView struct {
	ID         string         `json:"id"`
	MimeType   string         `json:"mimeType"`
	ReceivedAt time.Time      `json:"receivedAt"`
	Raw        string         `json:"raw"`
	Types      []string       `json:"types,omitempty"`
	Claims     map[string]any `json:"claims,omitempty"`
}

func (s *Service) handleStatus(w http.ResponseWriter, r *http.Request) {
	credentials, total, err := s.wallet.GetCredentialEntries(wallet.GetCredentialEntriesRequest{})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to read the credential store", err)
		return
	}

	publicKey := s.key.PublicKey()
	thumbprint, _ := publicKey.Thumbprint(crypto.SHA256)

	writeJSON(w, http.StatusOK, map[string]any{
		"holderKeyId":         s.key.ID(),
		"holderKeyAlg":        publicKey.Algorithm,
		"holderKeyThumbprint": base64.RawURLEncoding.EncodeToString(thumbprint),
		"credentialCount":     len(credentials),
		"totalCount":          total,
	})
}

func (s *Service) handleCredentials(w http.ResponseWriter, r *http.Request) {
	views, err := s.credentialViews()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to read the credential store", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"credentials": views})
}

func (s *Service) handleReceive(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Offer  string `json:"offer"`
		TxCode string `json:"tx_code"`
	}
	if err := decodeJSONBody(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "the request body is not valid JSON", err)
		return
	}

	offer, err := ParseCredentialOffer(body.Offer)
	if err != nil {
		writeError(w, http.StatusBadRequest, "the credential offer could not be parsed", err)
		return
	}

	saved, err := s.wallet.ReceiveCredential(wallet.ReceiveCredentialRequest{
		CredentialOffer: offer,
		Type:            receiverTypes.Oid4vci,
		Key:             s.key,
		TxCode:          strings.TrimSpace(body.TxCode),
	})
	if err != nil {
		// The issuer rejecting the offer is an expected outcome of a test run,
		// not a fault of this service, so it is reported as a bad request.
		writeError(w, http.StatusBadRequest, "the credential could not be received", err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"credential": newCredentialView(saved.Entry)})
}

func (s *Service) handlePresent(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Request string `json:"request"`
	}
	if err := decodeJSONBody(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "the request body is not valid JSON", err)
		return
	}
	if strings.TrimSpace(body.Request) == "" {
		writeError(w, http.StatusBadRequest, "the authorization request is empty", nil)
		return
	}

	redirectURI, err := s.wallet.PresentCredential(strings.TrimSpace(body.Request), s.key, nil)
	if err != nil {
		writeError(w, http.StatusBadRequest, "the presentation could not be sent", err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"redirect_uri": redirectURI})
}

// handleTrace returns what the wallet has sent, optionally only what is newer
// than the caller already has.
func (s *Service) handleTrace(w http.ResponseWriter, r *http.Request) {
	entries := s.trace.List()
	if raw := r.URL.Query().Get("since"); raw != "" {
		if since, err := strconv.Atoi(raw); err == nil {
			entries = s.trace.Since(since)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"entries": entries})
}

func (s *Service) handleClearTrace(w http.ResponseWriter, r *http.Request) {
	s.trace.Clear()
	writeJSON(w, http.StatusOK, map[string]any{"cleared": true})
}

func (s *Service) credentialViews() ([]credentialView, error) {
	credentials, _, err := s.wallet.GetCredentialEntries(wallet.GetCredentialEntriesRequest{})
	if err != nil {
		return nil, err
	}

	views := make([]credentialView, 0, len(credentials))
	for _, saved := range credentials {
		if saved == nil || saved.Entry == nil {
			continue
		}
		views = append(views, newCredentialView(saved.Entry))
	}
	return views, nil
}

func newCredentialView(entry *credstoreTypes.CredentialEntry) credentialView {
	view := credentialView{
		ID:         entry.Id,
		MimeType:   entry.MimeType,
		ReceivedAt: entry.ReceivedAt,
		Raw:        string(entry.Raw),
	}

	claims, err := decodeCredentialClaims(entry.Raw)
	if err != nil {
		return view
	}
	view.Types = credentialTypes(claims)
	view.Claims = credentialSubject(claims)
	return view
}

// decodeCredentialClaims reads the claim set of a stored credential without
// verifying it. The signature was checked when the credential was received;
// this is only for display.
func decodeCredentialClaims(raw []byte) (map[string]any, error) {
	// An SD-JWT VC is the issuer-signed JWT followed by tilde-separated
	// disclosures, so the JWT is whatever precedes the first tilde.
	token, _, _ := strings.Cut(string(raw), "~")

	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("the credential is not a JWT")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("the credential payload is not base64url: %w", err)
	}

	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("the credential payload is not JSON: %w", err)
	}
	return claims, nil
}

// credentialTypes reads the credential type from either a W3C VC JWT or an
// SD-JWT VC.
func credentialTypes(claims map[string]any) []string {
	if vct, ok := claims["vct"].(string); ok {
		return []string{vct}
	}

	vc, ok := claims["vc"].(map[string]any)
	if !ok {
		return nil
	}
	rawTypes, ok := vc["type"].([]any)
	if !ok {
		return nil
	}

	types := make([]string, 0, len(rawTypes))
	for _, value := range rawTypes {
		if name, ok := value.(string); ok {
			types = append(types, name)
		}
	}
	return types
}

// credentialSubject reads the claims a person would recognise, from either
// shape of credential.
func credentialSubject(claims map[string]any) map[string]any {
	if vc, ok := claims["vc"].(map[string]any); ok {
		if subject, ok := vc["credentialSubject"].(map[string]any); ok {
			return subject
		}
	}

	// An SD-JWT VC carries its disclosed claims at the top level, next to the
	// registered ones.
	registered := map[string]bool{
		"iss": true, "sub": true, "aud": true, "exp": true, "nbf": true,
		"iat": true, "jti": true, "cnf": true, "vct": true, "_sd": true,
		"_sd_alg": true, "status": true,
	}
	subject := map[string]any{}
	for name, value := range claims {
		if !registered[name] {
			subject[name] = value
		}
	}
	if len(subject) == 0 {
		return nil
	}
	return subject
}

func decodeJSONBody(r *http.Request, target any) error {
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	return decoder.Decode(target)
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// writeError reports a failure in a shape the screens and the end-to-end test
// can both read. The underlying error text is included because every consumer
// of this service is a developer looking at a test run.
func writeError(w http.ResponseWriter, status int, message string, err error) {
	body := map[string]any{"error": message}
	if err != nil {
		body["error_description"] = err.Error()
	}
	writeJSON(w, status, body)
}
