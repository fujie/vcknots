package webwallet

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Tracing what the wallet sends, so the protocol flow can be watched from the
// wallet's side as well as the server's.
//
// The server sees every protocol message too, but only the ones that reach it.
// This side additionally shows requests the wallet made that failed before an
// answer came back, and the order the wallet did things in.
//
// Bodies are kept verbatim, access tokens and pre-authorized codes included,
// which is the point of a protocol monitor and the reason this belongs in a test
// tool only.

// defaultTraceCapacity is how many exchanges to keep before dropping the oldest.
const defaultTraceCapacity = 300

// maxTraceBodyLength caps a recorded body.
const maxTraceBodyLength = 16_000

// TraceMessage is one half of an exchange.
type TraceMessage struct {
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body,omitempty"`
	// JSON reports that Body was pretty-printed.
	JSON      bool `json:"json,omitempty"`
	Truncated bool `json:"truncated,omitempty"`
}

// TraceEntry is one request the wallet made and the answer it got.
type TraceEntry struct {
	// ID is monotonic, so a screen can ask for everything after what it has.
	ID         int          `json:"id"`
	At         time.Time    `json:"at"`
	DurationMs int64        `json:"durationMs"`
	Step       string       `json:"step"`
	Method     string       `json:"method"`
	URL        string       `json:"url"`
	Status     int          `json:"status"`
	Request    TraceMessage `json:"request"`
	Response   TraceMessage `json:"response"`
	// Error is set when no response came back at all.
	Error string `json:"error,omitempty"`
	// Notes point out what a reader would otherwise decode by hand.
	Notes []string `json:"notes"`
}

// Trace holds the exchanges. It is safe for concurrent use.
type Trace struct {
	mu       sync.Mutex
	entries  []TraceEntry
	nextID   int
	capacity int
}

// NewTrace creates an empty trace.
func NewTrace() *Trace {
	return &Trace{nextID: 1, capacity: defaultTraceCapacity}
}

// List returns every entry, oldest first.
func (t *Trace) List() []TraceEntry {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]TraceEntry(nil), t.entries...)
}

// Since returns the entries recorded after id, for polling.
func (t *Trace) Since(id int) []TraceEntry {
	t.mu.Lock()
	defer t.mu.Unlock()

	entries := make([]TraceEntry, 0, len(t.entries))
	for _, entry := range t.entries {
		if entry.ID > id {
			entries = append(entries, entry)
		}
	}
	return entries
}

// Clear discards everything recorded so far.
func (t *Trace) Clear() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.entries = nil
}

func (t *Trace) record(entry TraceEntry) {
	t.mu.Lock()
	defer t.mu.Unlock()

	entry.ID = t.nextID
	t.nextID++
	t.entries = append(t.entries, entry)
	if len(t.entries) > t.capacity {
		t.entries = t.entries[len(t.entries)-t.capacity:]
	}
}

// Transport wraps base so every request through it is recorded. A nil base means
// http.DefaultTransport.
//
// The wallet's HTTP clients do not set a Transport of their own, so installing
// the result as http.DefaultTransport captures everything the wallet sends
// without the wallet package knowing about it.
func (t *Trace) Transport(base http.RoundTripper) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	return &tracingTransport{trace: t, base: base}
}

type tracingTransport struct {
	trace *Trace
	base  http.RoundTripper
}

func (tt *tracingTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	startedAt := time.Now()

	// A RoundTripper must not modify the request it is given, so the body is
	// read out and put on a copy.
	outgoing := request.Clone(request.Context())
	var requestBody []byte
	if request.Body != nil {
		requestBody, _ = io.ReadAll(request.Body)
		_ = request.Body.Close()
		outgoing.Body = io.NopCloser(bytes.NewReader(requestBody))
		outgoing.ContentLength = int64(len(requestBody))
	}

	response, err := tt.base.RoundTrip(outgoing)

	entry := TraceEntry{
		At:         startedAt,
		DurationMs: time.Since(startedAt).Milliseconds(),
		Step:       traceStep(request.Method, request.URL),
		Method:     request.Method,
		URL:        request.URL.String(),
		Request:    newTraceMessage(request.Header, requestBody),
		Notes:      []string{},
	}

	if err != nil {
		entry.Error = err.Error()
		tt.trace.record(entry)
		return response, err
	}

	// The response body is read here, so it has to be put back for the caller.
	responseBody, _ := io.ReadAll(response.Body)
	_ = response.Body.Close()
	response.Body = io.NopCloser(bytes.NewReader(responseBody))

	entry.Status = response.StatusCode
	entry.Response = newTraceMessage(response.Header, responseBody)
	entry.Notes = traceNotes(request, entry.Request)
	tt.trace.record(entry)

	return response, nil
}

// traceStep names an exchange in protocol terms.
func traceStep(method string, target *url.URL) string {
	path := target.Path
	switch {
	case strings.HasSuffix(path, "/.well-known/openid-credential-issuer"):
		return "OID4VCI · Credential Issuer Metadata"
	case strings.HasSuffix(path, "/.well-known/jwt-vc-issuer"):
		return "OID4VCI · JWT VC Issuer Metadata"
	case strings.HasSuffix(path, "/.well-known/oauth-authorization-server"),
		strings.HasSuffix(path, "/.well-known/openid-configuration"):
		return "OAuth · Authorization Server Metadata"
	case strings.HasSuffix(path, "/token"):
		return "OAuth · Token Request"
	case strings.HasSuffix(path, "/nonce"):
		return "OID4VCI · Nonce"
	case strings.HasSuffix(path, "/credentials"):
		return "OID4VCI · Credential Request"
	case strings.Contains(path, "/request.jwt/"):
		return "OID4VP · Request Object fetched (JAR)"
	case strings.Contains(path, "/callback"):
		return "OID4VP · Authorization Response sent"
	default:
		return fmt.Sprintf("%s %s", method, path)
	}
}

// traceNotes points out the parts of an exchange worth reading.
func traceNotes(request *http.Request, message TraceMessage) []string {
	notes := []string{}

	if _, present := message.Headers["dpop"]; present {
		notes = append(notes, "Carries a DPoP proof")
	}
	if authorization, present := message.Headers["authorization"]; present {
		scheme, _, _ := strings.Cut(authorization, " ")
		notes = append(notes, fmt.Sprintf("Authorization: %s", scheme))
	}

	// The Authorization Response the wallet posts is the interesting one: when it
	// is encrypted, its JWE header says which algorithm was chosen.
	if request.Method == http.MethodPost && strings.Contains(request.URL.Path, "/callback") && message.Body != "" {
		if values, err := url.ParseQuery(message.Body); err == nil {
			if response := values.Get("response"); response != "" {
				if header := readCompactJOSEHeader(response); header != nil {
					note := fmt.Sprintf("JWE protected header: alg=%v", header["alg"])
					if kid, present := header["kid"]; present {
						note += fmt.Sprintf(", kid=%v", kid)
					}
					notes = append(notes, note)
					if alg, ok := header["alg"].(string); ok && strings.HasPrefix(alg, "HPKE-") {
						notes = append(notes,
							"JOSE HPKE Integrated Encryption: the encapsulated secret is the JWE Encrypted Key, "+
								"and the initialization vector and authentication tag are empty")
					}
				}
			} else if values.Get("vp_token") != "" {
				notes = append(notes, "Sent in the clear as form fields (response_mode=direct_post)")
			}
		}
	}

	return notes
}

// readCompactJOSEHeader decodes the protected header of a compact JWS or JWE
// without verifying anything.
func readCompactJOSEHeader(token string) map[string]any {
	header, _, found := strings.Cut(token, ".")
	if !found {
		return nil
	}
	decoded, err := base64.RawURLEncoding.DecodeString(header)
	if err != nil {
		return nil
	}
	var parsed map[string]any
	if err := json.Unmarshal(decoded, &parsed); err != nil {
		return nil
	}
	return parsed
}

// traceHeaders are the header names worth showing; the rest is transport noise.
var traceHeaders = map[string]bool{
	"content-type":  true,
	"authorization": true,
	"dpop":          true,
	"dpop-nonce":    true,
	"accept":        true,
	"location":      true,
}

func newTraceMessage(headers http.Header, body []byte) TraceMessage {
	message := TraceMessage{Headers: map[string]string{}}
	for name, values := range headers {
		if traceHeaders[strings.ToLower(name)] && len(values) > 0 {
			message.Headers[strings.ToLower(name)] = values[0]
		}
	}
	if len(body) == 0 {
		return message
	}

	text := string(body)
	var pretty bytes.Buffer
	if json.Indent(&pretty, body, "", "  ") == nil {
		text = pretty.String()
		message.JSON = true
	}

	if len(text) > maxTraceBodyLength {
		text = text[:maxTraceBodyLength]
		message.Truncated = true
	}
	message.Body = text
	return message
}
