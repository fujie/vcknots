// Package webwallet puts a browser UI in front of the wallet so that the
// issuance, presentation and verification flow can be walked end to end.
//
// It is a thin shell: every protocol step is performed by the wallet package
// itself, so what the screens exercise is the real OID4VCI and OID4VP
// implementation rather than a parallel one written for testing.
//
// It is a test tool, not a wallet anyone should deploy: the holder key is
// generated per process and never persisted, and credentials go by default into
// a database that is discarded when the process ends.
package webwallet

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/trustknots/vcknots/wallet"
	"github.com/trustknots/vcknots/wallet/clientconfig"
	"github.com/trustknots/vcknots/wallet/credstore"
	"github.com/trustknots/vcknots/wallet/credstore/plugins/local"
	"github.com/trustknots/vcknots/wallet/env"
	"github.com/trustknots/vcknots/wallet/idprof"
	"github.com/trustknots/vcknots/wallet/keystore"
	"github.com/trustknots/vcknots/wallet/presenter"
	"github.com/trustknots/vcknots/wallet/presenter/plugins/oid4vp"
	"github.com/trustknots/vcknots/wallet/receiver"
	"github.com/trustknots/vcknots/wallet/serializer"
	verifierdispatch "github.com/trustknots/vcknots/wallet/verifier"
)

// credentialOfferScheme is the URI scheme an OID4VCI credential offer arrives
// under.
const credentialOfferScheme = "openid-credential-offer"

// Options configures the service. Every field is optional: with the zero value
// the wallet generates its own holder key, authenticates anonymously at the
// token endpoint, and trusts no additional X.509 roots.
type Options struct {
	// CertPath is a PEM file of trust roots for verifying a Verifier's
	// certificate chain when a signed Request Object (JAR) is used. Request
	// modes that pass their parameters in the URL carry no signature and need
	// no roots.
	CertPath string

	// InsecureSkipX509Verify disables certificate verification. It exists for
	// conformance testing against self-signed verifiers and must stay false
	// anywhere else.
	InsecureSkipX509Verify bool

	// ClientConfigPath, ClientPrivateJWKPath and ClientID configure
	// private_key_jwt client authentication at the token endpoint. When
	// ClientConfigPath is empty the wallet authenticates anonymously, which the
	// sample authorization server allows.
	ClientConfigPath     string
	ClientPrivateJWKPath string
	ClientID             string

	// StorePath is the credential database this wallet uses. Left empty, the
	// wallet gets a fresh database in a temporary directory, removed by Close.
	//
	// It deliberately does not fall back to the wallet package's default
	// location: that database is shared by every wallet on the machine, so a
	// test run would both inherit whatever is already there and leave its own
	// credentials behind.
	StorePath string
}

// Service holds the wallet and the holder key the screens act on.
type Service struct {
	wallet *wallet.Wallet
	key    wallet.IKeyEntry
	trace  *Trace

	// tempDir is the directory holding a generated credential database, if one
	// was generated. Close removes it.
	tempDir string
}

// Trace is the record of what the wallet has sent. It only fills up once
// InstallTransport has been called.
func (s *Service) Trace() *Trace { return s.trace }

// InstallTransport routes the process's outgoing HTTP through the trace.
//
// The wallet's HTTP clients do not set a Transport of their own, so replacing
// http.DefaultTransport is what makes their requests visible. It changes
// process-global state, which is why it is separate from New: tests construct a
// Service without disturbing anything.
func (s *Service) InstallTransport() {
	http.DefaultTransport = s.trace.Transport(http.DefaultTransport)
}

// Close releases what New allocated. It is safe to call more than once.
func (s *Service) Close() error {
	if s.tempDir == "" {
		return nil
	}
	dir := s.tempDir
	s.tempDir = ""
	return os.RemoveAll(dir)
}

// New builds a wallet and the service that exposes it over HTTP.
func New(options Options) (*Service, error) {
	credStore, tempDir, err := newCredentialStore(options.StorePath)
	if err != nil {
		return nil, err
	}
	receiverDispatcher, err := receiver.NewReceivingDispatcher(receiver.WithDefaultConfig())
	if err != nil {
		return nil, fmt.Errorf("failed to create the receiver: %w", err)
	}
	serializerDispatcher, err := serializer.NewSerializationDispatcher(serializer.WithDefaultConfig())
	if err != nil {
		return nil, fmt.Errorf("failed to create the serializer: %w", err)
	}
	verifierDispatcher, err := verifierdispatch.NewVerificationDispatcher(verifierdispatch.WithDefaultConfig())
	if err != nil {
		return nil, fmt.Errorf("failed to create the verifier: %w", err)
	}
	idProfiler, err := idprof.NewIdentityProfileDispatcher(idprof.WithDefaultConfig())
	if err != nil {
		return nil, fmt.Errorf("failed to create the identity profiler: %w", err)
	}

	trustRoots, err := loadTrustRoots(options.CertPath)
	if err != nil {
		return nil, err
	}
	presenterDispatcher, err := presenter.NewPresentationDispatcher(
		presenter.WithPlugin(presenter.Oid4vp, &oid4vp.Oid4vpPresenter{
			X509TrustChainRoots:    trustRoots,
			InsecureSkipX509Verify: options.InsecureSkipX509Verify,
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create the presenter: %w", err)
	}

	clientAuth, err := loadClientAuth(options)
	if err != nil {
		return nil, err
	}

	key, err := newHolderKey()
	if err != nil {
		return nil, err
	}

	w, err := wallet.NewWalletWithConfig(wallet.Config{
		CredStore:  credStore,
		IDProfiler: idProfiler,
		Receiver:   receiverDispatcher,
		Serializer: serializerDispatcher,
		Verifier:   verifierDispatcher,
		Presenter:  presenterDispatcher,
		ClientAuth: clientAuth,
		// The DPoP key is left unset so the wallet generates one of its own,
		// keeping DPoP key rotation independent of the holder key.
		DPoP: wallet.DPoPConfig{Enabled: true},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create the wallet: %w", err)
	}

	return &Service{wallet: w, key: key, trace: NewTrace(), tempDir: tempDir}, nil
}

// newCredentialStore opens the credential database, creating a temporary one
// when no path was configured. The second return value is the directory to
// remove on Close, empty when the caller supplied the path.
func newCredentialStore(storePath string) (*credstore.CredStoreDispatcher, string, error) {
	var tempDir string
	if strings.TrimSpace(storePath) == "" {
		dir, err := os.MkdirTemp("", "vcknots-webwallet-")
		if err != nil {
			return nil, "", fmt.Errorf("failed to create the credential store directory: %w", err)
		}
		tempDir = dir
		storePath = filepath.Join(dir, "credstore.db")
	}

	plugin, err := local.NewLocalCredentialStorage(storePath)
	if err != nil {
		_ = os.RemoveAll(tempDir)
		return nil, "", fmt.Errorf("failed to open the credential store %q: %w", storePath, err)
	}

	dispatcher, err := credstore.NewCredStoreDispatcher(credstore.WithPlugin(local.Local, plugin))
	if err != nil {
		_ = os.RemoveAll(tempDir)
		return nil, "", fmt.Errorf("failed to create the credential store: %w", err)
	}
	return dispatcher, tempDir, nil
}

// loadTrustRoots reads the PEM trust roots, if any were configured.
func loadTrustRoots(certPath string) (*x509.CertPool, error) {
	if strings.TrimSpace(certPath) == "" {
		return nil, nil
	}

	pem, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read the trust roots %q: %w", certPath, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("the trust roots %q contain no usable certificate", certPath)
	}
	return pool, nil
}

// loadClientAuth reads the private_key_jwt registration, if one was configured.
func loadClientAuth(options Options) (wallet.ClientAuthConfig, error) {
	if strings.TrimSpace(options.ClientConfigPath) == "" {
		return wallet.ClientAuthConfig{}, nil
	}

	loadOptions := []clientconfig.Option{
		// The sample private key is committed so the flow runs straight after a
		// clone, and git does not preserve file modes.
		clientconfig.AllowInsecureFilePermissions(),
	}
	if options.ClientID != "" {
		loadOptions = append(loadOptions, clientconfig.WithClientID(options.ClientID))
	}
	if options.ClientPrivateJWKPath != "" {
		loadOptions = append(loadOptions, clientconfig.WithPrivateJWKFile(options.ClientPrivateJWKPath))
	}

	auth, err := clientconfig.Load(options.ClientConfigPath, loadOptions...)
	if err != nil {
		return wallet.ClientAuthConfig{}, fmt.Errorf("failed to load the client registration: %w", err)
	}
	return auth, nil
}

// newHolderKey generates the key the wallet proves possession of when
// requesting a credential and when signing a presentation.
func newHolderKey() (wallet.IKeyEntry, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate the holder key: %w", err)
	}

	entry, err := keystore.NewKeyEntryFromJWK(jose.JSONWebKey{
		Key:       privateKey,
		KeyID:     "holder-key-1",
		Algorithm: string(jose.ES256),
		Use:       "sig",
	})
	if err != nil {
		return nil, fmt.Errorf("failed to wrap the holder key: %w", err)
	}
	return entry, nil
}

// offerFetchTimeout bounds the dereferencing of a credential_offer_uri.
const offerFetchTimeout = 30 * time.Second

// fetchCredentialOffer dereferences a credential_offer_uri (OID4VCI 1.0
// Section 4.1), which points at "a resource containing a JSON object with the
// Credential Offer parameters".
//
// The specification requires the https scheme. Plain HTTP is allowed only under
// the same switch the rest of this wallet uses for talking to a local issuer.
func fetchCredentialOffer(offerURI string) (string, error) {
	parsed, err := url.Parse(offerURI)
	if err != nil {
		return "", fmt.Errorf("credential_offer_uri is not a URI: %w", err)
	}
	if !strings.EqualFold(parsed.Scheme, "https") {
		if !env.IsHTTPAllowed() || !strings.EqualFold(parsed.Scheme, "http") {
			return "", fmt.Errorf("credential_offer_uri must use the https scheme, got %q", parsed.Scheme)
		}
	}

	client := &http.Client{Timeout: offerFetchTimeout}
	response, err := client.Get(parsed.String())
	if err != nil {
		return "", fmt.Errorf("failed to fetch credential_offer_uri: %w", err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("credential_offer_uri returned status %d", response.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(response.Body, maxOfferBytes))
	if err != nil {
		return "", fmt.Errorf("failed to read credential_offer_uri: %w", err)
	}
	return string(body), nil
}

// maxOfferBytes caps what a credential_offer_uri may return, so that a hostile
// or broken endpoint cannot exhaust memory.
const maxOfferBytes = 1 << 20

// ParseCredentialOffer accepts what an issuer hands out and returns the offer
// the wallet needs.
//
// A bare credential offer JSON document is accepted, since the screens let one
// be pasted directly. Otherwise the offer is an
// `openid-credential-offer://` URI, which OID4VCI 1.0 Section 4.1 says carries
// "a single URI query parameter, either credential_offer or
// credential_offer_uri": by value, or by reference to a resource holding the
// same JSON object. Each "MUST NOT be present when the other is present".
func ParseCredentialOffer(raw string) (*wallet.CredentialOffer, error) {
	document := strings.TrimSpace(raw)
	if document == "" {
		return nil, fmt.Errorf("the credential offer is empty")
	}

	if !strings.HasPrefix(document, "{") {
		parsed, err := url.Parse(document)
		if err != nil {
			return nil, fmt.Errorf("the credential offer is neither JSON nor a URI: %w", err)
		}
		if parsed.Scheme != credentialOfferScheme {
			return nil, fmt.Errorf("expected a %s:// URI, got scheme %q", credentialOfferScheme, parsed.Scheme)
		}

		query := parsed.Query()
		byValue := query.Get("credential_offer")
		byReference := query.Get("credential_offer_uri")

		switch {
		case byValue != "" && byReference != "":
			return nil, fmt.Errorf("the credential offer carries both credential_offer and credential_offer_uri, which Section 4.1 forbids")
		case byValue != "":
			document = byValue
		case byReference != "":
			document, err = fetchCredentialOffer(byReference)
			if err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("the credential offer URI carries neither credential_offer nor credential_offer_uri")
		}
	}

	var offer struct {
		CredentialIssuer           string   `json:"credential_issuer"`
		CredentialConfigurationIDs []string `json:"credential_configuration_ids"`
		Grants                     map[string]struct {
			PreAuthorizedCode string `json:"pre-authorized_code"`
		} `json:"grants"`
	}
	if err := json.Unmarshal([]byte(document), &offer); err != nil {
		return nil, fmt.Errorf("failed to parse the credential offer: %w", err)
	}
	if offer.CredentialIssuer == "" {
		return nil, fmt.Errorf("the credential offer names no credential_issuer")
	}

	issuer, err := url.Parse(offer.CredentialIssuer)
	if err != nil {
		return nil, fmt.Errorf("the credential offer has an invalid credential_issuer: %w", err)
	}

	grants := make(map[string]*wallet.CredentialOfferGrant, len(offer.Grants))
	for grantType, grant := range offer.Grants {
		grants[grantType] = &wallet.CredentialOfferGrant{PreAuthorizedCode: grant.PreAuthorizedCode}
	}

	return &wallet.CredentialOffer{
		CredentialIssuer:           issuer,
		CredentialConfigurationIDs: offer.CredentialConfigurationIDs,
		Grants:                     grants,
	}, nil
}
