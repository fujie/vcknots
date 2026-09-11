// Command webwallet runs the browser-facing wallet used for end-to-end testing.
//
//	go run ./webwallet/cmd/webwallet
//
// It pairs with the issuer and verifier screens the sample server serves at
// /ui. See wallet/webwallet for what it does and does not do.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/trustknots/vcknots/wallet/env"
	"github.com/trustknots/vcknots/wallet/webwallet"
)

func main() {
	addr := flag.String("addr", envOr("WEBWALLET_ADDR", ":8081"), "address to listen on")
	certPath := flag.String("cert", os.Getenv("VCKNOTS_CERT_PATH"),
		"PEM trust roots for verifying a verifier's certificate chain in a signed Request Object")
	insecureSkipX509Verify := flag.Bool("insecure-skip-x509-verify", false,
		"skip verifier certificate verification (conformance testing only)")
	clientConfigPath := flag.String("client-config", os.Getenv("WEBWALLET_CLIENT_CONFIG"),
		"client registration file enabling private_key_jwt at the token endpoint (optional)")
	clientPrivateJWKPath := flag.String("client-key", os.Getenv("WEBWALLET_CLIENT_KEY"),
		"private JWK for private_key_jwt client authentication")
	clientID := flag.String("client-id", os.Getenv("WEBWALLET_CLIENT_ID"),
		"client_id to select from the client registration file")
	storePath := flag.String("store", os.Getenv("WEBWALLET_STORE"),
		"credential database to use (default: a temporary one, discarded on exit)")
	allowHTTP := flag.Bool("allow-http", envOr("WEBWALLET_ALLOW_HTTP", "true") == "true",
		"allow plain HTTP issuer and verifier endpoints, as local testing needs")
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	// Local runs talk to http://localhost servers, which the wallet rejects
	// unless plain HTTP is explicitly allowed.
	env.SetHTTPAllowed(*allowHTTP)

	service, err := webwallet.New(webwallet.Options{
		CertPath:               *certPath,
		InsecureSkipX509Verify: *insecureSkipX509Verify,
		ClientConfigPath:       *clientConfigPath,
		ClientPrivateJWKPath:   *clientPrivateJWKPath,
		ClientID:               *clientID,
		StorePath:              *storePath,
	})
	if err != nil {
		logger.Error("Failed to start the wallet", "error", err)
		os.Exit(1)
	}

	// Route the wallet's own outgoing HTTP through the trace, so the wallet
	// screen can show the protocol from the wallet's side.
	service.InstallTransport()

	server := &http.Server{
		Addr:              *addr,
		Handler:           service.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	// Shutting down on a signal is what lets the temporary credential database
	// be removed: an end-to-end run stops this process with SIGTERM.
	ctx, stopListening := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopListening()

	serverStopped := make(chan error, 1)
	go func() {
		logger.Info("Wallet listening", "addr", *addr, "url", fmt.Sprintf("http://localhost%s", *addr))
		serverStopped <- server.ListenAndServe()
	}()

	var exitCode int
	select {
	case err := <-serverStopped:
		if err != nil && err != http.ErrServerClosed {
			logger.Error("The wallet stopped", "error", err)
			exitCode = 1
		}
	case <-ctx.Done():
		logger.Info("Shutting the wallet down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			logger.Warn("The wallet did not shut down cleanly", "error", err)
		}
	}

	if err := service.Close(); err != nil {
		logger.Warn("Failed to clean up the credential store", "error", err)
	}
	os.Exit(exitCode)
}

func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
