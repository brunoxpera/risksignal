// Command mock-oidc runs the local OpenID Connect test provider of the
// Compose development environment (WP-1a.03; implementation concept §4.2,
// decision D-003). It wraps github.com/oauth2-proxy/mockoidc behind a fixed
// address contract: inside the container it listens on 0.0.0.0:9000, which
// compose publishes to the host as 127.0.0.1:9000 only.
//
// mock-oidc is a development/test tool; product binaries never import it.
// It starts the provider, logs the generated client credentials and the
// discovery URL, then blocks until SIGTERM or SIGINT and shuts the provider
// down cleanly.
package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
)

// listenAddr is the container-internal contract; compose maps it to the
// loopback interface on the host and the healthcheck probes it on localhost.
const listenAddr = "0.0.0.0:9000"

func main() {
	if err := run(); err != nil {
		log.Fatalf("mock-oidc: %v", err)
	}
}

func run() error {
	cfg := mockConfigFromEnv()
	m, err := newServer(cfg)
	if err != nil {
		return err
	}

	// #nosec G102 — deliberate container-internal contract (see file header):
	// compose publishes this listener to the host loopback only.
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", listenAddr, err)
	}

	if err := m.Start(ln, nil); err != nil {
		_ = ln.Close()
		return fmt.Errorf("start mock OIDC server: %w", err)
	}

	log.Printf("mock OIDC provider listening on %s", ln.Addr())
	log.Printf("issuer: %s", m.Issuer())
	log.Printf("discovery: %s", m.DiscoveryEndpoint())
	log.Printf("generated client id %q, client secret %q", m.ClientID, m.ClientSecret)
	log.Printf("test user subject %q, roles claim \"roles\" = %v", cfg.Subject, cfg.Roles)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	<-ctx.Done()
	log.Print("shutting down")
	if err := m.Shutdown(); err != nil {
		return fmt.Errorf("shut down mock OIDC server: %w", err)
	}
	log.Print("shutdown complete")
	return nil
}
