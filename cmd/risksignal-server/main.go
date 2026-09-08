// Command risksignal-server serves the RiskSignal REST API and web frontend.
//
// Process role per implementation concept ch. 4.1: REST API, web UI, OIDC
// sessions, synchronous use cases and health endpoints. WP-1a.02: it loads
// and validates its configuration on startup (defaults -> optional JSON
// config file -> RISKSIGNAL_* environment variables); an invalid
// configuration exits 1 without starting. WP-1a.06: with a valid one it
// serves an as-yet empty http.ServeMux (ADR-008 — no router framework)
// wrapped in the httpapi middleware chain on http.addr, and shuts down
// gracefully on SIGINT/SIGTERM. Routes land in WP-1a.07 (health) and I1b
// (generated API, ADR-011).
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/xpera/risksignal/internal/adapters/httpapi"
	"github.com/xpera/risksignal/internal/platform/config"
)

// shutdownGracePeriod is how long the server waits for in-flight requests
// after a shutdown signal before it gives up (WP-1a.06: clean shutdown with a
// grace period).
const shutdownGracePeriod = 10 * time.Second

func main() {
	logger := log.New(os.Stderr, "risksignal-server ", log.LstdFlags)

	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "risksignal-server: invalid configuration:\n%v\n", err)
		os.Exit(1)
	}
	fmt.Print(cfg.Summary())

	if err := serve(cfg, logger); err != nil {
		logger.Printf("fatal: %v", err)
		os.Exit(1)
	}
}

// serve runs the HTTP server on cfg.HTTP.Addr until a shutdown signal ends
// the process cleanly. It returns nil after a graceful shutdown, and an error
// for anything else (bind failure, serve failure, shutdown timeout).
func serve(cfg *config.Config, logger *log.Logger) error {
	// Routes land in WP-1a.07 and I1b; until then every path 404s — through
	// the middleware chain, which is exactly what this WP must prove.
	mux := http.NewServeMux()
	srv := &http.Server{
		Addr:              cfg.HTTP.Addr,
		Handler:           httpapi.NewHandler(mux, logger),
		ReadHeaderTimeout: 5 * time.Second, // slow-header protection
		IdleTimeout:       60 * time.Second,
		ErrorLog:          logger, // net/http internals (e.g. panics that escape the chain)
	}

	// Listen first so a bind failure is reported synchronously; "listening"
	// is only logged once the address is actually taken.
	ln, err := net.Listen("tcp", cfg.HTTP.Addr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", cfg.HTTP.Addr, err)
	}
	logger.Printf("listening on %s", ln.Addr())

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(ln) }()

	select {
	case err := <-serveErr:
		if errors.Is(err, http.ErrServerClosed) {
			return nil // Serve returned after Shutdown below
		}
		return fmt.Errorf("serve: %w", err)
	case <-ctx.Done():
		logger.Printf("shutdown signal received; draining in-flight requests (grace period %s)",
			shutdownGracePeriod)
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownGracePeriod)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("graceful shutdown: %w", err)
		}
		logger.Printf("shutdown complete")
		return nil
	}
}
