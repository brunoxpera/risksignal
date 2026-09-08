// Command risksignal-server serves the RiskSignal REST API and web frontend.
//
// Process role per implementation concept ch. 4.1: REST API, web UI, OIDC
// sessions, synchronous use cases and health endpoints. WP-1a.01 skeleton
// only: it prints a startup line and exits 0. The HTTP server loop lands in
// WP-1a.06.
package main

import "fmt"

func main() {
	fmt.Println("risksignal-server starting (skeleton) — API and web; server loop lands in WP-1a.06")
}
