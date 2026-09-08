// Command risksignal-worker runs the RiskSignal background worker.
//
// Process role per implementation concept ch. 4.1: source fetching,
// normalisation, matching, prioritisation, SLA escalation, retention, outbox
// and notifications. WP-1a.01 skeleton only: it prints a startup line and
// exits 0. The scheduler loop lands in WP-1a.10.
package main

import "fmt"

func main() {
	fmt.Println("risksignal-worker starting (skeleton) — jobs and scheduler; scheduler loop lands in WP-1a.10")
}
