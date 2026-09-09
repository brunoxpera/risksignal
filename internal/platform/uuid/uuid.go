// Package uuid provides the platform's UUID helper (implementation concept
// ch. 7.2 "Identitäten und Zeit": identifiers are uuids, and command
// correlation and event identities are generated at the application layer —
// the database only defaults primary keys via gen_random_uuid()).
//
// Generation is deliberately dependency-free: 128 bits from crypto/rand in
// the RFC 4122 version-4 layout, formatted canonically. The panic on a
// crypto/rand failure mirrors the existing correlation-id generator in the
// httpapi adapter: crypto/rand.Read never fails on supported platforms, and
// falling back to guessable identifiers would be worse than failing loudly.
package uuid

import (
	"crypto/rand"
	"fmt"
)

// New returns a new random (version 4) UUID as a canonical 36-character
// string, e.g. "5d9f1c2e-3a4b-4c5d-8e6f-1a2b3c4d5e6f".
func New() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("uuid: crypto/rand unavailable: " + err.Error())
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // RFC 4122 variant
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
