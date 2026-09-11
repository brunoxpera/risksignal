// Command age-keygen prints a fresh age X25519 identity to stdout (WP-6.09 /
// DEV-122). It is a local development convenience only: the `make backup` and
// `make restore-test` targets use it to inject a throwaway `age` identity when
// the operator has not provided one. Production never uses this — the backup
// sidecar gets its identity through backup.encryption_key_ref (a
// runtime-injected secret, never in the repository or an image layer).
package main

import (
	"fmt"
	"os"

	"filippo.io/age"
)

func main() {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		fmt.Fprintf(os.Stderr, "age-keygen: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(identity.String())
}
