//go:build !windows

package main

import (
	"fmt"
	"os"
)

// requireRoot enforces the KISS spawn boundary (cs-console.info SPAWN
// SECURITY -- KISS): cs-console may only be invoked by a root parent
// (server.pl). A non-root parent cannot create a root child, so checking our
// own euid is exactly "the parent had root". Checked before ANY mode.
// cs-console must never be installed setuid/setgid or this equivalence
// breaks.
func requireRoot() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("cs-console requires root (only server.pl may invoke it)")
	}
	return nil
}
