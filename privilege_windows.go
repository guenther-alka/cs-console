//go:build windows

package main

import (
	"fmt"

	"golang.org/x/sys/windows"
)

// requireRoot enforces the KISS spawn boundary on Windows: only an elevated
// parent can create an elevated child. Checked before ANY mode. cs-console
// must not embed an auto-elevation manifest, or a non-elevated parent could
// auto-elevate us and break the equivalence.
func requireRoot() error {
	tok := windows.GetCurrentProcessToken()
	if !tok.IsElevated() {
		return fmt.Errorf("cs-console requires admin rights (only server.pl may invoke it)")
	}
	return nil
}
