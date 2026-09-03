//go:build windows

package main

// Windows PTY backend via github.com/UserExistsError/conpty -- a real
// ConPTY (Windows Pseudo Console) implementation, not the stub that
// github.com/creack/pty ships for windows (start_windows.go there just
// returns ErrUnsupported -- confirmed by reading it, see cs-console.info).

import (
	"context"
	"fmt"
	"strings"

	"github.com/UserExistsError/conpty"
)

type windowsPTY struct {
	cpty *conpty.ConPty
}

func startPTY(cfg *startConfig) (ptySession, error) {
	if !conpty.IsConPtyAvailable() {
		return nil, fmt.Errorf("ConPTY not available on this Windows version (needs 1809+/Server 2019+)")
	}
	// conpty.Start takes a single command line string, not argv -- build it
	// the same way exec.Command would join them for display, quoting each
	// argument that contains whitespace. Good enough for the target commands
	// this is meant for (passwd, visudo-equivalents, cmd.exe/powershell.exe);
	// revisit if an argument can itself contain embedded quotes.
	parts := append([]string{cfg.Cmd}, cfg.Args...)
	for i, p := range parts {
		if strings.ContainsAny(p, " \t\"") {
			parts[i] = `"` + strings.ReplaceAll(p, `"`, `\"`) + `"`
		}
	}
	commandLine := strings.Join(parts, " ")

	cpty, err := conpty.Start(commandLine)
	if err != nil {
		return nil, fmt.Errorf("starting %q under ConPTY: %w", cfg.Cmd, err)
	}
	return &windowsPTY{cpty: cpty}, nil
}

func (w *windowsPTY) Read(p []byte) (int, error)  { return w.cpty.Read(p) }
func (w *windowsPTY) Write(p []byte) (int, error) { return w.cpty.Write(p) }

func (w *windowsPTY) Resize(cols, rows int) error {
	return w.cpty.Resize(cols, rows)
}

func (w *windowsPTY) Wait() error {
	_, err := w.cpty.Wait(context.Background())
	return err
}

func (w *windowsPTY) Close() error {
	return w.cpty.Close()
}
