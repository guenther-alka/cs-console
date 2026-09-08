//go:build (linux || darwin || freebsd || netbsd || openbsd || dragonfly || solaris) && !illumos

package main

// POSIX PTY backend (everything except illumos and Windows) via
// github.com/creack/pty. This is the well-trodden piece of the design --
// creack/pty wraps the standard BSD openpty()/forkpty() family, which all
// of these platforms provide natively. See cs-console.info: this does NOT
// cover illumos (pty_solaris.go in creack/pty has //go:build solaris only,
// not "solaris || illumos" -- confirmed by reading the file), hence the
// separate pty_illumos.go. Solaris proper IS covered here: creack/pty's
// pty_solaris.go (pure Go, /dev/ptmx + STREAMS push) provides the PTY.

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/creack/pty"
)

type unixPTY struct {
	cmd *exec.Cmd
	f   *os.File // PTY master, per creack/pty's API
}

func startPTY(cfg *startConfig) (ptySession, error) {
	cmd := exec.Command(cfg.Cmd, cfg.Args...)
	// TERM so ncurses programs (clear, vi, less, top, ...) work in the remote
	// shell. server.pl/the daemon environment has no TERM (or "dumb"), which
	// makes `clear` and friends silent no-ops -- verified live (user typed
	// "clear" in the console and nothing happened).
	// NO_COLOR: UPDATE cs_26.09.08 (review Finding 2.1 -- Niedrig, see
	// session.go's startConfig.NoColor doc): used to be hardcoded ON
	// unconditionally here. Confirmed against the actual deployed console
	// theme (10_System/03_Console action.pl: background #000000,
	// red/green/yellow/blue all distinct, readable colors) that the
	// original black-on-black concern doesn't apply to the current
	// xterm.js theme -- so color now stays ON by default (TERM alone is
	// set), and NO_COLOR=1 is only added when explicitly requested via
	// cfg.NoColor or the CS_CONSOLE_FORCE_NO_COLOR=1 member-level env
	// override, for anyone who still wants plain, escape-code-free text.
	env := append(os.Environ(), "TERM=xterm-256color")
	if cfg.NoColor || os.Getenv("CS_CONSOLE_FORCE_NO_COLOR") == "1" {
		env = append(env, "NO_COLOR=1")
	}
	cmd.Env = env
	f, err := pty.Start(cmd)
	if err != nil {
		return nil, fmt.Errorf("starting %q under pty: %w", cfg.Cmd, err)
	}
	return &unixPTY{cmd: cmd, f: f}, nil
}

func (u *unixPTY) Read(p []byte) (int, error)  { return u.f.Read(p) }
func (u *unixPTY) Write(p []byte) (int, error) { return u.f.Write(p) }

func (u *unixPTY) Resize(cols, rows int) error {
	return pty.Setsize(u.f, &pty.Winsize{Cols: uint16(cols), Rows: uint16(rows)})
}

func (u *unixPTY) Wait() error {
	return u.cmd.Wait()
}

func (u *unixPTY) Close() error {
	// Best-effort: close the master fd, then make sure the child is gone.
	_ = u.f.Close()
	if u.cmd.Process != nil {
		_ = u.cmd.Process.Kill()
	}
	return nil
}
