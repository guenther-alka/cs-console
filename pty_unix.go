//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly

package main

// POSIX PTY backend (everything except illumos and Windows) via
// github.com/creack/pty. This is the well-trodden piece of the design --
// creack/pty wraps the standard BSD openpty()/forkpty() family, which all
// of these platforms provide natively. See cs-console.info: this does NOT
// cover illumos (pty_solaris.go in creack/pty has //go:build solaris only,
// not "solaris || illumos" -- confirmed by reading the file), hence the
// separate pty_illumos.go.

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
