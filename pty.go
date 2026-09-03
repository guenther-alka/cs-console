package main

// Common PTY abstraction. Each platform file (pty_unix.go, pty_windows.go,
// pty_illumos.go) implements startPTY() for its GOOS. See cs-console.info
// CHOSEN DESIGN point A for why three different backends are needed:
//   - linux/darwin/freebsd/netbsd/openbsd/dragonfly: github.com/creack/pty
//   - windows: github.com/UserExistsError/conpty (real ConPTY)
//   - illumos: hand-rolled STREAMS pty (no forkpty() in illumos libc) --
//     UNTESTED on real hardware, see pty_illumos.go header comment.

import "io"

// ptySession is a running interactive program attached to a pseudo-terminal.
type ptySession interface {
	io.ReadWriter // Read = program's output, Write = keyboard input to send it
	Resize(cols, rows int) error
	Wait() error // blocks until the target program exits
	Close() error
}
