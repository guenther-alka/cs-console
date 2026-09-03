// cs-console -- ephemeral, per-request interactive PTY relay for napp-it cs.
//
// Spawned by server.pl for exactly one interactive session (see
// cs-console.info design point B: NOT a standing daemon). Reads its start
// config from stdin, starts the target program under a real PTY (platform-
// specific backend, see pty.go/pty_*.go), listens for exactly one direct
// connection from the frontend, authenticates it by IP + one-time session
// token, then relays PTY bytes over that connection with ChaCha20-Poly1305
// application-level encryption (crypto.go) until the program exits, the
// connection closes, or a timeout fires. Then it exits -- there is nothing
// left running when no session is open.
//
// See data/howto.ai/cs-console.info in the csweb-gui repo for the full
// design this implements.
package main

import (
	"crypto/subtle"
	"fmt"
	"net"
	"os"
	"time"
)

const (
	defaultIdleTimeout  = 15 * time.Minute
	defaultMaxTimeout   = 4 * time.Hour
	acceptWindow        = 30 * time.Second // how long we wait for the frontend to connect at all
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "cs-console: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := readStartConfig()
	if err != nil {
		return err
	}

	idleTimeout := defaultIdleTimeout
	if cfg.IdleSecs > 0 {
		idleTimeout = time.Duration(cfg.IdleSecs) * time.Second
	}
	maxTimeout := defaultMaxTimeout
	if cfg.MaxSecs > 0 {
		maxTimeout = time.Duration(cfg.MaxSecs) * time.Second
	}

	pty, err := startPTY(cfg)
	if err != nil {
		return fmt.Errorf("starting PTY: %w", err)
	}
	defer pty.Close()

	sessionToken, err := newSessionToken()
	if err != nil {
		return err
	}
	sessionKey, err := newSessionKey()
	if err != nil {
		return err
	}

	// Loopback-only as basic hygiene per cs-console.info design C -- the
	// token is what actually gates access, this is cheap extra insurance.
	// NOTE: for the frontend to reach us across the network, this needs to
	// listen on a network-reachable address in the real deployment, not
	// 127.0.0.1 -- left as 0.0.0.0 here with the IP-pin + token as the real
	// gate (see IMPORTANT CLARIFICATION in cs-console.info design D for why
	// the transport binding itself is not the security boundary here).
	ln, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		return fmt.Errorf("listening: %w", err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	if err := writeStartResult(port, sessionToken, sessionKey); err != nil {
		return fmt.Errorf("reporting start result to server.pl: %w", err)
	}

	// PTY exit tears the whole process down regardless of connection state.
	ptyDone := make(chan error, 1)
	go func() { ptyDone <- pty.Wait() }()

	conn, err := acceptOne(ln, cfg.FrontendIP, acceptWindow)
	if err != nil {
		return fmt.Errorf("accepting frontend connection: %w", err)
	}
	defer conn.Close()

	if err := authenticate(conn, sessionKey, sessionToken); err != nil {
		return fmt.Errorf("authenticating frontend connection: %w", err)
	}

	relayDone := make(chan struct{})
	go relay(conn, pty, sessionKey, idleTimeout, relayDone)

	select {
	case err := <-ptyDone:
		return err // target program exited -- session over
	case <-relayDone:
		return nil // connection closed or idle/max timeout -- session over
	case <-time.After(maxTimeout):
		return fmt.Errorf("session exceeded max duration %s", maxTimeout)
	}
}

// acceptOne accepts exactly one connection within window and verifies its
// peer IP matches expectIP (see cs-console.info: token is IP-pinned to the
// frontend's source IP as seen by server.pl at request time).
func acceptOne(ln net.Listener, expectIP string, window time.Duration) (net.Conn, error) {
	type result struct {
		conn net.Conn
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		conn, err := ln.Accept()
		ch <- result{conn, err}
	}()

	select {
	case r := <-ch:
		if r.err != nil {
			return nil, r.err
		}
		host, _, err := net.SplitHostPort(r.conn.RemoteAddr().String())
		if err != nil {
			r.conn.Close()
			return nil, fmt.Errorf("parsing peer address: %w", err)
		}
		if host != expectIP {
			r.conn.Close()
			return nil, fmt.Errorf("connection from %s rejected: token was issued for %s", host, expectIP)
		}
		return r.conn, nil
	case <-time.After(window):
		return nil, fmt.Errorf("no connection within %s", window)
	}
}

// authenticate reads the first sealed frame from conn and checks it's
// exactly the session token, using a constant-time comparison (see
// cs-console.info: avoid a timing side-channel on the token check).
func authenticate(conn net.Conn, sessionKey, sessionToken []byte) error {
	r, err := newSealedReader(conn, sessionKey)
	if err != nil {
		return err
	}
	frame, err := r.ReadFrame()
	if err != nil {
		return fmt.Errorf("reading auth frame: %w", err)
	}
	if len(frame) != len(sessionToken) || subtle.ConstantTimeCompare(frame, sessionToken) != 1 {
		return fmt.Errorf("session token mismatch")
	}
	return nil
}

// relay pumps bytes both directions between the PTY and the encrypted
// connection until either side closes or idleTimeout elapses with no
// traffic. Closes done when finished.
func relay(conn net.Conn, pty ptySession, sessionKey []byte, idleTimeout time.Duration, done chan<- struct{}) {
	defer close(done)

	w, err := newSealedWriter(conn, sessionKey)
	if err != nil {
		return
	}
	r, err := newSealedReader(conn, sessionKey)
	if err != nil {
		return
	}

	lastActivity := make(chan struct{}, 1)
	signalActivity := func() {
		select {
		case lastActivity <- struct{}{}:
		default:
		}
	}

	// PTY output -> encrypted frames to frontend.
	go func() {
		buf := make([]byte, 32*1024)
		for {
			n, err := pty.Read(buf)
			if n > 0 {
				signalActivity()
				if werr := w.WriteFrame(buf[:n]); werr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()

	// Encrypted frames from frontend -> PTY input.
	go func() {
		for {
			frame, err := r.ReadFrame()
			if err != nil {
				return
			}
			signalActivity()
			if _, werr := pty.Write(frame); werr != nil {
				return
			}
		}
	}()

	// Idle watchdog. Either goroutine above exiting also eventually shows
	// up here as silence, so this is the single teardown trigger for the
	// "connection/PTY died quietly" case as well as genuine idleness.
	timer := time.NewTimer(idleTimeout)
	defer timer.Stop()
	for {
		select {
		case <-lastActivity:
			if !timer.Stop() {
				<-timer.C
			}
			timer.Reset(idleTimeout)
		case <-timer.C:
			return
		}
	}
}
