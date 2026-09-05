package main

// expect.go -- EXPECT MODE (cs-console.info EXPECT MODE + SPAWN SECURITY):
// a scripted, allowlisted interactive action ("expect replacement"), driven
// by cs-console under a real PTY. NOT free text: every action is a fixed
// table entry (cmd + argv template + fixed prompt tokens + fixed final
// marker), hand-verified per platform. Runs with LC_ALL=C so prompts are
// deterministic. Fail-closed: prompt mismatch or step timeout aborts with
// an error -- never types past into a shell.
//
// Invoked via the stdin JSON start config (mode:"expect", action, args,
// secret_file) -- see session.go / main.go. The secret (e.g. the new
// password) travels ONLY through secret_file (a 0600 root file server.pl
// writes), never argv / shell history / logs / the config line.
//
// Result: one JSON line on stdout, { ok, msg }.
//
// Real rationale (Gea): this is NOT root-containment (&exe already runs
// arbitrary commands as root); it exists because some OSes have no
// scriptable one-shot form for interactive programs (illumos/Solaris
// passwd reads only from the controlling tty), it is fail-closed TTY
// scripting, and credential changes stay on one auditable channel.

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"
)

// expectAction is one allowlisted scripted action.
type expectAction struct {
	ID              string   // allowlist id, e.g. "passwd_user"
	Cmd             string   // fixed program (resolved via PATH; never a shell)
	Args            []string // fixed argv template; "{user}" = cfg.Args[0]
	Prompts         []string // ordered prompt tokens to await (each followed by secret + "\n")
	SuccessMarker   string   // required success output fragment ("" = exit-code based)
	FailMarkers     []string // any of these anywhere -> abort as failure
	NoSuccessMarker bool     // program prints no success text (e.g. smbpasswd):
	// success = process exit code 0 AND no fail marker (cs_26.09.05)
}

// expectTable -- the compiled allowlist. Hand-verified per platform.
// RESTRICTION (Gea, cs_26.09.05): changing the ROOT/Administrator password
// is NOT allowed as a direct expect action -- that requires the interactive
// console (shell-mode login with the OS password gate). expect only covers
// NON-privileged accounts (passwd_user, smbpasswd_user, ksmbd_user); a
// uid-0 target is rejected below.
var expectTable = []expectAction{
	{
		ID:            "passwd_user",
		Cmd:           "passwd",
		Args:          []string{"{user}"},
		Prompts:       []string{"New Password:", "Re-enter new Password:"},
		SuccessMarker: "successfully changed",
		FailMarkers:   []string{"does not meet", "too short", "mismatch", "unchanged", "password not changed", "failed"},
	},
	{
		// smbpasswd_user: change a Samba user's password as root. Prompts
		// VERIFIED live on 192.168.2.187 (Proxmox/Samba) cs_26.09.05:
		// "New SMB password:" / "Retype new SMB password:"; on success
		// smbpasswd prints NO text (exit 0 only), hence NoSuccessMarker.
		ID:              "smbpasswd_user",
		Cmd:             "smbpasswd",
		Args:            []string{"{user}"},
		Prompts:         []string{"New SMB password:", "Retype new SMB password:"},
		FailMarkers:     []string{"unable to get new password", "mismatch", "failed", "error"},
		NoSuccessMarker: true,
	},
	{
		// ksmbd_user: change a ksmbd (kernel SMB server) user's password.
		// ksmbd-tools' ksmbd.adduser INTERACTIVE modes (-a add / -u update)
		// enforce a real TTY (getpass reads the controlling tty -- no batch/
		// stdin form for the interactive path), which is exactly what expect
		// mode exists for. CAPTURED + VERIFIED live on 192.168.2.185
		// (Proxmox/ksmbd) cs_26.09.05: ksmbd.adduser -u <user> prompts
		// "New password:" / "Retype password:" (each preceded by an ANSI
		// ESC[2K erase-line sequence -- matched fine after norm()/LC_ALL=C)
		// and on success prints "INFO: Updated user `X'" (hence the
		// SuccessMarker) and exits 0. Notes: (1) -u UPDATE is the change
		// path -- -a ADD refuses an existing user ("already exists"), so a
		// change must NOT be built on -a; (2) the -p PWD batch flag exists
		// but would put the new password in argv/process list -- expect is
		// deliberately used instead so the secret only travels via the 0600
		// secret_file -> PTY.
		ID:            "ksmbd_user",
		Cmd:           "ksmbd.adduser",
		Args:          []string{"-u", "{user}"},
		Prompts:       []string{"New password:", "Retype password:"},
		SuccessMarker: "Updated user",
		FailMarkers:   []string{"does not exist", "already exists", "mismatch", "error", "failed"},
	},
}

func expectActionByName(id string) *expectAction {
	for i := range expectTable {
		if expectTable[i].ID == id {
			return &expectTable[i]
		}
	}
	return nil
}

// writeExpectResult prints the one result JSON line to stdout.
func writeExpectResult(ok bool, msg string) error {
	b, _ := json.Marshal(map[string]any{"ok": ok, "msg": msg})
	fmt.Println(string(b))
	return nil
}

// runExpect is the expect-mode entry (called from main.go run()). It runs
// the allowlisted action under a PTY, drives the fixed prompts, and prints
// { ok, msg } to stdout. Always returns nil (the result is the JSON line).
func runExpect(cfg *startConfig) error {
	act := expectActionByName(cfg.Action)
	if act == nil {
		return writeExpectResult(false, fmt.Sprintf("unknown expect action %q", cfg.Action))
	}
	args := make([]string, 0, len(act.Args))
	for _, a := range act.Args {
		if a == "{user}" {
			if len(cfg.Args) < 1 || cfg.Args[0] == "" {
				return writeExpectResult(false, "expect action "+cfg.Action+" requires a user argument")
			}
			args = append(args, cfg.Args[0])
		} else {
			args = append(args, a)
		}
	}
	secret, err := readExpectSecret(cfg)
	if err != nil {
		return writeExpectResult(false, err.Error())
	}
	// RESTRICTION (Gea, cs_26.09.05): never change the root/Administrator
	// password through a direct expect action -- that requires the
	// interactive console (shell-mode login). Reject any uid-0 target.
	if len(args) > 0 && isPrivilegedTarget(args[0]) {
		return writeExpectResult(false, "changing the root/administrator password is not allowed via expect -- it requires the interactive console (shell-mode login)")
	}
	_ = os.Setenv("LC_ALL", "C") // deterministic prompts; inherited by the child

	pty, err := startPTY(&startConfig{Cmd: act.Cmd, Args: args})
	if err != nil {
		return writeExpectResult(false, fmt.Sprintf("starting %q: %v", act.Cmd, err))
	}
	defer pty.Close()

	out := newPTYOut()
	stopRead := make(chan struct{})
	readerDone := make(chan struct{})
	go func() {
		pumpPTY(pty, out, stopRead)
		close(readerDone)
	}()
	ptyDone := make(chan error, 1)
	go func() { ptyDone <- pty.Wait() }()

	stepTimeout := 30 * time.Second
	for _, prompt := range act.Prompts {
		if err := out.await(prompt, stepTimeout, readerDone); err != nil {
			return writeExpectResult(false, fmt.Sprintf("%s: %v", act.Cmd, err))
		}
		if frag := out.hasAny(act.FailMarkers); frag != "" {
			return writeExpectResult(false, fmt.Sprintf("%s: failed (output shows %q)", act.Cmd, frag))
		}
		if _, err := pty.Write([]byte(secret + "\n")); err != nil {
			return writeExpectResult(false, fmt.Sprintf("%s: writing response: %v", act.Cmd, err))
		}
	}

	// Wait for the program to exit and the reader to drain, then decide
	// success. waitErr carries the real exit status (pty.Wait) -- for
	// NoSuccessMarker actions success == exit code 0 with no fail marker
	// (smbpasswd prints nothing on success).
	var waitErr error
	select {
	case waitErr = <-ptyDone:
		// Reaped first: the reader usually sees EOF at the same time; give
		// it a short bounded moment to flush the last PTY output.
		select {
		case <-readerDone:
		case <-time.After(500 * time.Millisecond):
		}
	case <-readerDone:
		// Reader saw EOF first (program closed its tty): wait for the real
		// reap so the true exit status is known, bounded.
		select {
		case waitErr = <-ptyDone:
		case <-time.After(2 * time.Second):
			waitErr = fmt.Errorf("exit status unavailable")
		}
	case <-time.After(60 * time.Second):
		return writeExpectResult(false, fmt.Sprintf("%s: timed out waiting for exit", act.Cmd))
	}

	if frag := out.hasAny(act.FailMarkers); frag != "" {
		return writeExpectResult(false, fmt.Sprintf("%s: failed (output shows %q)", act.Cmd, frag))
	}
	if act.NoSuccessMarker {
		if waitErr != nil {
			return writeExpectResult(false, fmt.Sprintf("%s: exited with error: %v", act.Cmd, waitErr))
		}
		return writeExpectResult(true, strings.TrimSpace(out.tail(200)))
	}
	if !out.has(act.SuccessMarker) {
		return writeExpectResult(false, fmt.Sprintf("%s: no success marker; output: %s", act.Cmd, out.tail(200)))
	}
	return writeExpectResult(true, strings.TrimSpace(out.tail(200)))
}

// readExpectSecret loads the secret from secret_file (0600 root, written by
// server.pl) and removes the file afterwards. No stdin fallback: the config
// scanner may have buffered ahead, so only an explicit file is reliable.
func readExpectSecret(cfg *startConfig) (string, error) {
	if cfg.SecretFile == "" {
		return "", fmt.Errorf("expect action %s requires secret_file", cfg.Action)
	}
	b, err := os.ReadFile(cfg.SecretFile)
	if err != nil {
		return "", fmt.Errorf("reading secret_file: %v", err)
	}
	_ = os.Remove(cfg.SecretFile) // best-effort; 0600 root file, gone asap
	s := strings.TrimRight(string(b), "\r\n")
	if s == "" {
		return "", fmt.Errorf("secret_file is empty")
	}
	return s, nil
}

// ptyOut accumulates the raw PTY output for prompt matching.
type ptyOut struct {
	mu  sync.Mutex
	buf []byte
}

func newPTYOut() *ptyOut { return &ptyOut{} }

func (o *ptyOut) append(p []byte) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.buf = append(o.buf, p...)
	if len(o.buf) > 256*1024 { // bound memory; keep the tail (markers are short)
		o.buf = append([]byte(nil), o.buf[len(o.buf)-64*1024:]...)
	}
}

func (o *ptyOut) raw() string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return string(o.buf)
}

// norm lowercases and collapses whitespace so prompt matching is robust
// against \r vs \n / trailing-space differences (LC_ALL=C keeps the text).
func norm(s string) string {
	s = strings.ToLower(s)
	return strings.Join(strings.Fields(s), " ")
}

func (o *ptyOut) has(needle string) bool {
	n := norm(needle)
	return n != "" && strings.Contains(norm(o.raw()), n)
}

func (o *ptyOut) hasAny(needles []string) string {
	for _, n := range needles {
		if o.has(n) {
			return n
		}
	}
	return ""
}

func (o *ptyOut) tail(n int) string {
	s := o.raw()
	if len(s) > n {
		s = s[len(s)-n:]
	}
	return strings.TrimSpace(s)
}

// await polls the accumulated output until needle appears, the reader ends
// (program exited), or the timeout fires. Fail-closed.
func (o *ptyOut) await(needle string, timeout time.Duration, done <-chan struct{}) error {
	deadline := time.After(timeout)
	for {
		if o.has(needle) {
			return nil
		}
		select {
		case <-done:
			if o.has(needle) {
				return nil
			}
			return fmt.Errorf("program exited before prompt %q appeared; output: %s", needle, o.tail(160))
		case <-deadline:
			return fmt.Errorf("timed out waiting for prompt %q; output: %s", needle, o.tail(160))
		default:
		}
		time.Sleep(25 * time.Millisecond)
	}
}

// pumpPTY reads PTY output into the buffer until EOF/error or stop.
func pumpPTY(p ptySession, out *ptyOut, stop <-chan struct{}) {
	buf := make([]byte, 32*1024)
	for {
		select {
		case <-stop:
			return
		default:
		}
		n, err := p.Read(buf)
		if n > 0 {
			out.append(buf[:n])
		}
		if err != nil {
			return
		}
	}
}

// isPrivilegedTarget reports whether the expect target is a privileged
// (uid 0 / root / Administrator) account. RESTRICTION: such accounts may
// only be changed from the interactive console, never via a direct expect
// action. On Unix the account is resolved against /etc/passwd (uid 0);
// on Windows "Administrator" (case-insensitive) is rejected.
func isPrivilegedTarget(user string) bool {
	u := strings.ToLower(strings.TrimSpace(user))
	if u == "" {
		return false
	}
	if runtime.GOOS == "windows" {
		return u == "administrator"
	}
	if u == "root" {
		return true
	}
	f, err := os.Open("/etc/passwd")
	if err != nil {
		return false // cannot resolve -> do not hard-block on read failure
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		p := strings.Split(sc.Text(), ":")
		if len(p) > 2 && p[2] == "0" && strings.EqualFold(p[0], user) {
			return true
		}
	}
	return false
}
