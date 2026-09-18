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
	"os/exec"
	"regexp"
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
	Prompts         []string // ordered prompt tokens to await (each followed by secret + line ending)
	SuccessMarker   string   // required success output fragment ("" = exit-code based)
	FailMarkers     []string // any of these anywhere -> abort as failure
	NoSuccessMarker bool     // program prints no success text (e.g. smbpasswd):
	// success = process exit code 0 AND no fail marker (cs_26.09.05)

	// Resolve, when set, computes cmd/args/prompts per invocation instead
	// of using the static Cmd/Args/Prompts above -- needed when the
	// command family differs by platform (Solaris legacy keysource/`zfs
	// key` vs OpenZFS keyformat+keylocation/`load-key`) and/or a prompt
	// has the dataset name embedded in it (cs_26.09.18, zfs create/unlock
	// prompt actions). When set, Args placeholder substitution and the
	// {user}/isPrivilegedTarget check above are skipped -- Resolve is
	// responsible for its own argument validation.
	Resolve func(cfgArgs []string) (cmd string, args []string, prompts []string, err error)

	// PostResolve, when set, runs one additional NON-interactive command
	// after the interactive PTY step succeeds (e.g. `zfs mount <dataset>`
	// after `load-key`, which does not cascade-mount -- se.info sec.2,
	// CAPTURED+VERIFIED live on Windows cs_26.09.18: mounted=no after
	// load-key until an explicit `zfs mount`). Returning cmd=="" skips it
	// (e.g. Solaris `zfs key -l` mounts on its own, VERIFIED live
	// cs_26.09.18).
	PostResolve func(cfgArgs []string) (cmd string, args []string, err error)

	// VerifyResolve, when set, is the AUTHORITATIVE success check run
	// after the interactive step (and PostResolve, if any): se.info's
	// documented rule for every key operation in this project is "never
	// trust the command's own exit code/output alone -- always re-read
	// the property fresh". Returns the argv for a read-only `zfs get`
	// and the expected trimmed value; a mismatch or run error is failure
	// regardless of what the PTY output looked like.
	VerifyResolve func(cfgArgs []string) (cmd string, args []string, want string, err error)
}

// lineEnding is the byte sequence written after a secret to submit it to
// the child's line-input layer. Existing expectTable actions (passwd_user
// etc.) were only ever CAPTURED+VERIFIED against Unix ttys, where canonical
// line discipline treats "\n" alone as Enter -- so this keeps sending plain
// "\n" there (no behavior change). ConPTY on Windows is a real VT100-style
// terminal input stream where Enter is CR ("\r"); a bare "\n" was CONFIRMED
// live (cs_26.09.18, zfs create probe on my-w11) to never register as a
// submitted line -- the child just hangs forever waiting on the prompt.
// "\r\n" was CAPTURED+VERIFIED to work correctly there.
func lineEnding() string {
	if runtime.GOOS == "windows" {
		return "\r\n"
	}
	return "\n"
}

// validDatasetName / validEncryptionAlg: expect args go straight into argv
// (never a shell), so this isn't injection defense -- it's a sanity gate so
// a typo'd dataset/algorithm fails fast with a clear error instead of
// silently producing a confusing zfs error deep inside the PTY dialog, and
// so a dataset string starting with "-" can never be misread as a flag.
var validDatasetName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:/-]*$`)

var validEncryptionAlg = map[string]bool{
	"on":          true,
	"aes-128-ccm": true, "aes-192-ccm": true, "aes-256-ccm": true,
	"aes-128-gcm": true, "aes-192-gcm": true, "aes-256-gcm": true,
}

// resolveZFSCreate implements the "zfs_create_enc_prompt" action: create an
// encrypted dataset with a user-typed passphrase (keylocation=prompt),
// never persisted to any file -- see se.info MODE A. This is the
// prompt-based counterpart to napp-it's existing file-based create path
// (05_Create/action.pl, keysource=passphrase,file://...), which stays
// unchanged and remains the only path for keysplit (L1/L2/W1/W2), since
// keysplit needs real key bytes on disk, not a prompt (cs_26.09.18 design
// discussion).
//
// Three, not two, prompt variants -- CAPTURED+VERIFIED live cs_26.09.18 on
// all three, do not collapse back to a solaris/else split:
//   - Solaris (legacy keysource property): own command family entirely.
//   - Windows (OpenZFS On Windows): customizes the upstream prompt text --
//     VERIFIED on my-w11: "Enter new passphrase:" / "Re-enter new
//     passphrase:".
//   - illumos/Linux/FreeBSD/macOS (genuine upstream OpenZFS zfs binary):
//     plain upstream text -- VERIFIED on illumos (OmniOS 192.168.2.189):
//     "Enter passphrase:" / "Re-enter passphrase:", no "new", no dataset
//     name. Initially assumed (wrongly) to share Windows's text since both
//     use keyformat/keylocation -- live-tested this specifically because
//     of that assumption, and it was wrong: the two ports diverged on
//     this string. Not independently re-verified on Linux/FreeBSD/macOS,
//     but those share one upstream zfs_prompt.c with illumos, unlike
//     Windows's separate port, so the same text is expected there.
func resolveZFSCreate(a []string) (string, []string, []string, error) {
	if len(a) < 2 || a[0] == "" || a[1] == "" {
		return "", nil, nil, fmt.Errorf("zfs_create_enc_prompt requires dataset and encryption arguments")
	}
	dataset, enc := a[0], a[1]
	if !validDatasetName.MatchString(dataset) {
		return "", nil, nil, fmt.Errorf("invalid dataset name %q", dataset)
	}
	if !validEncryptionAlg[enc] {
		return "", nil, nil, fmt.Errorf("unsupported encryption algorithm %q", enc)
	}
	switch runtime.GOOS {
	case "solaris":
		// Legacy combined property; this Solaris 11.4.90.212.0 build has
		// no keyformat/keylocation/load-key at all (CONFIRMED live,
		// cs_26.09.18: "invalid property" / "unrecognized command").
		return "zfs", []string{"create", "-o", "encryption=" + enc, "-o", "keysource=passphrase,prompt", dataset},
			[]string{fmt.Sprintf("Enter passphrase for '%s': ", dataset), "Enter again: "}, nil
	case "windows":
		return "zfs", []string{"create", "-o", "encryption=" + enc, "-o", "keyformat=passphrase", "-o", "keylocation=prompt", dataset},
			[]string{"Enter new passphrase:", "Re-enter new passphrase:"}, nil
	default:
		return "zfs", []string{"create", "-o", "encryption=" + enc, "-o", "keyformat=passphrase", "-o", "keylocation=prompt", dataset},
			[]string{"Enter passphrase:", "Re-enter passphrase:"}, nil
	}
}

func resolveZFSCreateVerify(a []string) (string, []string, string, error) {
	return "zfs", []string{"get", "-H", "-o", "value", "keystatus", a[0]}, "available", nil
}

// resolveZFSUnlock implements the "zfs_unlock_enc_prompt" action: unlock an
// already-created keylocation=prompt dataset by typing the passphrase
// interactively. This is the ONLY way to unlock such a dataset on Solaris
// 11 or Windows -- both were CONFIRMED live (cs_26.09.18) to reject
// non-interactive/piped stdin outright (Solaris: immediate "key not found";
// Windows: hangs forever on a real console, piped stdin fully ignored,
// compounded by zfs.exe self-elevating into a fresh disconnected console
// under UAC when the caller lacks a real admin token -- irrelevant here
// since cs-console's own caller already runs elevated). File-based/keysplit
// members keep using server.pl's existing non-interactive `load-key -L
// file://...` override path (sub unlock) -- unaffected by this action.
func resolveZFSUnlock(a []string) (string, []string, []string, error) {
	if len(a) < 1 || a[0] == "" {
		return "", nil, nil, fmt.Errorf("zfs_unlock_enc_prompt requires a dataset argument")
	}
	dataset := a[0]
	if !validDatasetName.MatchString(dataset) {
		return "", nil, nil, fmt.Errorf("invalid dataset name %q", dataset)
	}
	if runtime.GOOS == "solaris" {
		return "zfs", []string{"key", "-l", dataset},
			[]string{fmt.Sprintf("Enter passphrase for '%s': ", dataset)}, nil
	}
	return "zfs", []string{"load-key", dataset},
		[]string{fmt.Sprintf("Enter passphrase for '%s':", dataset)}, nil
}

// resolveZFSUnlockPost: OpenZFS `load-key` does not cascade-mount (se.info
// sec.2; CONFIRMED live cs_26.09.18 on Windows: mounted=no right after
// load-key, mounted=yes only after an explicit `zfs mount`). Solaris's
// legacy `zfs key -l` mounts as part of the one command (CONFIRMED live
// cs_26.09.18 on 192.168.2.50: mounted=yes immediately, `mount` shows the
// filesystem) -- no post-step there.
func resolveZFSUnlockPost(a []string) (string, []string, error) {
	if runtime.GOOS == "solaris" {
		return "", nil, nil
	}
	return "zfs", []string{"mount", a[0]}, nil
}

func resolveZFSUnlockVerify(a []string) (string, []string, string, error) {
	return "zfs", []string{"get", "-H", "-o", "value", "keystatus", a[0]}, "available", nil
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
	{
		// zfs_create_enc_prompt: create an encrypted dataset with a
		// user-typed passphrase (keylocation=prompt), never persisted to
		// any file -- see se.info MODE A. cfg.Args = [dataset, encryption].
		// NoSuccessMarker: neither platform prints anything past the two
		// prompts on success (CAPTURED+VERIFIED live cs_26.09.18); the
		// authoritative check is VerifyResolve (keystatus==available), not
		// this text/exit-code gate -- kept as a first-pass sanity net only.
		ID:              "zfs_create_enc_prompt",
		Resolve:         resolveZFSCreate,
		VerifyResolve:   resolveZFSCreateVerify,
		NoSuccessMarker: true,
	},
	{
		// zfs_unlock_enc_prompt: unlock a keylocation=prompt dataset by
		// typing the passphrase interactively -- the only way to unlock
		// one on Solaris 11 / Windows (see resolveZFSUnlock doc comment).
		// cfg.Args = [dataset]. NoSuccessMarker for the same reason as
		// create; PostResolve mounts on non-Solaris (load-key doesn't
		// cascade-mount); VerifyResolve is authoritative.
		ID:              "zfs_unlock_enc_prompt",
		Resolve:         resolveZFSUnlock,
		PostResolve:     resolveZFSUnlockPost,
		VerifyResolve:   resolveZFSUnlockVerify,
		NoSuccessMarker: true,
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

	var cmd string
	var args []string
	var prompts []string

	if act.Resolve != nil {
		// Dynamic actions (dataset name embedded in argv/prompts,
		// platform-specific command family) own their own validation.
		var rerr error
		cmd, args, prompts, rerr = act.Resolve(cfg.Args)
		if rerr != nil {
			return writeExpectResult(false, rerr.Error())
		}
	} else {
		cmd = act.Cmd
		args = make([]string, 0, len(act.Args))
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
		// RESTRICTION (Gea, cs_26.09.05): never change the root/Administrator
		// password through a direct expect action -- that requires the
		// interactive console (shell-mode login). Reject any uid-0 target.
		if len(args) > 0 && isPrivilegedTarget(args[0]) {
			return writeExpectResult(false, "changing the root/administrator password is not allowed via expect -- it requires the interactive console (shell-mode login)")
		}
		prompts = act.Prompts
	}

	secret, err := readExpectSecret(cfg)
	if err != nil {
		return writeExpectResult(false, err.Error())
	}
	_ = os.Setenv("LC_ALL", "C") // deterministic prompts; inherited by the child

	pty, err := startPTY(&startConfig{Cmd: cmd, Args: args})
	if err != nil {
		return writeExpectResult(false, fmt.Sprintf("starting %q: %v", cmd, err))
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
	for _, prompt := range prompts {
		if err := out.await(prompt, stepTimeout, readerDone); err != nil {
			return writeExpectResult(false, fmt.Sprintf("%s: %v", cmd, err))
		}
		if frag := out.hasAny(act.FailMarkers); frag != "" {
			return writeExpectResult(false, fmt.Sprintf("%s: failed (output shows %q)", cmd, frag))
		}
		if _, err := pty.Write([]byte(secret + lineEnding())); err != nil {
			return writeExpectResult(false, fmt.Sprintf("%s: writing response: %v", cmd, err))
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
		return writeExpectResult(false, fmt.Sprintf("%s: timed out waiting for exit", cmd))
	}

	if frag := out.hasAny(act.FailMarkers); frag != "" {
		return writeExpectResult(false, fmt.Sprintf("%s: failed (output shows %q)", cmd, frag))
	}
	if act.NoSuccessMarker && waitErr != nil {
		return writeExpectResult(false, fmt.Sprintf("%s: exited with error: %v", cmd, waitErr))
	}
	if !act.NoSuccessMarker && !out.has(act.SuccessMarker) {
		return writeExpectResult(false, fmt.Sprintf("%s: no success marker; output: %s", cmd, out.tail(200)))
	}

	// Optional non-interactive follow-up (e.g. `zfs mount` after
	// `load-key`, which does not cascade-mount -- se.info sec.2).
	if act.PostResolve != nil {
		pcmd, pargs, perr := act.PostResolve(cfg.Args)
		if perr != nil {
			return writeExpectResult(false, perr.Error())
		}
		if pcmd != "" {
			pout, runErr := exec.Command(pcmd, pargs...).CombinedOutput()
			if runErr != nil {
				return writeExpectResult(false, fmt.Sprintf("%s %s: %v (%s)", pcmd, strings.Join(pargs, " "), runErr, strings.TrimSpace(string(pout))))
			}
		}
	}

	// AUTHORITATIVE success check (se.info: never trust exit code/output
	// alone for key operations -- always re-read the property fresh).
	if act.VerifyResolve != nil {
		vcmd, vargs, want, verr := act.VerifyResolve(cfg.Args)
		if verr != nil {
			return writeExpectResult(false, verr.Error())
		}
		vout, runErr := exec.Command(vcmd, vargs...).Output()
		got := strings.TrimSpace(string(vout))
		if runErr != nil {
			return writeExpectResult(false, fmt.Sprintf("verifying result (%s %s): %v", vcmd, strings.Join(vargs, " "), runErr))
		}
		if got != want {
			return writeExpectResult(false, fmt.Sprintf("%s: verification failed, expected keystatus %q, got %q", cmd, want, got))
		}
		return writeExpectResult(true, fmt.Sprintf("confirmed (keystatus=%s)", got))
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

// ansiEscape matches VT/ANSI escape sequences (CSI "\x1b[...<letter>", OSC
// "\x1b]...BEL", and bare "\x1b<letter>") so norm() can strip them before
// matching. DISCOVERED live cs_26.09.18 building the zfs create/unlock
// actions on Windows: ConPTY's session-start preamble (cursor
// hide/clear/home) races with the child's first prompt write and lands its
// OSC window-title-set sequence IN THE MIDDLE of the prompt text itself --
// e.g. the raw bytes for "Enter new passphrase:" arrived as literal "E",
// then a full "\x1b]0;...zfs.exe\a" OSC title sequence, then literal "nter
// new passphrase:". The two halves are visually adjacent when Go prints the
// string quoted (%q) but are NOT a contiguous substring in the actual byte
// stream, so plain Contains() matching silently times out forever even
// though the prompt is genuinely there. Stripping escape sequences first
// fixes this for any prompt on any platform (harmless no-op on ttys that
// never emit these).
var ansiEscape = regexp.MustCompile(`\x1b(\[[0-9;?]*[A-Za-z]|\][^\a\x1b]*(\a|\x1b\\)|[A-Za-z])`)

// norm strips ANSI/VT escape sequences, lowercases, and collapses
// whitespace so prompt matching is robust against \r vs \n / trailing-space
// differences (LC_ALL=C keeps the text itself deterministic) and against
// escape sequences landing inside the prompt text (see ansiEscape doc).
func norm(s string) string {
	s = ansiEscape.ReplaceAllString(s, "")
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
