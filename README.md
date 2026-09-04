# cs-console

Ephemeral, per-request interactive PTY relay for napp-it cs. Implements the
design in `csweb-gui/data/howto.ai/cs-console.info` (design points A-D plus
SECURITY -- PASSWORD GATE).

**Status (2026.09.04): Phase 2 (server.pl `get_tty` spawn integration) is
built and live-tested on Windows and illumos. The password gate (PAM/
LogonUser + lockout, see below) is built and build-verified but NOT yet
live-tested on real hardware.** Phase 3 (browser xterm.js + AI Helpdesk
SHELL_OPEN wiring) has not been started.

## What's here

- `main.go` -- entry point: reads a JSON start-config line from stdin,
  starts the target program under a PTY, listens for one direct
  connection, authenticates it by IP + one-time session token, relays PTY
  bytes over it with ChaCha20-Poly1305 encryption until the program exits
  or a timeout fires, then exits itself.
- `pty.go` -- the `ptySession` interface all three backends implement.
- `pty_unix.go` -- Linux/macOS/*BSD backend via `github.com/creack/pty`.
  **Built and smoke-tested** (see below).
- `pty_windows.go` -- Windows backend via `github.com/UserExistsError/conpty`
  (real ConPTY). **Cross-compiles cleanly, not yet run on real Windows.**
- `pty_illumos.go` -- illumos backend, hand-rolled STREAMS pty via cgo (no
  `forkpty()` in illumos libc, see file header for the full rationale and
  the reference implementations it follows). **Built and PTY-round-trip
  verified on real OmniOS (2026.09.04, see below) -- the two compiler
  bugs the first real build attempt found (`syscall.GetErrno` never
  existed; `syscall.SYS_IOCTL` is genuinely undefined for illumos in
  Go's stdlib) are fixed; `Resize()` now uses
  `golang.org/x/sys/unix.IoctlSetWinsize`.**
- `session.go` -- the local stdin/stdout protocol with the parent process
  (server.pl, in the real deployment) and session token/key generation.
- `crypto.go` -- the ChaCha20-Poly1305 frame sealing/opening used for both
  the auth handshake and the relayed PTY data.
- `testclient/` -- throwaway test harness used for the smoke test below,
  not part of the shipped design.
- `lockout.go` -- brute-force lockout for the password gate below: 3
  failed attempts locks a frontend IP out for 15s, state kept in a
  per-IP file (SHA-256'd IP in the filename) under the tmp dir server.pl
  passes in (falls back to `os.TempDir()` if not given). No cross-process
  file locking (deliberate tradeoff, secondary brake not the primary
  control). **Written 2026.09.04, NOT yet tested under real concurrent
  load** -- a standalone arithmetic re-implementation of the state
  machine was verified separately (3 fails -> 15s lock, counter resets),
  but the real file-based version has not been exercised on a real
  member.
- `auth.go` -- platform-independent password-gate orchestration
  (`authConversation` interface, `runPasswordGate()`): connect first,
  then password, like PuTTY/SSH -- the lockout above is checked, then
  `verifyOSAccount()` runs (up to 3 attempts), then and only then does
  `main.go` start the requested PTY.
- `auth_unix.go` (build tag `!windows`, covers linux/darwin/*bsd AND
  illumos -- PAM's API doesn't differ there the way the PTY backend
  does) -- PAM-based OS password verification via a cgo conversation
  callback, generic over every PAM message style (not hardcoded to one
  password prompt), so an OS whose PAM stack demands 2FA gets it relayed
  transparently. **Written 2026.09.04 from the PAM conversation-callback
  pattern, NOT yet built or run on any real machine** -- same caveat
  `pty_illumos.go` carried before its own hardware pass: plausible,
  unverified, needs a live build+test pass (the file's own header lists
  the specific things most likely to be wrong: PAM's response-array
  ownership contract, the "login" PAM service-name guess, the
  uintptr/unsafe.Pointer handle idiom against `go vet`).
- `auth_windows.go` (build tag `windows`) -- Windows OS password
  verification via `LogonUser` (`LOGON32_LOGON_NETWORK`), verification
  only (token closed immediately, no impersonation). Single
  username+password exchange only -- no Windows 2FA support by design
  (deferred until actually needed; there is no generic multi-factor
  conversational API to hook into the way PAM has). **Written
  2026.09.04, NOT yet run on any real Windows machine** (cross-compiles
  cleanly).

## Build

```
go build -o cs-console .                          # current platform
GOOS=windows GOARCH=amd64 go build -o cs-console.exe .
GOOS=darwin  GOARCH=amd64 go build -o cs-console-darwin.amd64 .
GOOS=darwin  GOARCH=arm64 go build -o cs-console-darwin.arm64 .
# illumos: must be built ON an illumos/OmniOS host with gcc installed --
# cross-compiling from elsewhere needs an illumos sysroot this repo
# doesn't assume you have.
CGO_ENABLED=1 go build -o cs-console-illumos.amd64 .
```

All four non-illumos targets (linux, windows, darwin/amd64, darwin/arm64)
build cleanly with `go vet` silent. This matches the platform list already
established for cs-imageindex (see cs-imageindex.info) minus illumos,
which needs its own native build+test pass.

## Smoke test performed (Linux, standing in for the creack/pty POSIX path
shared with macOS/*BSD)

```
echo '{"cmd":"/bin/sh","args":["-c","cat"],"frontend_ip":"127.0.0.1","idle_secs":5,"max_secs":20}' \
  | ./cs-console
# -> prints one JSON line: {"port":N,"session_token":"...","session_key":"..."}
```

A test client (`testclient/`) connected, did the sealed-frame auth
handshake with the reported token+key, then sent `echo round-trip-ok\n`.
Result:

```
PTY said: "echo round-trip-ok\r\n"   <- PTY's own terminal echo
PTY said: "echo round-trip-ok\r\n"   <- cat's actual output
```

The `\r\n` and the doubled output (echo + program output) confirm this is
a real PTY with real terminal line-discipline behavior, not a plain pipe.
The process exited cleanly on its own ~5s after the last activity
(idle_secs=5), confirming the idle-timeout teardown path works. No server-
side errors were logged during the run.

## illumos smoke test (real OmniOS, 2026.09.04)

Same protocol, run natively on OmniOS (omnio46, r151058, Go 1.26.7):

```
echo '{"cmd":"/bin/sh","args":["-c","cat"],"frontend_ip":"127.0.0.1","idle_secs":8,"max_secs":30}' \
  | ./cs-console
```

`testclient` connected and did the same round trip. Result:

```
PTY said: "echo round-trip-ok\r\necho round-trip-ok\r\n"
```

The doubled `\r\n` output is the same real-PTY signature as the Linux
test above, confirming the hand-rolled STREAMS sequence (open/grantpt/
unlockpt/fork/setsid/reopen/I_PUSH ptem+ldterm+ttcompat/dup2/exec) works
correctly on real illumos hardware. This was the last unverified Phase 1
platform.

Windows ConPTY was separately confirmed to spawn correctly on real
Windows (2026.09.04, via napp-it cs's own `server.pl` integration -- see
that project's `cs-console.info`), though its PTY relay handshake itself
(as opposed to just the spawn) is not yet exercised the way illumos's is
here.

Not yet tested: the max-session timeout path, multiple sequential
sessions, and anything touching the actual `server.pl` spawn/token-relay
integration over its real (encrypted, remote-member) socket path --
both Windows and illumos have so far only been exercised locally/
directly, not through that full path (Phase 2 integration itself is
done and working, see napp-it cs's own docs).

## Password gate (security hardening pass, 2026.09.04)

Per `cs-console.info` SECURITY -- PASSWORD GATE: cs-console now requires an
OS-delegated root/Administrator password confirm (PAM on Unix/illumos,
LogonUser on Windows) after the frontend connects and authenticates by
token/IP, but *before* the requested command's PTY is started. Up to 3
attempts; a failed attempt locks the frontend's IP out for 15s
(`lockout.go`); the password (or any OTP/other PAM-requested credential)
never reaches the AI model, the chat transcript, or any log. 2FA is
delivered transparently wherever the OS's own PAM stack demands it;
Windows 2FA is explicitly out of scope for now (see `auth_windows.go`).

**None of this has been live-tested on real hardware yet** -- it is
build-verified only (native Linux build against real PAM headers, `go
vet` clean, Windows cross-compile clean, gofmt clean, and a standalone
arithmetic check of the lockout state machine). Treat it exactly like
`pty_illumos.go` before its own OmniOS pass: plausible, not yet proven.

## Next steps (see cs-console.info OPEN QUESTIONS / NEXT STEPS)

1. Test the illumos backend on a real OmniOS member.
2. Test the Windows backend on a real Windows member.
3. Live-test the password gate: `auth_unix.go` on real illumos/macOS/
   *BSD hardware, `auth_windows.go` on real Windows, and `lockout.go`
   under real concurrent-session load.
4. Phase 2: the `server.pl` command verb that spawns this binary and
   relays session token/key to the frontend -- needs a local-sync
   checkpoint first per project convention before touching server.pl.
   (Status: DONE and live-tested on Windows/illumos for the spawn path
   itself -- see napp-it cs's own `cs-console.info` -- the relay
   handshake through the real remote-member socket path is still open.)
5. Phase 3: the central Go daemon's WebSocket endpoint + xterm.js on the
   browser side, and the `aihelplib.pl` SHELL_OPEN/SHELL_INPUT/SHELL_CLOSE
   integration for the AI Helpdesk -- including wiring the new
   `ai_console_allowed()` operator-role exclusion into that handler once
   it exists.
