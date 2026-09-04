# cs-console -- Phase 1 prototype

Ephemeral, per-request interactive PTY relay for napp-it cs. Implements the
design in `csweb-gui/data/howto.ai/cs-console.info` (design points A-D).

**Status: standalone prototype, NOT yet wired into csweb-gui.** No
`server.pl`/`aihelplib.pl` code has been touched. This is Phase 1 of the
plan agreed with Gea: get the Go binary itself right and smoke-tested
before touching production Perl code (which needs a local-sync gate first
per project convention).

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

## Next steps (see cs-console.info OPEN QUESTIONS / NEXT STEPS)

1. Test the illumos backend on a real OmniOS member.
2. Test the Windows backend on a real Windows member.
3. Phase 2: the `server.pl` command verb that spawns this binary and
   relays session token/key to the frontend -- needs a local-sync
   checkpoint first per project convention before touching server.pl.
4. Phase 3: the central Go daemon's WebSocket endpoint + xterm.js on the
   browser side, and the `aihelplib.pl` SHELL_OPEN/SHELL_INPUT/SHELL_CLOSE
   integration for the AI Helpdesk.
