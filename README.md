# cs-console

> **This is a first release candidate.**

Ephemeral, per-request interactive PTY relay for napp-it 4ai (client-server). Implements the
design in `csweb-gui/data/howto.ai/cs-console.info` (design points A-D plus
SECURITY -- PASSWORD GATE).
csweb-gui deploys and updates this manually per member menu About > Download cs-tools

## Status (2026.09.08)

v0.5.7: fixes a concurrent-session lockout race (parallel sessions from the
same frontend IP no longer each get their own independent 3-attempt
budget, see `lockout.go`) plus three low-priority findings from the
2026.09.08 review -- NO_COLOR is no longer hardcoded on (the console's
current dark xterm.js theme renders ANSI color fine; opt back into plain
text via `startConfig.no_color` or `CS_CONSOLE_FORCE_NO_COLOR=1`), the
password gate now relays the actual PAM/LogonUser error text (module/error
names only, never secrets) instead of just "authentication failed", and
`acceptOne`'s rare wrong-peer-connected case now returns an identifiable
sentinel error for a future caller-side friendly-message translation.
`lockout_concurrency_test.go` regression-tests the lockout fix (-race
clean, 25-trial aggregate).

v0.5.5 released on GitHub with prebuilt binaries for 8 targets
(windows/linux/darwin/freebsd/illumos/solaris amd64; linux+darwin also
arm64). The interactive console (open -> OS password gate -> shell) is
live-verified end-to-end on all six amd64 platforms: Windows, Linux
(Proxmox), illumos (OmniOS), macOS, FreeBSD and Solaris. Transport is POLL
(not SSE) through the Perl web-server with a dedicated rate-limit-free auth
for the `/console/*` endpoints. Expect mode (`passwd_user` / `smbpasswd_user`
/ `ksmbd_user`) is committed and live-verified; root/Administrator (uid 0)
is always refused.

## Supported platforms

| Platform | Arch | PTY backend | Status |
| --- | --- | --- | --- |
| Linux | amd64, arm64 | creack/pty | live-verified |
| Windows | amd64 | ConPTY | live-verified |
| macOS | amd64, arm64 | creack/pty | live-verified |
| FreeBSD | amd64 | creack/pty | live-verified |
| illumos | amd64 | hand-rolled STREAMS (cgo) | live-verified |
| Solaris | amd64 | creack/pty | live-verified |

## Password gate

OS-delegated root/Administrator password confirm before the PTY starts:
PAM on Linux/macOS/FreeBSD/illumos/Solaris, `LogonUser` on Windows. Up to 3
attempts, per-IP lockout (15s) via `lockout.go`. The password (or any
PAM-requested OTP) never reaches the AI model, the chat transcript, or logs.

## What's here

- `main.go` -- start-config from stdin, PTY spawn, one direct connection,
  IP + token auth, ChaCha20-Poly1305 relay, then exit.
- `pty.go` / `pty_unix.go` / `pty_windows.go` / `pty_illumos.go` -- PTY
  backends (creack/pty, ConPTY, hand-rolled STREAMS).
- `session.go` / `crypto.go` -- parent protocol + sealed relay.
- `auth.go` / `auth_unix.go` / `auth_windows.go` -- password gate (PAM /
  LogonUser).
- `lockout.go` -- per-IP brute-force lockout.
- `expect.go` -- allowlisted expect-mode actions.
