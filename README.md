# cs-console

> **This is a first release candidate for evaluations.**

Ephemeral, per-request interactive PTY relay for napp-it cs. Implements the
design in `csweb-gui/data/howto.ai/cs-console.info` (design points A-D plus
SECURITY -- PASSWORD GATE).

## Status (2026.09.06)

v0.5.5 released on GitHub with prebuilt binaries for 8 targets
(windows/linux/darwin/freebsd/illumos/solaris amd64; linux+darwin also
arm64). The interactive console (open -> OS password gate -> shell) is
live-verified end-to-end on Windows, Linux (Proxmox), illumos (OmniOS) and
macOS. FreeBSD binary is built and deployed (version probe verified), but
its console path is not yet exercised. Solaris is built natively (gcc 14 +
Go 1.26 on the member); version probe and PTY spawn verified on real Solaris
-- the full console (PAM gate) is not yet exercised. Transport is POLL
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
| FreeBSD | amd64 | creack/pty | binary deployed, console untested |
| illumos | amd64 | hand-rolled STREAMS (cgo) | live-verified |
| Solaris | amd64 | creack/pty | native build, PTY spawn verified |

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
