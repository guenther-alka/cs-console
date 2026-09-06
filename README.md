# cs-console

> **This is a first release candidate for evaluations.**

Ephemeral, per-request interactive PTY relay for napp-it cs. Implements the
design in `csweb-gui/data/howto.ai/cs-console.info` (design points A-D plus
SECURITY -- PASSWORD GATE).

## Status (2026.09.06)

v0.5.4 released on GitHub with prebuilt binaries. The interactive console
(open -> OS password gate -> shell) is live-verified end-to-end on Windows,
Linux (Proxmox), illumos (OmniOS), macOS and FreeBSD. Transport is POLL (not
SSE) through the Perl web-server with a dedicated rate-limit-free auth for
the `/console/*` endpoints. Expect mode (`passwd_user` / `smbpasswd_user` /
`ksmbd_user`) is committed and live-verified; root/Administrator (uid 0) is
always refused.

## Supported platforms

| Platform | Arch | PTY backend |
| --- | --- | --- |
| Linux | amd64, arm64 | creack/pty |
| Windows | amd64 | ConPTY |
| macOS | amd64, arm64 | creack/pty |
| FreeBSD | amd64 | creack/pty |
| illumos | amd64 | hand-rolled STREAMS (cgo) |
| Solaris | amd64 | creack/pty (build tag present) |

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
