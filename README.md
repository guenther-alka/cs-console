# cs-console

Signed-off-by: Guenther Alka gea@napp-it.org<br>
Concept Co-Authored-By: Claude Fable 5 noreply@anthropic.com<br>

Part of the [napp-it 4ai (client-server edition)](https://napp-it.org) cluster tooling family
(alongside [cs-tools](https://www.napp-it.org/cs-tools_en.html))
csweb-gui deploys and updates this manually per member menu About > Download cs-tools

Ephemeral, per-request interactive PTY relay for napp-it 4ai (client-server). Implements the
design in `csweb-gui/data/howto.ai/cs-console.info` (design points A-D plus
SECURITY -- PASSWORD GATE).
csweb-gui deploys and updates this manually per member menu About > Download cs-tools

## Status (2026.09.18)

v0.5.8: two new expect-mode actions, `zfs_create_enc_prompt` /
`zfs_unlock_enc_prompt` -- create/unlock a `keylocation=prompt` encrypted
dataset by typing the passphrase interactively. Needed because Solaris 11
and Windows (OpenZFS On Windows) both confirmed-reject non-interactive
stdin for prompt-mode ZFS key entry (Solaris fails immediately; Windows
hangs on a real console, piped stdin fully ignored) -- this is the ONLY
way to drive that flow on those two platforms. Existing file-based create
(napp-it's own `05_Create/action.pl`) and keysplit are unaffected and
unchanged; those still need real key bytes on disk, which a prompt can't
provide. All four prompt strings (Solaris create/unlock, Windows
create/unlock) CAPTURED + VERIFIED live before shipping, matching this
project's usual discipline. Two related robustness fixes landed with it,
both applying to every expect action, not just these two: a Windows
ConPTY line-ending bug (bare `"\n"` never submitted a line there; fixed
via a GOOS-aware `lineEnding()`, `"\r\n"` on Windows) and an ANSI-escape-
in-the-middle-of-a-prompt bug found on ConPTY (norm() now strips escape
sequences before matching). A third real bug: illumos's create prompt
text ("Enter passphrase:" / "Re-enter passphrase:") was wrongly assumed
to match Windows's ("Enter new passphrase:" / "Re-enter new
passphrase:") since both are keyformat/keylocation OpenZFS variants --
live-tested that assumption on illumos (OmniOS) and it was wrong, fixed
by splitting create's prompt resolver into solaris/windows/default
instead of solaris/else. All three platforms (Solaris, Windows, illumos)
live-verified end-to-end through the real production expect path after
the fix. See `cs-console.info` EXPECT MODE section, STATUS UPDATE
cs_26.09.18, for the full writeup. Remaining wiring: the web-GUI menu
action + server.pl/aihelplib allowlist mirroring (not yet built).

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
