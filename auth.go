package main

// OS-delegated password gate -- see cs-console.info SECURITY -- PASSWORD
// GATE (decided cs_26.09.04, refined with Gea the same day). Connect
// first, then password, like PuTTY/SSH: cs-console runs the requested
// command only after the operator authenticates against the OS itself
// (PAM on Unix/illumos, LogonUser on Windows) -- delegated so OS auth
// changes (hash scheme, lockout policy, and per Gea's later refinement,
// 2FA IF the OS's own PAM stack demands it) need no cs-console change.
//
// STATUS: LIVE-TESTED cs_26.09.04 on all 6 reachable cluster members
// (Windows, illumos x2, Linux, FreeBSD, macOS) -- see auth_unix.go /
// auth_windows.go / lockout.go headers and cs-console.info STATUS for
// the full per-member writeup. Windows 2FA (there is no generic
// LogonUser equivalent of PAM's conversational multi-prompt model) is
// explicitly deferred until it's actually needed, per Gea's decision --
// Windows verifyOSAccount only ever does a single username+password
// exchange for now.

import (
	"encoding/json"
	"fmt"
	"os"
	"runtime"
)

// authConversation is how a platform's verifyOSAccount implementation
// talks to the connected frontend during OS authentication. Both
// implementations (auth_unix.go's PAM conv callback, auth_windows.go's
// single LogonUser call) drive this same interface, so main.go's gate
// orchestration below never needs to know which platform it's on.
type authConversation interface {
	// Prompt sends msg to the frontend and blocks for its response.
	// echo=true means the frontend should show what's typed (rare -- PAM
	// PAM_PROMPT_ECHO_ON); echo=false means mask it (the normal password/
	// OTP case, PAM_PROMPT_ECHO_OFF). Never called for pure display
	// messages -- see Info.
	Prompt(msg string, echo bool) (response string, err error)
	// Info sends a display-only message with no response expected (PAM
	// PAM_TEXT_INFO / PAM_ERROR_MSG, or a gate-level status like "wrong
	// password, N attempts left"). Windows' single-shot LogonUser call
	// never needs this; PAM's conversation can emit either at any point.
	Info(msg string) error
}

// gateMessage is the tiny JSON wire sub-protocol layered on top of the
// existing sealed-frame transport (crypto.go) for the password-gate
// phase, before the connection switches over to raw PTY byte relay.
// Every frame during the gate phase is one gateMessage from cs-console;
// the frontend's reply frame (for Type=="prompt") is just the raw
// response bytes, no JSON wrapper -- kept asymmetric on purpose, same
// spirit as the rest of this project's "don't add structure nothing
// reads" bias (see cs-console.info design notes).
type gateMessage struct {
	Type string `json:"type"` // "prompt" | "info" | "locked" | "ok" | "denied"
	Echo bool   `json:"echo"` // meaningful only for Type=="prompt"
	Text string `json:"text"`
}

// sealedConversation implements authConversation over the connection's
// sealed reader/writer -- the thing both PAM's conv callback and the
// Windows LogonUser path actually call into.
type sealedConversation struct {
	w *sealedWriter
	r *sealedReader
}

func (c *sealedConversation) Prompt(msg string, echo bool) (string, error) {
	if err := c.sendJSON(gateMessage{Type: "prompt", Echo: echo, Text: msg}); err != nil {
		return "", err
	}
	frame, err := c.r.ReadFrame()
	if err != nil {
		return "", fmt.Errorf("reading gate response: %w", err)
	}
	return string(frame), nil
}

func (c *sealedConversation) Info(msg string) error {
	return c.sendJSON(gateMessage{Type: "info", Text: msg})
}

func (c *sealedConversation) sendJSON(m gateMessage) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	return c.w.WriteFrame(b)
}

// encodeGateMessage is used where no error return is convenient (a
// best-effort final notification right before returning an error up the
// call stack) -- gateMessage's fields are all trivially JSON-safe
// (booleans and short strings we composed ourselves), so this cannot
// realistically fail; ignoring a hypothetical error here only risks the
// frontend seeing a closed connection with no explanation instead of one
// with one, never a hang or a security downgrade.
func encodeGateMessage(m gateMessage) []byte {
	b, _ := json.Marshal(m)
	return b
}

// runPasswordGate is the flow from cs-console.info's SECURITY -- PASSWORD
// GATE section, verbatim:
//
//	listen -> accept -> token/IP auth   (done by caller, see main.go)
//	        -> "Enter root password:"   (repeated per gateAccount below)
//	        -> read pw -> verifyOSAccount   [OS-native, see auth_unix.go /
//	           auth_windows.go -- may itself be a multi-prompt PAM
//	           conversation, not just one password]
//	        -> wrong: re-prompt (max 3 attempts, then disconnect + audit)
//	        -> correct: startPTY(cmd) -> relay
//
// The 3-attempt/lockout counter (lockout.go) counts one COMPLETE
// verifyOSAccount call as one attempt, regardless of how many individual
// prompts it involved internally -- a wrong OTP after a correct password
// is one failed attempt, not two (see cs-console.info).
func runPasswordGate(w *sealedWriter, r *sealedReader, tmpDir, frontendIP string) error {
	// Gea, cs_26.09.04 ("vor dem login prompt hostname und os anzeigen zur
	// kontrolle welcher member gerade connected wird"): announce which
	// machine this session is actually talking to BEFORE anything else --
	// including before the lockout check below -- so the operator can spot
	// a wrong-member mistake at a glance instead of typing a password
	// blind and finding out afterward. hostname() failing is not fatal to
	// the gate itself, just falls back to "unknown".
	host, err := os.Hostname()
	if err != nil || host == "" {
		host = "unknown"
	}
	banner := fmt.Sprintf("cs-console: %s (%s/%s)", host, runtime.GOOS, runtime.GOARCH)
	if werr := w.WriteFrame(encodeGateMessage(gateMessage{Type: "info", Text: banner})); werr != nil {
		return fmt.Errorf("sending host banner: %w", werr)
	}

	// FIX cs_26.09.08 (Claude, cs-console review Finding 3.2 -- Mittel,
	// "concurrent-session lockout race"): lockoutCheck used to run ONCE
	// here, before the retry loop below, never again inside it. Because
	// cs-console is spawned fresh per request (no standing daemon -- see
	// design point B) with its own independent 3-attempt loop, two or more
	// parallel sessions from the same frontend IP could each pass this one
	// upfront check before any of them had recorded a single failure, then
	// each burn through their own full 3-attempt budget -- N concurrent
	// sessions effectively multiplying the real guess budget by N instead
	// of sharing one 3-attempt/15s limit. Fix: re-check the shared on-disk
	// lockout state before EVERY attempt, not just once, so a failure
	// recorded by a sibling session (lockoutRecordFailure below, same
	// state file, see lockout.go) is picked up immediately by this session
	// too, mid-loop -- not only on its next fresh spawn.
	conv := &sealedConversation{w: w, r: r}
	for attempt := 1; attempt <= lockoutMaxAttempts; attempt++ {
		if locked, retryAfter := lockoutCheck(tmpDir, frontendIP); locked {
			_ = w.WriteFrame(encodeGateMessage(gateMessage{Type: "locked",
				Text: fmt.Sprintf("too many attempts, try again in %ds", int(retryAfter.Seconds()))}))
			return fmt.Errorf("frontend %s is locked out for %s", frontendIP, retryAfter)
		}

		err := verifyOSAccount(conv)
		if err == nil {
			lockoutReset(tmpDir, frontendIP)
			return w.WriteFrame(encodeGateMessage(gateMessage{Type: "ok"}))
		}

		lockoutRecordFailure(tmpDir, frontendIP)
		remaining := lockoutMaxAttempts - attempt
		// FIX cs_26.09.08 (review Finding 1.2 -- Niedrig, "PAM-Service-Fehler
		// wird nicht durchgereicht"): verifyOSAccount's err was previously
		// discarded here except for its nil-ness -- an admin on a member
		// whose default PAM chain itself is broken (not a wrong password,
		// e.g. pam_start/pam_authenticate failing for a config reason) saw
		// only the generic "authentication failed" text with no clue the
		// problem is systemic, not a mistyped password. err's message
		// (auth_unix.go: "pam_start/pam_authenticate/pam_acct_mgmt: <PAM's
		// own pam_strerror() text>"; auth_windows.go: the LogonUser Win32
		// error text) is always a fixed, non-secret module/error
		// description -- never the submitted password or PAM conversation
		// content -- so it's safe to surface as-is via the same Info
		// channel already used for the attempt-countdown message.
		detail := "authentication failed"
		if err != nil {
			detail = err.Error()
		}
		if remaining <= 0 {
			_ = w.WriteFrame(encodeGateMessage(gateMessage{Type: "denied",
				Text: fmt.Sprintf("authentication failed, disconnecting (%s)", detail)}))
			return fmt.Errorf("password gate: %d failed attempts from %s, disconnecting", attempt, frontendIP)
		}
		_ = conv.Info(fmt.Sprintf("authentication failed (%d attempt(s) left) -- %s", remaining, detail))
	}
	return fmt.Errorf("password gate: unreachable") // loop always returns above
}
