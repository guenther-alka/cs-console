package main

// OS-delegated password gate -- see cs-console.info SECURITY -- PASSWORD
// GATE (decided cs_26.09.04, refined with Gea the same day). Connect
// first, then password, like PuTTY/SSH: cs-console runs the requested
// command only after the operator authenticates against the OS itself
// (PAM on Unix/illumos, LogonUser on Windows) -- delegated so OS auth
// changes (hash scheme, lockout policy, and per Gea's later refinement,
// 2FA IF the OS's own PAM stack demands it) need no cs-console change.
//
// STATUS: written from the design discussion, NOT yet live-tested on a
// real member the way pty_illumos.go was -- see auth_unix.go / lockout.go
// headers. Windows 2FA (there is no generic LogonUser equivalent of PAM's
// conversational multi-prompt model) is explicitly deferred until it's
// actually needed, per Gea's decision -- Windows verifyOSAccount only
// ever does a single username+password exchange for now.

import (
	"encoding/json"
	"fmt"
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
	if locked, retryAfter := lockoutCheck(tmpDir, frontendIP); locked {
		_ = w.WriteFrame(encodeGateMessage(gateMessage{Type: "locked",
			Text: fmt.Sprintf("too many attempts, try again in %ds", int(retryAfter.Seconds()))}))
		return fmt.Errorf("frontend %s is locked out for %s", frontendIP, retryAfter)
	}

	conv := &sealedConversation{w: w, r: r}
	for attempt := 1; attempt <= lockoutMaxAttempts; attempt++ {
		err := verifyOSAccount(conv)
		if err == nil {
			lockoutReset(tmpDir, frontendIP)
			return w.WriteFrame(encodeGateMessage(gateMessage{Type: "ok"}))
		}

		lockoutRecordFailure(tmpDir, frontendIP)
		remaining := lockoutMaxAttempts - attempt
		if remaining <= 0 {
			_ = w.WriteFrame(encodeGateMessage(gateMessage{Type: "denied",
				Text: "authentication failed, disconnecting"}))
			return fmt.Errorf("password gate: %d failed attempts from %s, disconnecting", attempt, frontendIP)
		}
		_ = conv.Info(fmt.Sprintf("authentication failed (%d attempt(s) left)", remaining))
	}
	return fmt.Errorf("password gate: unreachable") // loop always returns above
}
