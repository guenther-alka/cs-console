package main

// Session bootstrap: the local control protocol with server.pl (the parent
// process that spawned us) and the network-facing session token used to
// authenticate the frontend's direct connection.
//
// See cs-console.info design points B/C/D:
//   - server.pl spawns cs-console per request (no standing daemon), so the
//     local hop needs no shared secret of its own: only server.pl can write
//     to our stdin in the first place (that's what process spawn + piped
//     stdin already guarantees), so config just arrives as one JSON line.
//   - cs-console mints the SESSION TOKEN + SESSION KEY for the *network*
//     hop (frontend <-> cs-console) and reports them back over stdout,
//     which server.pl relays to the frontend over the existing
//     authenticated &socket() channel.
//   - the session token is IP-pinned to the frontend's source IP as seen
//     by server.pl at request time.

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
)

// startConfig is the one JSON line server.pl writes to our stdin at spawn.
type startConfig struct {
	Cmd        string   `json:"cmd"`         // target program, e.g. "passwd"
	Args       []string `json:"args"`        // arguments, if any
	FrontendIP string   `json:"frontend_ip"` // IP the session token is pinned to
	IdleSecs   int      `json:"idle_secs"`   // 0 -> default (see main.go)
	MaxSecs    int      `json:"max_secs"`    // 0 -> default (see main.go)
	TmpDir     string   `json:"tmp_dir"`     // server.pl's $tpath (/opt/csweb-gui/tmp) -- used
	// for the password-gate lockout state file (see
	// lockout.go); optional, falls back to os.TempDir()
	// if server.pl doesn't send it (older callers).
}

// readStartConfig reads and validates the one config line from stdin.
func readStartConfig() (*startConfig, error) {
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 0, 64*1024), 64*1024)
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return nil, fmt.Errorf("reading start config from stdin: %w", err)
		}
		return nil, fmt.Errorf("reading start config from stdin: no input")
	}
	var cfg startConfig
	if err := json.Unmarshal(scanner.Bytes(), &cfg); err != nil {
		return nil, fmt.Errorf("parsing start config: %w", err)
	}
	if cfg.Cmd == "" {
		return nil, fmt.Errorf("start config missing required 'cmd'")
	}
	if cfg.FrontendIP == "" {
		return nil, fmt.Errorf("start config missing required 'frontend_ip'")
	}
	return &cfg, nil
}

// startResult is the one JSON line we write to stdout once listening, so
// server.pl can relay it to the frontend. Never logged, never written to
// disk by us -- see cs-console.info design point C.
type startResult struct {
	Port         int    `json:"port"`
	SessionToken string `json:"session_token"` // hex
	SessionKey   string `json:"session_key"`   // hex
}

func writeStartResult(port int, token, key []byte) error {
	res := startResult{
		Port:         port,
		SessionToken: hex.EncodeToString(token),
		SessionKey:   hex.EncodeToString(key),
	}
	enc := json.NewEncoder(os.Stdout)
	return enc.Encode(&res) // one JSON line, newline-terminated
}

const sessionTokenLen = 32 // bytes, before hex-encoding

func newSessionToken() ([]byte, error) {
	tok := make([]byte, sessionTokenLen)
	if _, err := rand.Read(tok); err != nil {
		return nil, fmt.Errorf("generating session token: %w", err)
	}
	return tok, nil
}
