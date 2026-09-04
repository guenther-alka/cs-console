package main

// Password-gate brute-force lockout -- see cs-console.info SECURITY --
// PASSWORD GATE, "BRUTE-FORCE BOUNDED" (decided cs_26.09.04, discussed and
// refined with Gea the same day): after 3 failed OS-auth attempts from a
// given frontend IP, that IP is locked out for 15s, enforced entirely
// inside cs-console itself -- no server.pl-side state needed. Because
// cs-console is spawned fresh per request (no standing daemon, see
// design point B), the counter cannot live in process memory: it has to
// survive across separate cs-console processes, so it's a small state
// file in server.pl's own tmp dir ($tpath = /opt/csweb-gui/tmp, passed to
// us as startConfig.TmpDir -- see session.go) rather than the OS's shared,
// world-writable temp dir.
//
// STATUS: LIVE-TESTED cs_26.09.04 on all 6 reachable cluster members
// (Windows/my-w11, illumos/.189+.203, Linux/.112, FreeBSD/.191,
// macOS/.196) -- 3 fails -> instant LOCKED on the next attempt -> correct
// expiry and fresh cycle after 15s, verified end to end on every
// platform (see cs-console.info STATUS for the full per-member writeup).
// Still NOT exercised under real CONCURRENT-session load (two sessions
// racing on the same IP at once) -- the note below about a rare missed
// increment being an accepted tradeoff, not a proven-safe one, still
// stands.
//
// Deliberately NOT using a cross-process file lock (flock/LockFileEx):
// this is a secondary brake, not the primary control -- the primary
// control is the OS's own account lockout policy (PAM/LogonUser), which
// this note in cs-console.info explicitly calls "an additional backstop,
// not relied on" for exactly the reverse reason philosophers might expect:
// here WE are the backstop, the OS is what's actually relied on. A rare
// missed increment from two truly concurric sessions racing on the same
// IP just means one extra guess slips through occasionally, not that the
// gate is bypassed.

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	lockoutMaxAttempts = 3
	lockoutDuration    = 15 * time.Second
	lockoutStaleAfter  = time.Hour // opportunistic cleanup threshold
)

// lockoutFilePath returns the per-IP state file path inside dir, named
// consistently with server.pl's existing "cs-console_<jobid>.{in,out,err}"
// convention (see server.pl _get_tty) so an admin who already knows that
// naming recognizes these files too. The IP itself is hashed rather than
// used verbatim in the filename: IPv6 addresses contain ':', which is not
// a legal filename character on Windows, and hashing sidesteps that
// entirely rather than special-casing IPv4 vs IPv6.
func lockoutFilePath(dir, ip string) string {
	if dir == "" {
		dir = os.TempDir() // fallback if server.pl didn't send tmp_dir (older caller)
	}
	sum := sha256.Sum256([]byte(ip))
	return filepath.Join(dir, "cs-console_lockout_"+hex.EncodeToString(sum[:8])+".state")
}

// lockoutState is deliberately just two numbers -- see file header for why
// a real lock isn't used here: keeping the read-modify-write window as
// short as possible (two int fields, one line each) is the cheap mitigation
// in place of a real lock.
type lockoutState struct {
	FailCount   int
	LockedUntil int64 // unix seconds; 0 = not locked
}

func readLockoutState(path string) lockoutState {
	data, err := os.ReadFile(path)
	if err != nil {
		return lockoutState{} // no file yet == never failed
	}
	var st lockoutState
	for _, line := range strings.Split(string(data), "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		n, _ := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
		switch strings.TrimSpace(k) {
		case "fail_count":
			st.FailCount = int(n)
		case "locked_until":
			st.LockedUntil = n
		}
	}
	return st
}

func writeLockoutState(path string, st lockoutState) error {
	content := fmt.Sprintf("fail_count=%d\nlocked_until=%d\n", st.FailCount, st.LockedUntil)
	return os.WriteFile(path, []byte(content), 0o600)
}

// lockoutCheck reports whether ip is currently locked out, and if so for
// how much longer. Call this BEFORE attempting OS auth at all -- a locked
// caller should never even reach PAM/LogonUser, both to avoid wasting an
// attempt against the OS's own counter and to avoid a timing side-channel
// between "locked out" and "wrong password" responses.
func lockoutCheck(tmpDir, ip string) (locked bool, retryAfter time.Duration) {
	path := lockoutFilePath(tmpDir, ip)
	st := readLockoutState(path)
	now := time.Now().Unix()
	if st.LockedUntil > now {
		return true, time.Duration(st.LockedUntil-now) * time.Second
	}
	// Opportunistic cleanup of long-stale files -- no cron needed (see
	// header comment); safe to ignore errors, this is best-effort tidying.
	if st.LockedUntil > 0 && now-st.LockedUntil > int64(lockoutStaleAfter.Seconds()) {
		_ = os.Remove(path)
	}
	return false, 0
}

// lockoutRecordFailure increments ip's failure counter and, once it
// reaches lockoutMaxAttempts, sets locked_until lockoutDuration from now
// and resets the counter. This is called once per COMPLETE OS-auth
// attempt (i.e. once per full PAM conversation / LogonUser call and its
// final result), never per individual prompt within a multi-factor
// exchange -- see cs-console.info: a wrong OTP after a correct password
// is one failed attempt, not two.
func lockoutRecordFailure(tmpDir, ip string) {
	path := lockoutFilePath(tmpDir, ip)
	st := readLockoutState(path)
	st.FailCount++
	if st.FailCount >= lockoutMaxAttempts {
		st.LockedUntil = time.Now().Add(lockoutDuration).Unix()
		st.FailCount = 0
	}
	_ = writeLockoutState(path, st) // best-effort; a write failure here must
	// never block disconnecting the caller -- see verifyAndGate in auth.go
}

// lockoutReset clears ip's state entirely after a successful OS auth.
func lockoutReset(tmpDir, ip string) {
	_ = os.Remove(lockoutFilePath(tmpDir, ip))
}
