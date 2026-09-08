package main

// Standalone regression/verification test for cs-console review Finding
// 3.2 (Mittel, "concurrent-session lockout race") -- added by Claude
// cs_26.09.08. Not part of the release binary in spirit; kept as a
// permanent `go test` check since it costs nothing to keep and directly
// exercises the shared state lockout.go's functions manage.
//
// Rather than driving the full network protocol (which needs a real
// sealed connection -- see testclient/), this drives the SAME sequence
// of lockoutCheck/lockoutRecordFailure calls runPasswordGate makes, in
// two shapes, from N concurrent goroutines against ONE shared state
// file -- standing in for N concurrent cs-console processes spawned for
// the same frontend IP (exactly main.go's design: no standing daemon,
// each session is its own process with its own independent loop).
//
//   oldShapeLoop:  lockoutCheck() ONCE before the loop (auth.go's shape
//                  before this fix) -- once a session enters its retry
//                  loop it never looks at shared state again.
//   newShapeLoop:  lockoutCheck() before EVERY attempt (auth.go's shape
//                  after this fix, see runPasswordGate).
//
// The metric that matters: how many auth attempts happen AFTER the
// shared state has already tripped lockoutMaxAttempts and locked. Those
// are exactly the "extra" guesses Finding 3.2 is about -- a locked-out
// attacker's parallel sessions still getting to try the OS password.
// oldShapeLoop should let a meaningful number through (each already-
// running sibling finishes its own budget blind); newShapeLoop should
// let through close to zero (every sibling notices on its very next
// iteration, which is at most one attempt after the trip, per session,
// by construction).

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// simulateSessions runs `sessions` concurrent goroutines, each attempting
// up to `perSession` OS-auth calls (always failing) against the shared
// lockout state in dir/ip, using either the old or the new check shape.
// Returns how many attempts were made TOTAL and how many of those
// happened while the shared state was ALREADY locked at the moment the
// attempt's own pre-check ran (0 for newShape by construction, since it
// checks immediately before every attempt).
func simulateSessions(t *testing.T, dir, ip string, sessions, perSession int, checkEveryAttempt bool) (total, afterLock int64) {
	var wg sync.WaitGroup
	start := make(chan struct{})
	for s := 0; s < sessions; s++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			checked := false
			for attempt := 0; attempt < perSession; attempt++ {
				if checkEveryAttempt || !checked {
					checked = true
					if locked, _ := lockoutCheck(dir, ip); locked {
						return // matches runPasswordGate: locked -> disconnect immediately
					}
				}
				atomic.AddInt64(&total, 1)
				if locked, _ := lockoutCheck(dir, ip); locked {
					atomic.AddInt64(&afterLock, 1) // this attempt happened despite state being locked
				}
				time.Sleep(200 * time.Microsecond) // let goroutines interleave realistically
				lockoutRecordFailure(dir, ip)
			}
		}()
	}
	close(start)
	wg.Wait()
	return
}

func TestConcurrentSessionsShareOneLockoutBudget(t *testing.T) {
	const sessions = 5
	const perSession = 3 // each session's own retry budget, matches lockoutMaxAttempts
	const trials = 25    // aggregate over many trials -- any SINGLE trial is timing-
	// dependent (real file I/O jitter), same as the already-accepted residual race
	// documented in lockout.go's header; the fix's effect is a statistical one
	// (per-attempt recheck catches the lock sooner on average), not a hard per-run
	// guarantee, so that's what this asserts on.

	var oldTotalAfterLock, newTotalAfterLock int64
	for i := 0; i < trials; i++ {
		oldDir := t.TempDir()
		_, oldAfterLock := simulateSessions(t, oldDir, "203.0.113.7", sessions, perSession, false)
		oldTotalAfterLock += oldAfterLock

		newDir := t.TempDir()
		_, newAfterLock := simulateSessions(t, newDir, "203.0.113.8", sessions, perSession, true)
		newTotalAfterLock += newAfterLock
	}

	t.Logf("across %d trials of %d concurrent simulated sessions each:", trials, sessions)
	t.Logf("  OLD shape (check once before loop):    %d attempts total made while ALREADY locked", oldTotalAfterLock)
	t.Logf("  NEW shape (check before every attempt): %d attempts total made while ALREADY locked", newTotalAfterLock)

	if newTotalAfterLock >= oldTotalAfterLock {
		t.Fatalf("expected the fix (recheck before every attempt) to let substantially FEWER post-lockout attempts through than the pre-fix shape (check once before the loop) over %d trials; got old=%d new=%d",
			trials, oldTotalAfterLock, newTotalAfterLock)
	}
	t.Logf("OK: per-attempt recheck (the fix) cut post-lockout attempts from %d to %d over %d trials of %d concurrent simulated sessions",
		oldTotalAfterLock, newTotalAfterLock, trials, sessions)
}
