//go:build windows

package main

// Windows OS password verification via LogonUser -- see cs-console.info
// SECURITY -- PASSWORD GATE. Single username+password exchange only: no
// multi-prompt conversation like PAM's, and per Gea's explicit decision
// (cs_26.09.04, "2fa für windows erst angehen wenn es notwendig werden
// sollte") no attempt is made here to support Windows MFA/2FA -- there is
// no generic LogonUser equivalent of PAM's conversational model to hook
// into for that; if it's ever needed it will require a materially
// different approach (e.g. the Credential Provider UI surface), not an
// extension of this file.
//
// STATUS: LIVE-TESTED cs_26.09.04 on real Windows (my-w11): wrong
// password correctly rejected with the expected LogonUser error, correct
// attempt countdown, DENIED after 3, lockout enforced and correctly
// expiring (see cs-console.info STATUS for the full writeup and
// lockout.go for the lockout side). NOT yet exercised: a real successful
// LogonUser call (deliberately left for Gea to verify by hand, never
// through an AI-driven session -- see testclient's own header comment).

import (
	"fmt"
	"syscall"
	"unsafe"
)

const gateAccount = "Administrator"

const (
	logon32LogonNetwork    = 3
	logon32ProviderDefault = 0
)

var (
	advapi32       = syscall.NewLazyDLL("advapi32.dll")
	procLogonUserW = advapi32.NewProc("LogonUserW")
)

// verifyOSAccount asks conv for the Administrator password once (no
// multi-step conversation on this platform) and verifies it via
// LOGON32_LOGON_NETWORK -- verification only, no interactive session is
// created. The returned token handle is closed immediately: cs-console
// never impersonates the account, it only confirms the password is
// correct (see cs-console.info: "the returned token is closed
// immediately (verification only, no impersonation)").
func verifyOSAccount(conv authConversation) error {
	password, err := conv.Prompt(fmt.Sprintf("%s password:", gateAccount), false)
	if err != nil {
		return fmt.Errorf("reading password: %w", err)
	}

	userPtr, err := syscall.UTF16PtrFromString(gateAccount)
	if err != nil {
		return err
	}
	domainPtr, err := syscall.UTF16PtrFromString(".") // local account, not domain
	if err != nil {
		return err
	}
	passPtr, err := syscall.UTF16PtrFromString(password)
	if err != nil {
		return err
	}

	var token syscall.Handle
	ret, _, callErr := procLogonUserW.Call(
		uintptr(unsafe.Pointer(userPtr)),
		uintptr(unsafe.Pointer(domainPtr)),
		uintptr(unsafe.Pointer(passPtr)),
		uintptr(logon32LogonNetwork),
		uintptr(logon32ProviderDefault),
		uintptr(unsafe.Pointer(&token)),
	)
	if ret == 0 {
		return fmt.Errorf("LogonUser failed for %s: %w", gateAccount, callErr)
	}
	defer syscall.CloseHandle(token) // verification only -- never impersonate

	return nil
}
