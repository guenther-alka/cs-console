//go:build !windows

package main

// PAM-based OS password verification for everything except Windows --
// linux, darwin, *bsd, AND illumos (illumos has real PAM, same API shape
// as Linux; this file is NOT restricted to pty_unix.go's platform list
// because pty_illumos.go only carves illumos out for the PTY backend,
// where illumos genuinely needs different code -- PAM itself does not
// differ that way). See cs-console.info SECURITY -- PASSWORD GATE.
//
// STATUS: LIVE-TESTED cs_26.09.04 -- built natively and exercised end to
// end (wrong-password rejection, correct attempt countdown, real PAM
// "Password:" prompt) on FOUR real, genuinely different PAM
// implementations: illumos/OmniOS (.189 r151058 AND .203 r151056, the
// very first real PAM test this code ever had), Linux/Proxmox (.112,
// Linux-PAM, after installing libpam0g-dev), FreeBSD (.191, OpenPAM),
// and macOS (.196, Apple's PAM, built with CGO_CFLAGS pointed at the
// Xcode SDK since headers aren't under plain /usr/include there anymore).
// See cs-console.info STATUS for the full per-member writeup. The
// specific trouble spots below were all live-fire tested as a side
// effect -- none of them turned out to be a real bug, but they remain
// documented here for the next person reading this file cold:
//   - PAM's response-array ownership/freeing contract: some PAM
//     implementations free() the array *resp we return from the
//     conversation callback themselves after consuming it, others expect
//     the caller-supplied conv function's allocations to be freed by
//     whoever called pam_authenticate -- this file assumes the former
//     (never frees respArray itself after returning it), which is the
//     documented Linux-PAM contract; illumos, FreeBSD/OpenPAM and macOS
//     all worked correctly under this same assumption in live testing.
//   - the "login" PAM service name (see verifyOSAccount) is a guess at a
//     service that exists everywhere by default; confirmed working
//     (real "Password:" prompt, correct accept/reject) on all four PAM
//     platforms tested live.
//   - the uintptr<->unsafe.Pointer handle trick below is a standard cgo
//     idiom (the value is never dereferenced as a real pointer on the Go
//     side, only used as an opaque map key); `go vet` flags it as an
//     expected/accepted finding (see the inline comment lower in this
//     file) on every platform built so far.
// NOT yet exercised: a real 2FA-demanding PAM stack (every member tested
// so far only asks for a single password), and concurrent sessions
// racing against the same account/IP at once.

/*
#cgo LDFLAGS: -lpam
#include <security/pam_appl.h>
#include <stdlib.h>

extern int cs_console_pam_conv(int num_msg, struct pam_message **msg,
                                struct pam_response **resp, void *appdata_ptr);

static void cs_console_set_conv(struct pam_conv *conv, void *handle) {
    // Cast needed: PAM's own struct pam_conv.conv field type declares its
    // msg parameter as "const struct pam_message **", but cgo's exported
    // Go function (see cs_console_pam_conv below) generates a non-const
    // "struct pam_message **" -- Go has no const qualifier to match with.
    // The cast is safe: cs_console_pam_conv only reads through msg, never
    // writes through it.
    conv->conv = (int (*)(int, const struct pam_message **, struct pam_response **, void *))cs_console_pam_conv;
    conv->appdata_ptr = handle;
}
*/
import "C"

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"unsafe"
)

// gateAccount is the OS account cs-console authenticates against before
// starting the requested command -- see cs-console.info: "an OS-delegated
// root/Administrator password confirm is required first".
const gateAccount = "root"

// pamServiceName returns the PAM service cs-console uses for the gate.
// Default is "login" (a broadly available PAM service). A member operator
// who wants a dedicated policy -- e.g. OmniOS/Solaris, where the stock
// pam.conf "login" chain can fail root auth over a conversation
// (pam_dhkeys/pam_dial_auth; verified live cs_26.09.05: login auth=3 while
// a minimal chain returns auth=0) -- creates /etc/cs-console-pam-service
// containing a service name and adds the matching block to /etc/pam.conf
// (or /etc/pam.d/<name> on Linux/FreeBSD). Content is a single token.
func pamServiceName() string {
	b, err := os.ReadFile("/etc/cs-console-pam-service")
	if err == nil {
		if s := strings.TrimSpace(string(b)); s != "" {
			return s
		}
	}
	return "login"
}

// convRegistry maps opaque integer handles to the authConversation for
// the PAM exchange currently in flight. cgo forbids passing a Go pointer
// into C in a way C might hand back to Go code that dereferences it
// outside rules cgo can verify, so an integer handle is passed as the
// conv's void* appdata_ptr instead, and looked up here -- this map is
// the actual Go-side state, the C value is just a key into it.
var (
	convMu       sync.Mutex
	convRegistry = map[uintptr]authConversation{}
	convNextID   uintptr
)

func registerConv(c authConversation) uintptr {
	convMu.Lock()
	defer convMu.Unlock()
	convNextID++
	id := convNextID
	convRegistry[id] = c
	return id
}

func unregisterConv(id uintptr) {
	convMu.Lock()
	defer convMu.Unlock()
	delete(convRegistry, id)
}

// cs_console_pam_conv is PAM's conversation callback, implemented in Go
// and exported for the C preamble above to reference. It relays every
// PAM message to the connected frontend via authConversation -- an
// arbitrary sequence of PAM_PROMPT_ECHO_OFF (password/OTP, masked),
// PAM_PROMPT_ECHO_ON (visible input), PAM_TEXT_INFO/PAM_ERROR_MSG
// (display-only) -- rather than assuming exactly one password prompt.
// This is what makes 2FA-capable PAM stacks work transparently (Gea,
// cs_26.09.04: "2fa mit planen, wenn das OS es anfordert muss es
// geliefert werden") without cs-console needing to know 2FA exists.
//
//export cs_console_pam_conv
func cs_console_pam_conv(numMsg C.int, msg **C.struct_pam_message, resp **C.struct_pam_response, appdataPtr unsafe.Pointer) C.int {
	convMu.Lock()
	conv, ok := convRegistry[uintptr(appdataPtr)]
	convMu.Unlock()
	if !ok {
		return C.PAM_CONV_ERR
	}

	n := int(numMsg)
	if n <= 0 {
		return C.PAM_CONV_ERR
	}
	msgs := unsafe.Slice(msg, n)

	respArray := C.calloc(C.size_t(n), C.size_t(unsafe.Sizeof(C.struct_pam_response{})))
	if respArray == nil {
		return C.PAM_BUF_ERR
	}
	responses := unsafe.Slice((*C.struct_pam_response)(respArray), n)

	for i := 0; i < n; i++ {
		m := msgs[i]
		text := C.GoString(m.msg)
		switch m.msg_style {
		case C.PAM_PROMPT_ECHO_OFF, C.PAM_PROMPT_ECHO_ON:
			answer, err := conv.Prompt(text, m.msg_style == C.PAM_PROMPT_ECHO_ON)
			if err != nil {
				C.free(respArray)
				return C.PAM_CONV_ERR
			}
			responses[i].resp = C.CString(answer)
		case C.PAM_TEXT_INFO, C.PAM_ERROR_MSG:
			_ = conv.Info(text)
		default:
			// Unknown message style -- fail closed rather than guess what
			// PAM wants here.
			C.free(respArray)
			return C.PAM_CONV_ERR
		}
	}

	*resp = (*C.struct_pam_response)(respArray)
	return C.PAM_SUCCESS
}

// verifyOSAccount runs the full PAM conversation for gateAccount ("root"),
// relaying every prompt through conv. Fails closed: only
// pam_authenticate AND pam_acct_mgmt BOTH returning PAM_SUCCESS counts as
// success -- any other outcome, including a conv error partway through,
// is a failure.
func verifyOSAccount(conv authConversation) error {
	id := registerConv(conv)
	defer unregisterConv(id)

	cUser := C.CString(gateAccount)
	defer C.free(unsafe.Pointer(cUser))
	// "login" is used as the default PAM service (present in /etc/pam.d/login
	// or /etc/pam.conf on effectively every PAM-based system) so no new PAM
	// config file needs to ship with cs-console -- unless a deployment wants
	// a dedicated policy (e.g. its own 2FA requirement just for console
	// access, or an OmniOS/Solaris member whose stock "login" chain rejects
	// root over a conversation). A "cs-console" service file/block can be
	// added and the service name selected per member via
	// /etc/cs-console-pam-service (see pamServiceName above).
	cService := C.CString(pamServiceName())
	defer C.free(unsafe.Pointer(cService))

	var pamConv C.struct_pam_conv
	// go vet flags this line ("possible misuse of unsafe.Pointer") --
	// expected and safe: id is an opaque integer handle (a map key, see
	// convRegistry above), never a real Go pointer, and PAM only ever
	// hands it back to cs_console_pam_conv as a void* that gets converted
	// straight back to a uintptr for the same map lookup. This is cgo's
	// own documented idiom for passing non-pointer data through a C
	// void* parameter; it is not the "store a Go pointer where the GC
	// can't see it" misuse the vet check exists to catch.
	C.cs_console_set_conv(&pamConv, unsafe.Pointer(id)) //nolint:govet,unsafeptr

	var handle *C.pam_handle_t
	ret := C.pam_start(cService, cUser, &pamConv, &handle)
	if ret != C.PAM_SUCCESS {
		return fmt.Errorf("pam_start: %s", C.GoString(C.pam_strerror(handle, ret)))
	}
	defer C.pam_end(handle, ret)

	if ret = C.pam_authenticate(handle, 0); ret != C.PAM_SUCCESS {
		return fmt.Errorf("pam_authenticate: %s", C.GoString(C.pam_strerror(handle, ret)))
	}
	if ret = C.pam_acct_mgmt(handle, 0); ret != C.PAM_SUCCESS {
		return fmt.Errorf("pam_acct_mgmt: %s", C.GoString(C.pam_strerror(handle, ret)))
	}
	return nil
}
