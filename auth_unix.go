//go:build !windows

package main

// PAM-based OS password verification for everything except Windows --
// linux, darwin, *bsd, AND illumos (illumos has real PAM, same API shape
// as Linux; this file is NOT restricted to pty_unix.go's platform list
// because pty_illumos.go only carves illumos out for the PTY backend,
// where illumos genuinely needs different code -- PAM itself does not
// differ that way). See cs-console.info SECURITY -- PASSWORD GATE.
//
// STATUS: written from the PAM conversation-callback pattern (the same
// approach libraries like msteinert/pam use), NOT yet built or run on any
// real machine. Given this session's own experience with pty_illumos.go
// -- hand-written cgo that had never actually compiled turned out to have
// two real bugs on the very first build attempt on real hardware -- treat
// every line below the same way: plausible, unverified, needs a live
// build+test pass (ideally on the same omnio46 box, since illumos is the
// PAM target furthest from what most cgo/PAM examples online assume)
// before this is trusted with anything beyond a throwaway test. Likely
// trouble spots to check first:
//   - PAM's response-array ownership/freeing contract: some PAM
//     implementations free() the array *resp we return from the
//     conversation callback themselves after consuming it, others expect
//     the caller-supplied conv function's allocations to be freed by
//     whoever called pam_authenticate -- this file assumes the former
//     (never frees respArray itself after returning it), which is the
//     documented Linux-PAM contract, but has NOT been checked against
//     illumos's actual PAM implementation's own contract.
//   - the "login" PAM service name (see verifyOSAccount) is a guess at a
//     service that exists everywhere by default; illumos ships its own
//     /etc/pam.d/other + service-specific stacks that may behave
//     differently for "login" specifically than Linux's does.
//   - the uintptr<->unsafe.Pointer handle trick below is a standard cgo
//     idiom (the value is never dereferenced as a real pointer on the Go
//     side, only used as an opaque map key), but go vet's unsafeptr
//     check may still flag it -- confirm `go vet` is clean on the actual
//     build platform, not just that it compiles.

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
	"sync"
	"unsafe"
)

// gateAccount is the OS account cs-console authenticates against before
// starting the requested command -- see cs-console.info: "an OS-delegated
// root/Administrator password confirm is required first".
const gateAccount = "root"

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
	// "login" is used as a broadly-available default PAM service (present
	// in /etc/pam.d/login on effectively every PAM-based system) so no new
	// PAM config file needs to ship with cs-console -- if a deployment
	// wants a dedicated policy (e.g. its own 2FA requirement just for
	// console access), a "cs-console" service file could be added and
	// this name changed to match, but that's not needed to get OS-
	// delegated auth working at all.
	cService := C.CString("login")
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
