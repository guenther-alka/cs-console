//go:build illumos

package main

// illumos PTY backend -- HAND-ROLLED, UNTESTED ON REAL HARDWARE.
//
// illumos libc has never shipped openpty()/forkpty()/login_tty() (see
// https://illumos.org/issues/5386, still open), so unlike every other
// platform this backend targets, there is no library to wrap. The sequence
// below follows the documented, solved pattern used by neovim's own
// SunOS/illumos forkpty() (commit 2c8f4d0912a280ae55d73d96d0ca2ed96b8fde8a),
// Python's old Solaris posixmodule.c patch, and gnulib's openpty module:
//
//   1. open /dev/ptmx (master)
//   2. grantpt() + unlockpt(), ptsname() -> slave device path
//   3. fork()
//      child:  setsid() to become a new session leader with no controlling
//              terminal, then open the slave path AGAIN (this second open,
//              made by a session leader with no controlling tty and NOT
//              O_NOCTTY, is what actually acquires it as the controlling
//              terminal under SysV/illumos tty semantics -- the Linux
//              TIOCSCTTY ioctl approach does not apply here), push the
//              STREAMS modules "ptem"/"ldterm"/"ttcompat" onto it, dup2
//              it onto fd 0/1/2, exec the target program.
//      parent: keep the master fd for I/O, remember the child pid.
//
// This whole dance is done in a small embedded C helper (below) rather than
// via os/exec + syscall.SysProcAttr, deliberately: the Go runtime does not
// give user code a safe hook to run arbitrary syscalls between fork() and
// exec() in the child (needed here for the second open()+STREAMS push),
// and illumos's syscall.SysProcAttr does not expose Linux's TIOCSCTTY-style
// Setctty mechanism this would otherwise need. Doing the fork/setsid/open/
// push/dup2/exec sequence in C via cgo is the faithful, direct translation
// of the reference implementations above, at the cost of requiring cgo
// (CGO_ENABLED=1 and a C compiler -- gcc, e.g. `pkg install
// developer/gcc` on OmniOS -- at build time for this platform only; the
// other platforms' backends are pure Go).
//
// STATUS: written from the documented pattern, has NOT been built or run
// on real illumos/OmniOS hardware yet -- see cs-console.info OPEN
// QUESTIONS item 1. Treat every syscall constant and struct layout below
// as needing verification on a real machine before this is trusted with
// anything beyond a throwaway test. Likely trouble spots to check first:
//   - exact I_PUSH ioctl constant value and the "strioctl"-vs-plain-string
//     argument form actually expected by illumos' streamio.h (this uses
//     the plain-string form documented in ptem(7M)/streamio(7I));
//   - whether grantpt()/unlockpt()/ptsname() are present as expected in
//     OmniOS's current libc, and their exact signatures;
//   - error handling / retry needs around EINTR that a real test run
//     would surface.

/*
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <stropts.h>
#include <sys/stat.h>
#include <sys/wait.h>

// Runs the full open/grantpt/unlockpt/fork/setsid/reopen/streams-push/
// exec sequence. argv must be NULL-terminated. Returns the master fd on
// success (>=0) and writes the child pid to *out_pid; returns -1 and sets
// errno on failure before fork; returns -2 if fork() itself failed.
static int cs_console_illumos_start(char *const argv[], pid_t *out_pid) {
    int master = open("/dev/ptmx", O_RDWR | O_NOCTTY);
    if (master < 0) return -1;
    if (grantpt(master) != 0) { close(master); return -1; }
    if (unlockpt(master) != 0) { close(master); return -1; }
    char *slave_name = ptsname(master);
    if (slave_name == NULL) { close(master); return -1; }
    // Copy off the stack before fork -- ptsname()'s buffer is static/thread-local.
    char slave_path[256];
    strncpy(slave_path, slave_name, sizeof(slave_path) - 1);
    slave_path[sizeof(slave_path) - 1] = '\0';

    pid_t pid = fork();
    if (pid < 0) { close(master); return -2; }

    if (pid == 0) {
        // Child: new session, then re-open the slave (this is the open
        // that acquires it as our controlling terminal -- see header
        // comment above), push the STREAMS modules, wire up fd 0/1/2.
        close(master);
        if (setsid() < 0) _exit(126);
        int slave = open(slave_path, O_RDWR);
        if (slave < 0) _exit(126);
        if (ioctl(slave, I_PUSH, "ptem") < 0) _exit(126);
        if (ioctl(slave, I_PUSH, "ldterm") < 0) _exit(126);
        if (ioctl(slave, I_PUSH, "ttcompat") < 0) _exit(126);
        if (dup2(slave, 0) < 0 || dup2(slave, 1) < 0 || dup2(slave, 2) < 0) _exit(126);
        if (slave > 2) close(slave);
        execvp(argv[0], argv);
        _exit(127); // execvp only returns on failure
    }

    // Parent.
    *out_pid = pid;
    return master;
}
*/
import "C"

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

type illumosPTY struct {
	master *os.File
	pid    int
}

func startPTY(cfg *startConfig) (ptySession, error) {
	argv := append([]string{cfg.Cmd}, cfg.Args...)
	cArgv := make([]*C.char, len(argv)+1)
	for i, a := range argv {
		cArgv[i] = C.CString(a)
	}
	cArgv[len(argv)] = nil
	defer func() {
		for _, p := range cArgv[:len(argv)] {
			C.free(unsafe.Pointer(p))
		}
	}()

	var cPid C.pid_t
	masterFd, cerr := C.cs_console_illumos_start(&cArgv[0], &cPid)
	if masterFd < 0 {
		if masterFd == -2 {
			return nil, fmt.Errorf("fork() failed starting %q under illumos pty", cfg.Cmd)
		}
		// cerr is populated from errno as a side effect of the cgo call
		// convention (the standard two-value-return idiom) -- there is no
		// syscall.GetErrno() in Go, that was never a real function.
		return nil, fmt.Errorf("starting %q under illumos pty: %w", cfg.Cmd, cerr)
	}

	master := os.NewFile(uintptr(masterFd), "/dev/ptmx")
	return &illumosPTY{master: master, pid: int(cPid)}, nil
}

func (i *illumosPTY) Read(p []byte) (int, error)  { return i.master.Read(p) }
func (i *illumosPTY) Write(p []byte) (int, error) { return i.master.Write(p) }

func (i *illumosPTY) Resize(cols, rows int) error {
	// TIOCSWINSZ works identically to the BSD/Linux ioctl once "ptem" is
	// pushed onto the slave (ptem emulates the standard terminal ioctls,
	// see ptem(7M)). Go's stdlib syscall package has no SYS_IOCTL/raw
	// Syscall trampoline for illumos/solaris (confirmed by grepping Go
	// 1.26's syscall source on real OmniOS: SYS_IOCTL is defined only for
	// linux/bsd/darwin) -- illumos's Go port wraps ioctl via libc instead,
	// exposed through golang.org/x/sys/unix (already a project dependency).
	// unix.IoctlSetWinsize's illumos/solaris variant (ioctl_signed.go,
	// //go:build aix || solaris) takes an int req, matching unix.TIOCSWINSZ
	// and unix.Winsize as defined for solaris (illumos reuses the solaris
	// x/sys/unix files, same as it reuses stdlib syscall's solaris files).
	ws := &unix.Winsize{Row: uint16(rows), Col: uint16(cols)}
	return unix.IoctlSetWinsize(int(i.master.Fd()), unix.TIOCSWINSZ, ws)
}

func (i *illumosPTY) Wait() error {
	var ws syscall.WaitStatus
	_, err := syscall.Wait4(i.pid, &ws, 0, nil)
	if err != nil {
		return err
	}
	// syscall.Wait4 only reports the wait syscall itself failing (ECHILD
	// etc.) -- the child's exit status lives in ws. Report a non-zero exit
	// or signal death as an error so expect mode's NoSuccessMarker actions
	// (success == exit code 0) are meaningful on illumos too, matching the
	// *exec.ExitError semantics cmd.Wait() gives the unix backend.
	if ws.Exited() {
		if code := ws.ExitStatus(); code != 0 {
			return fmt.Errorf("exit status %d", code)
		}
		return nil
	}
	return fmt.Errorf("terminated abnormally: %v", ws)
}

func (i *illumosPTY) Close() error {
	_ = i.master.Close()
	if i.pid > 0 {
		_ = syscall.Kill(i.pid, syscall.SIGKILL)
	}
	return nil
}
