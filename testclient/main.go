// Throwaway smoke-test client: connects to a running cs-console instance,
// does the sealed-frame auth handshake, then drives the SECURITY --
// PASSWORD GATE sub-protocol (gateMessage JSON frames, see auth.go) before
// falling through to a one-line PTY echo round-trip if the gate reports
// "ok". Not part of the shipped design -- just for verifying the gate +
// relay logic actually work end-to-end on real hardware.
//
// Usage: testclient <port> <token-hex> <key-hex> <password-to-send> [host]
//
// IMPORTANT (cs_26.09.04 hardening-pass live tests): this client is meant
// to be run with a WRONG password, or with lockout/banner behavior as the
// thing under test -- never with a real root/Administrator password typed
// into an AI-driven session. The success ("ok") path is for a human to
// verify by running this same command themselves, by hand, on their own
// keyboard, with their own real password as argv[4].
package main

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

type aeadIface interface {
	Seal(dst, nonce, plaintext, additionalData []byte) []byte
	Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)
	NonceSize() int
}

type gateMessage struct {
	Type string `json:"type"`
	Echo bool   `json:"echo"`
	Text string `json:"text"`
}

func seal(aead aeadIface, plaintext []byte) []byte {
	nonce := make([]byte, aead.NonceSize())
	rand.Read(nonce)
	sealed := aead.Seal(nil, nonce, plaintext, nil)
	frame := make([]byte, 4+len(nonce)+len(sealed))
	binary.BigEndian.PutUint32(frame[0:4], uint32(len(nonce)+len(sealed)))
	copy(frame[4:], nonce)
	copy(frame[4+len(nonce):], sealed)
	return frame
}

func readFrame(r io.Reader, aead aeadIface) ([]byte, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(lenBuf[:])
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	nonce := buf[:aead.NonceSize()]
	ct := buf[aead.NonceSize():]
	return aead.Open(nil, nonce, ct, nil)
}

func main() {
	if len(os.Args) < 5 {
		fmt.Fprintln(os.Stderr, "usage: testclient <port> <token-hex> <key-hex> <password> [host]")
		os.Exit(2)
	}
	port := os.Args[1]
	tokenHex := os.Args[2]
	keyHex := os.Args[3]
	password := os.Args[4]
	host := "127.0.0.1"
	if len(os.Args) > 5 {
		host = os.Args[5]
	}

	token := mustHex(tokenHex)
	key := mustHex(keyHex)

	aead, err := chacha20poly1305.New(key)
	if err != nil {
		panic(err)
	}

	conn, err := net.Dial("tcp", host+":"+port)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	// Auth frame: the session token itself.
	if _, err := conn.Write(seal(aead, token)); err != nil {
		panic(err)
	}

	conn.SetReadDeadline(time.Now().Add(10 * time.Second))

	// Password-gate phase: cs-console sends one gateMessage JSON frame at
	// a time (info/prompt/locked/ok/denied) until either "ok" (fall
	// through to raw PTY relay below) or "locked"/"denied" (session over).
	for {
		frame, err := readFrame(conn, aead)
		if err != nil {
			fmt.Println("gate read err:", err)
			return
		}
		var m gateMessage
		if err := json.Unmarshal(frame, &m); err != nil {
			fmt.Printf("gate: non-JSON frame (unexpected): %q\n", frame)
			return
		}
		switch m.Type {
		case "info":
			fmt.Printf("[gate info] %s\n", m.Text)
		case "prompt":
			echoNote := "masked"
			if m.Echo {
				echoNote = "visible"
			}
			fmt.Printf("[gate prompt, %s] %s -> sending supplied password\n", echoNote, m.Text)
			if _, err := conn.Write(seal(aead, []byte(password))); err != nil {
				panic(err)
			}
		case "locked":
			fmt.Printf("[gate LOCKED] %s\n", m.Text)
			return
		case "denied":
			fmt.Printf("[gate DENIED] %s\n", m.Text)
			return
		case "ok":
			fmt.Println("[gate OK] authenticated -- falling through to PTY relay")
			goto relay
		default:
			fmt.Printf("[gate] unknown message type %q: %s\n", m.Type, m.Text)
		}
	}

relay:
	// Same Phase-1 echo round-trip as before, now only reachable after a
	// real successful OS auth.
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	out, err := readFrame(conn, aead)
	if err != nil {
		fmt.Println("read1 err:", err)
	} else {
		fmt.Printf("PTY said: %q\n", string(out))
	}

	if _, err := conn.Write(seal(aead, []byte("echo round-trip-ok\n"))); err != nil {
		panic(err)
	}

	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	for i := 0; i < 3; i++ {
		out, err := readFrame(conn, aead)
		if err != nil {
			fmt.Println("read err:", err)
			break
		}
		fmt.Printf("PTY said: %q\n", string(out))
	}
}

func mustHex(s string) []byte {
	b := make([]byte, len(s)/2)
	for i := range b {
		fmt.Sscanf(s[i*2:i*2+2], "%02x", &b[i])
	}
	return b
}
