// Throwaway smoke-test client: connects to a running cs-console instance,
// does the sealed-frame auth handshake, sends one line of input, prints
// what comes back. Not part of the shipped design -- just for verifying
// crypto.go + main.go's relay logic actually works end-to-end.
package main

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

func seal(aead interface {
	Seal(dst, nonce, plaintext, additionalData []byte) []byte
	NonceSize() int
}, plaintext []byte) []byte {
	nonce := make([]byte, aead.NonceSize())
	rand.Read(nonce)
	sealed := aead.Seal(nil, nonce, plaintext, nil)
	frame := make([]byte, 4+len(nonce)+len(sealed))
	binary.BigEndian.PutUint32(frame[0:4], uint32(len(nonce)+len(sealed)))
	copy(frame[4:], nonce)
	copy(frame[4+len(nonce):], sealed)
	return frame
}

func readFrame(r io.Reader, aead interface {
	Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)
	NonceSize() int
}) ([]byte, error) {
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
	port := os.Args[1]
	tokenHex := os.Args[2]
	keyHex := os.Args[3]

	token := mustHex(tokenHex)
	key := mustHex(keyHex)

	aead, err := chacha20poly1305.New(key)
	if err != nil {
		panic(err)
	}

	conn, err := net.Dial("tcp", "127.0.0.1:"+port)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	// Auth frame: the session token itself.
	if _, err := conn.Write(seal(aead, token)); err != nil {
		panic(err)
	}

	// Read whatever the PTY already produced (e.g. shell banner/echo).
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	out, err := readFrame(conn, aead)
	if err != nil {
		fmt.Println("read1 err:", err)
	} else {
		fmt.Printf("PTY said: %q\n", string(out))
	}

	// Send a line of input.
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
