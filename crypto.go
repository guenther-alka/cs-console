package main

// Payload encryption for the frontend<->cs-console session data channel.
//
// Deliberately application-level ChaCha20-Poly1305 with a one-time session
// key, NOT reliance on whatever transport (TLS or plain TCP) is used
// underneath -- see cs-console.info "PAYLOAD ENCRYPTION". This mirrors the
// existing napp-it cs pattern: the core &socket() channel already encrypts
// frontend-backend data with ChaCha20, and ZFS replication already uses an
// "encrypted zstream with a one-time key" for one specific bulk transfer.
//
// Framing: each message is
//   [4-byte big-endian length][12-byte nonce][ciphertext+16-byte AEAD tag]
// The nonce is a random 12 bytes per message (simplest correct scheme --
// with a fresh random key per session and messages that are naturally
// bounded in count for one interactive session, random-nonce collision
// probability is negligible; a monotonic counter is an equally valid
// alternative and slightly cheaper, not implemented here for simplicity).

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

const sessionKeyLen = chacha20poly1305.KeySize // 32 bytes

// newSessionKey returns a fresh random ChaCha20-Poly1305 key for one session.
func newSessionKey() ([]byte, error) {
	key := make([]byte, sessionKeyLen)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generating session key: %w", err)
	}
	return key, nil
}

// sealedWriter wraps an io.Writer, sealing every frame with the session key.
type sealedWriter struct {
	w    io.Writer
	aead interface {
		Seal(dst, nonce, plaintext, additionalData []byte) []byte
		NonceSize() int
	}
}

func newSealedWriter(w io.Writer, key []byte) (*sealedWriter, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("init AEAD: %w", err)
	}
	return &sealedWriter{w: w, aead: aead}, nil
}

func (s *sealedWriter) WriteFrame(plaintext []byte) error {
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("generating nonce: %w", err)
	}
	sealed := s.aead.Seal(nil, nonce, plaintext, nil)
	frame := make([]byte, 4+len(nonce)+len(sealed))
	binary.BigEndian.PutUint32(frame[0:4], uint32(len(nonce)+len(sealed)))
	copy(frame[4:], nonce)
	copy(frame[4+len(nonce):], sealed)
	_, err := s.w.Write(frame)
	return err
}

// sealedReader wraps an io.Reader, opening every frame with the session key.
type sealedReader struct {
	r    io.Reader
	aead interface {
		Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)
		NonceSize() int
	}
}

func newSealedReader(r io.Reader, key []byte) (*sealedReader, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("init AEAD: %w", err)
	}
	return &sealedReader{r: r, aead: aead}, nil
}

const maxFrameLen = 1 << 20 // 1MB per frame -- generous for terminal I/O, bounds memory

func (s *sealedReader) ReadFrame() ([]byte, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(s.r, lenBuf[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(lenBuf[:])
	if n > maxFrameLen || int(n) < s.aead.NonceSize() {
		return nil, errors.New("cs-console: frame length out of bounds")
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(s.r, buf); err != nil {
		return nil, err
	}
	nonce := buf[:s.aead.NonceSize()]
	ciphertext := buf[s.aead.NonceSize():]
	plaintext, err := s.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("cs-console: frame auth failed (tampered or wrong key): %w", err)
	}
	return plaintext, nil
}
