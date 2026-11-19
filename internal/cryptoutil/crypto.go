// Package cryptoutil provides password-based archive encryption:
// Argon2id key derivation + chunked AES-256-GCM.
//
// Nonce safety: every encrypted stream (one per block, plus one for the
// footer) starts with a fresh random 128-bit stream ID, and a per-stream
// sub-key is derived from the master key with HMAC-SHA256(master, ID).
// Because each stream therefore has its own AES key, the plain counter
// nonce inside it can never collide with a nonce used under any other key -
// unlike a scheme with a short random nonce prefix under one shared key,
// where a birthday collision (and with it the catastrophic loss of GCM
// confidentiality/authenticity) becomes plausible on large archives.
//
// Every chunk is also authenticated together with its position and a
// "final" flag, so reordering, dropping or truncating chunks of a stream is
// detected, and with caller-supplied associated data (the stream's role and
// block index), so a stream can't be transplanted somewhere else.
package cryptoutil

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
)

const (
	nonceSize     = 12
	tagSize       = 16
	streamIDSize  = 16
	chunkPlainMax = 4 << 20 // 4 MiB of plaintext per encrypted chunk
)

// KDFParams are the Argon2id cost parameters. They are stored in the archive
// header so they can be raised in future versions without breaking old
// archives.
type KDFParams struct {
	Time    uint32 // passes
	MemKiB  uint32 // memory in KiB
	Threads uint8
}

// DefaultKDF is a deliberately stronger-than-minimum setting (3 passes,
// 128 MiB, 4 lanes).
var DefaultKDF = KDFParams{Time: 3, MemKiB: 128 * 1024, Threads: 4}

// Upper bounds accepted when READING an archive, so a crafted header can't
// make the decryptor allocate absurd amounts of memory or burn CPU forever.
const (
	maxKDFTime    = 64
	maxKDFMemKiB  = 2 * 1024 * 1024 // 2 GiB
	maxKDFThreads = 64
)

// Validate rejects parameters that are zero or unreasonably large.
func (p KDFParams) Validate() error {
	if p.Time < 1 || p.Time > maxKDFTime {
		return fmt.Errorf("unsupported KDF time cost %d", p.Time)
	}
	if p.MemKiB < 8 || p.MemKiB > maxKDFMemKiB {
		return fmt.Errorf("unsupported KDF memory cost %d KiB", p.MemKiB)
	}
	if p.Threads < 1 || p.Threads > maxKDFThreads {
		return fmt.Errorf("unsupported KDF parallelism %d", p.Threads)
	}
	return nil
}

// DeriveKey turns a password + random salt into a 32-byte master key using
// Argon2id (memory-hard, resistant to GPU brute-forcing).
func DeriveKey(password string, salt []byte, p KDFParams) ([]byte, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return argon2.IDKey([]byte(password), salt, p.Time, p.MemKiB, p.Threads, 32), nil
}

// Cipher holds the master key of an archive. It is safe for concurrent use:
// every stream derives its own AEAD from it.
type Cipher struct {
	master []byte
}

// NewCipher wraps a 32-byte master key.
func NewCipher(key []byte) (*Cipher, error) {
	if len(key) != 32 {
		return nil, errors.New("cryptoutil: master key must be 32 bytes")
	}
	k := make([]byte, len(key))
	copy(k, key)
	return &Cipher{master: k}, nil
}

func (c *Cipher) streamAEAD(id []byte) (cipher.AEAD, error) {
	mac := hmac.New(sha256.New, c.master)
	mac.Write([]byte("gitlab.com/specterog/maxzip/stream-key/v1"))
	mac.Write(id)
	block, err := aes.NewCipher(mac.Sum(nil))
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func chunkNonce(counter uint64) []byte {
	nonce := make([]byte, nonceSize)
	binary.BigEndian.PutUint64(nonce[4:], counter)
	return nonce
}

// chunkAAD = caller AAD || counter || final flag.
func chunkAAD(aad []byte, counter uint64, final bool) []byte {
	out := make([]byte, 0, len(aad)+9)
	out = append(out, aad...)
	var c [8]byte
	binary.BigEndian.PutUint64(c[:], counter)
	out = append(out, c[:]...)
	if final {
		out = append(out, 1)
	} else {
		out = append(out, 0)
	}
	return out
}

// EncryptWriter encrypts data in fixed-size chunks and writes
// [4-byte big-endian ciphertext length][ciphertext+tag] records, preceded by
// the 16-byte random stream ID. Close MUST be called: it emits the final
// (possibly empty) chunk that marks the end of the stream.
type EncryptWriter struct {
	w       io.Writer
	aead    cipher.AEAD
	aad     []byte
	counter uint64
	buf     []byte
	closed  bool
}

// NewEncryptWriter starts a new stream. aad binds the stream to its context
// (for example "block" + index); the reader must supply the same value.
func NewEncryptWriter(w io.Writer, c *Cipher, aad []byte) (*EncryptWriter, error) {
	id := make([]byte, streamIDSize)
	if _, err := rand.Read(id); err != nil {
		return nil, err
	}
	aead, err := c.streamAEAD(id)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(id); err != nil {
		return nil, err
	}
	return &EncryptWriter{w: w, aead: aead, aad: append([]byte(nil), aad...), buf: make([]byte, 0, chunkPlainMax)}, nil
}

func (e *EncryptWriter) Write(p []byte) (int, error) {
	if e.closed {
		return 0, errors.New("cryptoutil: write after close")
	}
	total := len(p)
	for len(p) > 0 {
		// A full buffer is only flushed once more data arrives, so the last
		// chunk of the stream is always flushed by Close and marked final.
		if len(e.buf) == chunkPlainMax {
			if err := e.flushChunk(false); err != nil {
				return 0, err
			}
		}
		n := chunkPlainMax - len(e.buf)
		if n > len(p) {
			n = len(p)
		}
		e.buf = append(e.buf, p[:n]...)
		p = p[n:]
	}
	return total, nil
}

func (e *EncryptWriter) flushChunk(final bool) error {
	nonce := chunkNonce(e.counter)
	ct := e.aead.Seal(nil, nonce, e.buf, chunkAAD(e.aad, e.counter, final))
	e.counter++
	e.buf = e.buf[:0]
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(ct)))
	if _, err := e.w.Write(lenBuf[:]); err != nil {
		return err
	}
	_, err := e.w.Write(ct)
	return err
}

// Close writes the final chunk. It is idempotent.
func (e *EncryptWriter) Close() error {
	if e.closed {
		return nil
	}
	e.closed = true
	return e.flushChunk(true)
}

// DecryptReader reverses EncryptWriter, presenting a plain io.Reader.
type DecryptReader struct {
	r       io.Reader
	aead    cipher.AEAD
	aad     []byte
	counter uint64
	buf     []byte
	done    bool
}

func NewDecryptReader(r io.Reader, c *Cipher, aad []byte) (*DecryptReader, error) {
	id := make([]byte, streamIDSize)
	if _, err := io.ReadFull(r, id); err != nil {
		return nil, err
	}
	aead, err := c.streamAEAD(id)
	if err != nil {
		return nil, err
	}
	return &DecryptReader{r: r, aead: aead, aad: append([]byte(nil), aad...)}, nil
}

var errAuth = errors.New("decryption failed: wrong password or corrupted archive")

func (d *DecryptReader) Read(p []byte) (int, error) {
	for len(d.buf) == 0 {
		if d.done {
			return 0, io.EOF
		}
		if err := d.readChunk(); err != nil {
			return 0, err
		}
	}
	n := copy(p, d.buf)
	d.buf = d.buf[n:]
	return n, nil
}

func (d *DecryptReader) readChunk() error {
	var lenBuf [4]byte
	if _, err := io.ReadFull(d.r, lenBuf[:]); err != nil {
		if err == io.EOF {
			// The stream ended without its final chunk: truncated.
			return errors.New("decryption failed: stream is truncated")
		}
		return err
	}
	ctLen := binary.BigEndian.Uint32(lenBuf[:])
	if ctLen < tagSize || ctLen > chunkPlainMax+tagSize {
		return errors.New("decryption failed: invalid chunk length (corrupted archive)")
	}
	ct := make([]byte, ctLen)
	if _, err := io.ReadFull(d.r, ct); err != nil {
		return err
	}
	// A non-final chunk always carries exactly chunkPlainMax bytes; anything
	// shorter must be the final one. Try the most likely interpretation
	// first, then the other, so the final flag is authenticated either way.
	final := ctLen != chunkPlainMax+tagSize
	nonce := chunkNonce(d.counter)
	pt, err := d.aead.Open(nil, nonce, ct, chunkAAD(d.aad, d.counter, final))
	if err != nil && !final {
		pt, err = d.aead.Open(nil, nonce, ct, chunkAAD(d.aad, d.counter, true))
		if err == nil {
			final = true
		}
	}
	if err != nil {
		return errAuth
	}
	d.counter++
	d.buf = pt
	d.done = final
	return nil
}
