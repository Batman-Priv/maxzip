// Package format defines the on-disk layout of a maxzip archive (MAXZ4) and
// the low-level read/write helpers shared by every archive mode.
//
// Header:
//
//	[5 bytes]  magic "MAXZ5"
//	[1 byte]   format version
//	[1 byte]   flags: bit0=encrypted, bit1=dedup mode, bit2=dictionary present,
//	           bit6=comment present, bits3-5=default algo (informational;
//	           every block also stores its own actual algo byte, so this
//	           is only a quick hint)
//	[16 bytes] salt (only if encrypted)
//	[4+4+1 bytes] Argon2id time, memory (KiB), threads (only if encrypted)
//	[4 bytes + N] dictionary length + bytes (only if FlagDict is set)
//	[4 bytes + N] comment length + UTF-8 bytes (only if FlagComment is set) -
//	           always stored in plaintext, even for encrypted archives, the
//	           same way zip/rar comments are viewable without a password
//	[32 bytes] SHA-256 of every header byte above (catches header corruption;
//	           block contents and the footer index are each separately
//	           checksummed too - see internal/archive - so this is the one
//	           remaining piece of the file that wasn't covered by anything)
//	... body (block-mode or dedup-mode; see internal/archive) ...
//
// Body layout is documented in internal/archive.
//
// Version 2 changes from version 1: header checksum added, and the footer
// layout in internal/archive gained an always-present "chunked section"
// (used by -dedup and automatic big-file splitting). Version 3 adds the
// comment field. Version 4 adds an empty-directories section to the
// normal-mode footer, and permission/mtime fields to chunked-mode file
// entries (see internal/archive for both). Version 5 stores the Argon2id
// parameters in the header, uses per-stream sub-keys with authenticated
// chunk positions (see internal/cryptoutil), and encrypts + authenticates
// the footer index of encrypted archives. Archives from an earlier version
// are not readable by this version.
package format

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"

	"gitlab.com/specterog/maxzip/internal/cryptoutil"
)

const (
	Magic         = "MAXZ5"
	FormatVersion = byte(5)

	FlagEncrypted = byte(1 << 0)
	FlagDedup     = byte(1 << 1)
	FlagDict      = byte(1 << 2)
	FlagComment   = byte(1 << 6)
	AlgoShift     = 3
	AlgoMask      = byte(0x7)

	SaltSize = 16

	// Upper bounds enforced when reading, so a crafted header can't force a
	// huge allocation before any checksum has been verified.
	MaxDictSize    = 64 << 20
	MaxCommentSize = 1 << 20
	MaxStringSize  = 0xFFFF
)

// Header holds everything read from (or written to) the fixed archive header.
type Header struct {
	Flags   byte
	Salt    []byte               // present only if Flags&FlagEncrypted != 0
	KDF     cryptoutil.KDFParams // present only if Flags&FlagEncrypted != 0
	Dict    []byte               // present only if Flags&FlagDict != 0
	Comment string               // present only if Flags&FlagComment != 0
}

func WriteHeader(w io.Writer, h Header) error {
	if len(h.Dict) > MaxDictSize {
		return fmt.Errorf("dictionary too large (%d bytes)", len(h.Dict))
	}
	if len(h.Comment) > MaxCommentSize {
		return fmt.Errorf("comment too long (%d bytes, max %d)", len(h.Comment), MaxCommentSize)
	}
	var buf bytes.Buffer
	buf.WriteString(Magic)
	buf.Write([]byte{FormatVersion, h.Flags})
	if h.Flags&FlagEncrypted != 0 {
		buf.Write(h.Salt)
		var kdf [9]byte
		binary.BigEndian.PutUint32(kdf[0:4], h.KDF.Time)
		binary.BigEndian.PutUint32(kdf[4:8], h.KDF.MemKiB)
		kdf[8] = h.KDF.Threads
		buf.Write(kdf[:])
	}
	if h.Flags&FlagDict != 0 {
		var lenBuf [4]byte
		binary.BigEndian.PutUint32(lenBuf[:], uint32(len(h.Dict)))
		buf.Write(lenBuf[:])
		buf.Write(h.Dict)
	}
	if h.Flags&FlagComment != 0 {
		var lenBuf [4]byte
		binary.BigEndian.PutUint32(lenBuf[:], uint32(len(h.Comment)))
		buf.Write(lenBuf[:])
		buf.WriteString(h.Comment)
	}
	sum := sha256.Sum256(buf.Bytes())
	if _, err := w.Write(buf.Bytes()); err != nil {
		return err
	}
	_, err := w.Write(sum[:])
	return err
}

func ReadHeader(r io.Reader) (Header, error) {
	var h Header
	buf := make([]byte, len(Magic)+2)
	if _, err := io.ReadFull(r, buf); err != nil {
		return h, err
	}
	if string(buf[:len(Magic)]) != Magic {
		return h, fmt.Errorf("not a valid maxzip archive (bad magic) - archives from older versions are not compatible with this one")
	}
	version := buf[len(Magic)]
	if version != FormatVersion {
		return h, fmt.Errorf("unsupported archive version %d (this build reads version %d)", version, FormatVersion)
	}
	h.Flags = buf[len(Magic)+1]

	var headerBytes bytes.Buffer
	headerBytes.Write(buf)

	if h.Flags&FlagEncrypted != 0 {
		h.Salt = make([]byte, SaltSize)
		if _, err := io.ReadFull(r, h.Salt); err != nil {
			return h, err
		}
		headerBytes.Write(h.Salt)
		var kdf [9]byte
		if _, err := io.ReadFull(r, kdf[:]); err != nil {
			return h, err
		}
		headerBytes.Write(kdf[:])
		h.KDF = cryptoutil.KDFParams{
			Time:    binary.BigEndian.Uint32(kdf[0:4]),
			MemKiB:  binary.BigEndian.Uint32(kdf[4:8]),
			Threads: kdf[8],
		}
	}
	if h.Flags&FlagDict != 0 {
		var lenBuf [4]byte
		if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
			return h, err
		}
		headerBytes.Write(lenBuf[:])
		n := binary.BigEndian.Uint32(lenBuf[:])
		dict, err := readBounded(r, n, MaxDictSize, "dictionary")
		if err != nil {
			return h, err
		}
		h.Dict = dict
		headerBytes.Write(h.Dict)
	}
	if h.Flags&FlagComment != 0 {
		var lenBuf [4]byte
		if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
			return h, err
		}
		headerBytes.Write(lenBuf[:])
		n := binary.BigEndian.Uint32(lenBuf[:])
		cbuf, err := readBounded(r, n, MaxCommentSize, "comment")
		if err != nil {
			return h, err
		}
		headerBytes.Write(cbuf)
		h.Comment = string(cbuf)
	}

	var stored [32]byte
	if _, err := io.ReadFull(r, stored[:]); err != nil {
		return h, err
	}
	sum := sha256.Sum256(headerBytes.Bytes())
	if !bytes.Equal(sum[:], stored[:]) {
		return h, fmt.Errorf("archive header is corrupted (checksum mismatch)")
	}
	return h, nil
}

// readBounded reads exactly n bytes, refusing n above max, and without
// allocating n bytes up front: memory grows only as real data arrives, so a
// header that lies about a length can't make us allocate more than the file
// actually holds.
func readBounded(r io.Reader, n, max uint32, what string) ([]byte, error) {
	if n > max {
		return nil, fmt.Errorf("corrupted archive: %s length %d exceeds limit %d", what, n, max)
	}
	var buf bytes.Buffer
	if _, err := io.CopyN(&buf, r, int64(n)); err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return nil, err
	}
	return buf.Bytes(), nil
}

// ReadBounded is the exported form of readBounded for other packages.
func ReadBounded(r io.Reader, n, max uint32, what string) ([]byte, error) {
	return readBounded(r, n, max, what)
}

// WriteString/ReadString: a length-prefixed UTF-8 string, used throughout
// the footer formats for file names.
func WriteString(w io.Writer, s string) error {
	if len(s) > MaxStringSize {
		return fmt.Errorf("name too long (%d bytes, max %d): %.60s...", len(s), MaxStringSize, s)
	}
	if err := binary.Write(w, binary.BigEndian, uint16(len(s))); err != nil {
		return err
	}
	_, err := w.Write([]byte(s))
	return err
}

func ReadString(r io.Reader) (string, error) {
	var l uint16
	if err := binary.Read(r, binary.BigEndian, &l); err != nil {
		return "", err
	}
	buf := make([]byte, l)
	if _, err := io.ReadFull(r, buf); err != nil {
		return "", err
	}
	return string(buf), nil
}
