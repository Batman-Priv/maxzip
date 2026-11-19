// Package delta implements a simplified rsync-style binary diff: encode a
// target byte slice as a series of copy-from-reference and literal-bytes
// instructions against a reference byte slice, and decode it back.
//
// This is NOT the bsdiff algorithm (no suffix array, no byte-exact
// longest-match search) - it's the same fundamental idea rsync itself
// uses: fixed-size reference blocks, indexed by a rolling checksum so the
// target can be scanned for matches at any byte offset, with a strong
// hash to confirm a weak-checksum hit before trusting it. It's simpler
// than bsdiff and easier to verify correct by direct inspection, at the
// cost of not finding byte-exact matches shorter than one block or
// misaligned in ways a full suffix-array search would catch.
//
// STATUS: wired into pack/unpack via "-delta" (see internal/block, which
// groups similar files inside a solid block into reference/delta chains,
// and internal/archive/deltastate.go, which rebuilds them on extraction).
// Everything read back from an archive goes through the bounded
// DecodeMax/Unmarshal below, so a crafted delta can't allocate or produce
// more than the caller allows.
package delta

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
)

// modBase is the same modulus Adler-32 uses - a prime just under 2^16, so
// the two half-sums pack into a uint32 without overlapping.
const modBase uint32 = 65521

// DefaultBlockSize is a reasonable default for typical document/config/
// database-file sized deltas. Smaller blocks find more matches in heavily
// edited files at the cost of a larger delta encoding overhead per match.
const DefaultBlockSize = 2048

type rollingHash struct {
	a, b     uint32
	blockLen uint32
}

func newRollingHash(window []byte) *rollingHash {
	var a, b uint32
	l := uint32(len(window))
	for i, c := range window {
		a += uint32(c)
		b += (l - uint32(i)) * uint32(c)
	}
	return &rollingHash{a: a % modBase, b: b % modBase, blockLen: l}
}

func (h *rollingHash) sum() uint32 {
	return (h.b << 16) | (h.a & 0xffff)
}

// roll advances the window by one byte: oldByte leaves, newByte enters.
func (h *rollingHash) roll(oldByte, newByte byte) {
	h.a = (h.a + modBase - uint32(oldByte)) % modBase
	h.a = (h.a + uint32(newByte)) % modBase
	lOld := (h.blockLen * uint32(oldByte)) % modBase
	h.b = (h.b + modBase - lOld) % modBase
	h.b = (h.b + h.a) % modBase
}

type Kind byte

const (
	Copy Kind = iota
	Literal
)

// Op is one instruction in a delta: either copy Length bytes from the
// reference starting at RefOffset, or emit Data literally.
type Op struct {
	Kind      Kind
	RefOffset int
	Length    int
	Data      []byte
}

type refEntry struct {
	offset int
	strong [32]byte
}

// Encode diffs target against reference, producing a sequence of Ops that
// Decode(reference, ops) reconstructs target from exactly.
func Encode(reference, target []byte, blockSize int) []Op {
	if blockSize <= 0 {
		blockSize = DefaultBlockSize
	}

	index := map[uint32][]refEntry{}
	addRefBlock := func(off int, block []byte) {
		weak := newRollingHash(block).sum()
		index[weak] = append(index[weak], refEntry{offset: off, strong: sha256.Sum256(block)})
	}
	off := 0
	for off+blockSize <= len(reference) {
		addRefBlock(off, reference[off:off+blockSize])
		off += blockSize
	}
	if off < len(reference) {
		addRefBlock(off, reference[off:])
	}

	var ops []Op
	var literal []byte
	flushLiteral := func() {
		if len(literal) > 0 {
			ops = append(ops, Op{Kind: Literal, Length: len(literal), Data: literal})
			literal = nil
		}
	}

	n := len(target)
	if n == 0 {
		return nil
	}
	if n < blockSize {
		return []Op{{Kind: Literal, Length: n, Data: append([]byte(nil), target...)}}
	}

	i := 0
	h := newRollingHash(target[0:blockSize])
	for i+blockSize <= n {
		weak := h.sum()
		matched := false
		if candidates, ok := index[weak]; ok {
			strong := sha256.Sum256(target[i : i+blockSize])
			for _, c := range candidates {
				if c.strong == strong {
					flushLiteral()
					ops = append(ops, Op{Kind: Copy, RefOffset: c.offset, Length: blockSize})
					matched = true
					break
				}
			}
		}
		if matched {
			i += blockSize
			if i+blockSize > n {
				break
			}
			h = newRollingHash(target[i : i+blockSize])
			continue
		}

		literal = append(literal, target[i])
		oldByte := target[i]
		i++
		if i+blockSize > n {
			break
		}
		newByte := target[i+blockSize-1]
		h.roll(oldByte, newByte)
	}
	if i < n {
		literal = append(literal, target[i:]...)
	}
	flushLiteral()
	return ops
}

// Decode reconstructs the target bytes from reference and a sequence of
// Ops produced by Encode.
func Decode(reference []byte, ops []Op) ([]byte, error) {
	return DecodeMax(reference, ops, -1)
}

// DecodeMax is Decode with an upper bound on the output size (maxOut < 0
// means unlimited). Use it on anything that came out of an archive.
func DecodeMax(reference []byte, ops []Op, maxOut int) ([]byte, error) {
	var out []byte
	for _, op := range ops {
		if maxOut >= 0 && (len(out) > maxOut || op.Length > maxOut-len(out)) {
			return nil, fmt.Errorf("delta: output would exceed %d bytes", maxOut)
		}
		switch op.Kind {
		case Copy:
			if op.RefOffset < 0 || op.Length < 0 || op.RefOffset > len(reference) || op.Length > len(reference)-op.RefOffset {
				return nil, fmt.Errorf("delta: copy op out of range (offset %d, length %d, reference %d bytes)", op.RefOffset, op.Length, len(reference))
			}
			out = append(out, reference[op.RefOffset:op.RefOffset+op.Length]...)
		case Literal:
			if maxOut >= 0 && len(op.Data) > maxOut-len(out) {
				return nil, fmt.Errorf("delta: output would exceed %d bytes", maxOut)
			}
			out = append(out, op.Data...)
		default:
			return nil, fmt.Errorf("delta: unknown op kind %d", op.Kind)
		}
	}
	return out, nil
}

// Marshal/Unmarshal serialize Ops to/from a byte blob, for storing a delta
// as archive content once this is wired into the CLI.
func Marshal(ops []Op) []byte {
	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, uint32(len(ops)))
	for _, op := range ops {
		buf.WriteByte(byte(op.Kind))
		switch op.Kind {
		case Copy:
			binary.Write(&buf, binary.BigEndian, uint64(op.RefOffset))
			binary.Write(&buf, binary.BigEndian, uint64(op.Length))
		case Literal:
			binary.Write(&buf, binary.BigEndian, uint32(len(op.Data)))
			buf.Write(op.Data)
		}
	}
	return buf.Bytes()
}

func Unmarshal(data []byte) ([]Op, error) {
	r := bytes.NewReader(data)
	var count uint32
	if err := binary.Read(r, binary.BigEndian, &count); err != nil {
		return nil, err
	}
	// Every op takes at least 5 bytes, so a larger count is impossible.
	if uint64(count)*5 > uint64(r.Len()) {
		return nil, fmt.Errorf("delta: op count %d is impossible for %d bytes of data", count, r.Len())
	}
	ops := make([]Op, count)
	for i := range ops {
		kb, err := r.ReadByte()
		if err != nil {
			return nil, err
		}
		ops[i].Kind = Kind(kb)
		switch ops[i].Kind {
		case Copy:
			var off, length uint64
			if err := binary.Read(r, binary.BigEndian, &off); err != nil {
				return nil, err
			}
			if err := binary.Read(r, binary.BigEndian, &length); err != nil {
				return nil, err
			}
			if off > 1<<40 || length > 1<<40 {
				return nil, fmt.Errorf("delta: copy op out of range")
			}
			ops[i].RefOffset = int(off)
			ops[i].Length = int(length)
		case Literal:
			var l uint32
			if err := binary.Read(r, binary.BigEndian, &l); err != nil {
				return nil, err
			}
			if int64(l) > int64(r.Len()) {
				return nil, fmt.Errorf("delta: literal length %d exceeds the remaining data", l)
			}
			ops[i].Length = int(l)
			buf := make([]byte, l)
			if _, err := io.ReadFull(r, buf); err != nil {
				return nil, err
			}
			ops[i].Data = buf
		default:
			return nil, fmt.Errorf("delta: unknown op kind %d while unmarshaling", kb)
		}
	}
	return ops, nil
}
