package preprocess

import "encoding/binary"

// x86 "BCJ" filter: machine code is full of CALL (E8) and JMP (E9)
// instructions whose operand is a RELATIVE displacement, so the same target
// function appears as a different 4-byte number at every call site. The
// filter rewrites those operands to ABSOLUTE addresses, which repeat
// exactly and compress far better. It is the same idea as the BCJ filters in
// 7-Zip/xz, and, like them, only a heuristic about WHICH bytes are
// instructions: a stray E8/E9 inside data is converted too, but the
// transform is an exact bijection either way, so decoding always restores
// the original bytes - the filter can only fail to help, never corrupt.
//
// Reversibility is the delicate part: converting one operand rewrites bytes
// that an earlier, unconverted E8/E9 looked at when it made its own
// decision, so a naive filter is NOT invertible (the unit test with dense
// E8/E9 data catches exactly that). This implementation therefore follows
// the carefully designed state machine used by the xz/LZMA SDK x86 filter
// (a small "previous opcodes" mask decides when a candidate may be
// converted, and an inner loop keeps the converted value inside the
// sign-extension range), which is a true bijection; the tests round-trip
// millions of adversarial bytes and a real binary.

// MaxBCJSize bounds the files BCJ will buffer in memory.
const MaxBCJSize = 64 << 20

var (
	maskToAllowed = [8]bool{true, true, true, false, true, false, false, false}
	maskToBit     = [8]uint32{0, 1, 2, 2, 3, 3, 3, 3}
)

func test86MSByte(b byte) bool { return b == 0x00 || b == 0xFF }

// BCJEncode transforms b in place.
func BCJEncode(b []byte) { bcj(b, true) }

// BCJDecode reverses BCJEncode in place.
func BCJDecode(b []byte) { bcj(b, false) }

func bcj(buf []byte, encode bool) {
	if len(buf) < 5 {
		return
	}
	var prevMask uint32
	prevPos := ^uint32(4) // == 0-5 mod 2^32, as in the reference: nothing seen yet
	limit := len(buf) - 5
	pos := 0
	for pos <= limit {
		b := buf[pos]
		if b != 0xE8 && b != 0xE9 {
			pos++
			continue
		}
		offset := uint32(pos) - prevPos
		prevPos = uint32(pos)
		if offset > 5 {
			prevMask = 0
		} else {
			for i := uint32(0); i < offset; i++ {
				prevMask &= 0x77
				prevMask <<= 1
			}
		}
		b = buf[pos+4]
		if test86MSByte(b) && maskToAllowed[(prevMask>>1)&7] && (prevMask>>1) < 0x10 {
			src := uint32(b)<<24 | uint32(buf[pos+3])<<16 | uint32(buf[pos+2])<<8 | uint32(buf[pos+1])
			var dest uint32
			for {
				if encode {
					dest = src + uint32(pos) + 5
				} else {
					dest = src - (uint32(pos) + 5)
				}
				if prevMask == 0 {
					break
				}
				i := maskToBit[prevMask>>1]
				b = byte(dest >> (24 - i*8))
				if !test86MSByte(b) {
					break
				}
				src = dest ^ (uint32(1)<<(32-i*8) - 1)
			}
			buf[pos+4] = ^byte(((dest >> 24) & 1) - 1)
			buf[pos+3] = byte(dest >> 16)
			buf[pos+2] = byte(dest >> 8)
			buf[pos+1] = byte(dest)
			pos += 5
			prevMask = 0
		} else {
			pos++
			prevMask |= 1
			if test86MSByte(b) {
				prevMask |= 0x10
			}
		}
	}
}

// LooksLikeX86Executable reports whether the first bytes of a file look
// like a PE ("MZ") or ELF executable/library - the only files BCJ is tried
// on, so it never wastes time (or risks anything) on ordinary data.
func LooksLikeX86Executable(head []byte) bool {
	if len(head) >= 2 && head[0] == 'M' && head[1] == 'Z' {
		return true
	}
	if len(head) >= 20 && string(head[:4]) == "\x7fELF" {
		// e_machine at offset 18 (little endian): 3 = x86, 62 = x86-64.
		m := binary.LittleEndian.Uint16(head[18:20])
		if head[5] == 2 { // big-endian ELF
			m = binary.BigEndian.Uint16(head[18:20])
		}
		return m == 3 || m == 62
	}
	return false
}
