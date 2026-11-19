package preprocess

import "encoding/binary"

const MaxBCJSize = 64 << 20

var (
	maskToAllowed = [8]bool{true, true, true, false, true, false, false, false}
	maskToBit     = [8]uint32{0, 1, 2, 2, 3, 3, 3, 3}
)

func test86MSByte(b byte) bool { return b == 0x00 || b == 0xFF }

func BCJEncode(b []byte) { bcj(b, true) }

func BCJDecode(b []byte) { bcj(b, false) }

func bcj(buf []byte, encode bool) {
	if len(buf) < 5 {
		return
	}
	var prevMask uint32
	prevPos := ^uint32(4) 
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

func LooksLikeX86Executable(head []byte) bool {
	if len(head) >= 2 && head[0] == 'M' && head[1] == 'Z' {
		return true
	}
	if len(head) >= 20 && string(head[:4]) == "\x7fELF" {
		
		m := binary.LittleEndian.Uint16(head[18:20])
		if head[5] == 2 { 
			m = binary.BigEndian.Uint16(head[18:20])
		}
		return m == 3 || m == 62
	}
	return false
}
