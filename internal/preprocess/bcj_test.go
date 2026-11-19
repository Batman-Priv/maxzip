package preprocess

import (
	"bytes"
	"math/rand"
	"os"
	"testing"
)

func TestBCJRoundTripRandom(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	for trial := 0; trial < 200000; trial++ {
		n := rng.Intn(80)
		b := make([]byte, n)
		for i := range b {
			switch rng.Intn(5) {
			case 0:
				b[i] = 0xE8
			case 1:
				b[i] = 0xE9
			case 2:
				b[i] = 0x00
			case 3:
				b[i] = 0xFF
			default:
				b[i] = byte(rng.Intn(256))
			}
		}
		orig := append([]byte(nil), b...)
		BCJEncode(b)
		BCJDecode(b)
		if !bytes.Equal(b, orig) {
			t.Fatalf("round trip failed for %x", orig)
		}
	}
}

func TestBCJExactCall(t *testing.T) {
	// call +0x10 at offset 0 -> absolute 0x15
	b := []byte{0xE8, 0x10, 0, 0, 0, 0x90}
	BCJEncode(b)
	if b[1] != 0x15 || b[4] != 0 {
		t.Fatalf("unexpected encoding %x", b)
	}
	BCJDecode(b)
	if b[1] != 0x10 {
		t.Fatalf("decode failed %x", b)
	}
}

func TestBCJOnRealBinary(t *testing.T) {
	for _, p := range []string{"/bin/ls", "/usr/bin/ls", "/bin/sh"} {
		b, err := os.ReadFile(p)
		if err != nil || !LooksLikeX86Executable(b[:64]) {
			continue
		}
		orig := append([]byte(nil), b...)
		BCJEncode(b)
		if bytes.Equal(b, orig) {
			t.Fatalf("%s: filter changed nothing", p)
		}
		BCJDecode(b)
		if !bytes.Equal(b, orig) {
			t.Fatalf("%s: round trip failed", p)
		}
		return
	}
	t.Skip("no x86 binary available")
}
