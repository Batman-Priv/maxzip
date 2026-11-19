package delta

import (
	"bytes"
	"encoding/binary"
	"math/rand"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	rng := rand.New(rand.NewSource(3))
	ref := make([]byte, 50000)
	rng.Read(ref)
	tgt := append([]byte(nil), ref...)
	copy(tgt[1000:1100], bytes.Repeat([]byte{7}, 100))
	tgt = append(tgt, []byte("more")...)
	ops, err := Unmarshal(Marshal(Encode(ref, tgt, 1024)))
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeMax(ref, ops, len(tgt))
	if err != nil || !bytes.Equal(got, tgt) {
		t.Fatalf("round trip failed: %v", err)
	}
}

func TestDecodeMaxStopsBombs(t *testing.T) {
	ref := make([]byte, 100)
	ops := make([]Op, 1000)
	for i := range ops {
		ops[i] = Op{Kind: Copy, RefOffset: 0, Length: 100}
	}
	if _, err := DecodeMax(ref, ops, 5000); err == nil {
		t.Fatal("100 KB of output accepted under a 5000 byte limit")
	}
}

func TestUnmarshalRejectsLies(t *testing.T) {
	// op count of 4 billion with no data
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, 0xFFFFFFFF)
	if _, err := Unmarshal(b); err == nil {
		t.Fatal("impossible op count accepted")
	}
	// literal claiming 4 GB
	b = []byte{0, 0, 0, 1, byte(Literal), 0xFF, 0xFF, 0xFF, 0xFF}
	if _, err := Unmarshal(b); err == nil {
		t.Fatal("impossible literal length accepted")
	}
}

func TestUnmarshalGarbageNeverPanics(t *testing.T) {
	rng := rand.New(rand.NewSource(9))
	ref := make([]byte, 64)
	for i := 0; i < 20000; i++ {
		b := make([]byte, rng.Intn(64))
		rng.Read(b)
		if len(b) >= 4 {
			b[0], b[1], b[2] = 0, 0, 0
		}
		if ops, err := Unmarshal(b); err == nil {
			_, _ = DecodeMax(ref, ops, 1<<20)
		}
	}
}
