package cryptoutil

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"io"
	"testing"
)

func testCipher(t *testing.T) *Cipher {
	t.Helper()
	k := make([]byte, 32)
	rand.Read(k)
	c, err := NewCipher(k)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func encrypt(t *testing.T, c *Cipher, aad, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := NewEncryptWriter(&buf, c, aad)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func decrypt(c *Cipher, aad, ct []byte) ([]byte, error) {
	r, err := NewDecryptReader(bytes.NewReader(ct), c, aad)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(r)
}

func TestRoundTripSizes(t *testing.T) {
	c := testCipher(t)
	
	for _, n := range []int{0, 1, 1000, chunkPlainMax, chunkPlainMax + 1, 2 * chunkPlainMax, 2*chunkPlainMax + 17} {
		data := make([]byte, n)
		rand.Read(data)
		got, err := decrypt(c, []byte("aad"), encrypt(t, c, []byte("aad"), data))
		if err != nil {
			t.Fatalf("size %d: %v", n, err)
		}
		if !bytes.Equal(got, data) {
			t.Fatalf("size %d: round trip mismatch", n)
		}
	}
}

func TestWrongKeyAndAAD(t *testing.T) {
	c, other := testCipher(t), testCipher(t)
	ct := encrypt(t, c, []byte("block:1"), []byte("secret"))
	if _, err := decrypt(other, []byte("block:1"), ct); err == nil {
		t.Fatal("decrypted with the wrong key")
	}
	if _, err := decrypt(c, []byte("block:2"), ct); err == nil {
		t.Fatal("decrypted with the wrong AAD (stream transplant not detected)")
	}
}

func TestTamperDetected(t *testing.T) {
	c := testCipher(t)
	ct := encrypt(t, c, nil, bytes.Repeat([]byte("x"), 5000))
	for _, pos := range []int{streamIDSize + 4, len(ct) - 1, 3} {
		bad := append([]byte(nil), ct...)
		bad[pos] ^= 1
		if _, err := decrypt(c, nil, bad); err == nil {
			t.Fatalf("flip at %d not detected", pos)
		}
	}
}

func TestTruncationAndReorderDetected(t *testing.T) {
	c := testCipher(t)
	data := make([]byte, 2*chunkPlainMax+100)
	rand.Read(data)
	ct := encrypt(t, c, nil, data)

	off := streamIDSize
	for i := 0; i < 2; i++ {
		off += 4 + int(binary.BigEndian.Uint32(ct[off:]))
	}
	if _, err := decrypt(c, nil, ct[:off]); err == nil {
		t.Fatal("dropping the final chunk was not detected")
	}

	l0 := 4 + int(binary.BigEndian.Uint32(ct[streamIDSize:]))
	s1 := streamIDSize + l0
	l1 := 4 + int(binary.BigEndian.Uint32(ct[s1:]))
	sw := append([]byte(nil), ct[:streamIDSize]...)
	sw = append(sw, ct[s1:s1+l1]...)
	sw = append(sw, ct[streamIDSize:streamIDSize+l0]...)
	sw = append(sw, ct[s1+l1:]...)
	if _, err := decrypt(c, nil, sw); err == nil {
		t.Fatal("chunk reordering was not detected")
	}
}

func TestOversizedChunkLengthRejected(t *testing.T) {
	c := testCipher(t)
	ct := encrypt(t, c, nil, []byte("hi"))
	binary.BigEndian.PutUint32(ct[streamIDSize:], 0xFFFFFFF0)
	if _, err := decrypt(c, nil, ct); err == nil {
		t.Fatal("absurd chunk length accepted")
	}
}

func TestStreamsUseDistinctKeys(t *testing.T) {
	c := testCipher(t)
	seen := map[string]bool{}
	for i := 0; i < 2000; i++ {
		ct := encrypt(t, c, nil, []byte("a"))
		id := string(ct[:streamIDSize])
		if seen[id] {
			t.Fatal("stream ID repeated")
		}
		seen[id] = true
	}
}

func TestKDFParamsValidated(t *testing.T) {
	bad := []KDFParams{{0, 1024, 1}, {1, 0, 1}, {1, 1024, 0}, {1000, 1024, 1}, {1, 1 << 30, 1}}
	for _, p := range bad {
		if _, err := DeriveKey("pw", make([]byte, 16), p); err == nil {
			t.Fatalf("accepted bad params %+v", p)
		}
	}
	if _, err := DeriveKey("pw", make([]byte, 16), KDFParams{1, 64, 1}); err != nil {
		t.Fatal(err)
	}
}
