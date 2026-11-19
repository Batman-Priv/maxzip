package archive

import (
	"bytes"
	"math/rand"
	"os"
	"path/filepath"
	"testing"

	"gitlab.com/specterog/maxzip/internal/compressor"
	"gitlab.com/specterog/maxzip/internal/format"
	"gitlab.com/specterog/maxzip/internal/smart"
)

func makeTree(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "d"), 0o755)
	os.WriteFile(filepath.Join(dir, "a.txt"), bytes.Repeat([]byte("hello world\n"), 5000), 0o644)
	os.WriteFile(filepath.Join(dir, "d", "b.txt"), bytes.Repeat([]byte("other text\n"), 3000), 0o644)
	return dir
}

func pack(t *testing.T, src, pw string) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), "t.mzp")
	err := Pack(PackOptions{
		Inputs: []string{src}, Output: out, Algo: compressor.Zstd, Level: "fastest",
		Smart: smart.On, Password: pw, Threads: 2, BlockSize: 16 * 1024, DedupChunk: 4096,
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestEncryptedFooterHidesNames(t *testing.T) {
	a := pack(t, makeTree(t), "pw")
	raw, _ := os.ReadFile(a)
	if bytes.Contains(raw, []byte("a.txt")) || bytes.Contains(raw, []byte("b.txt")) {
		t.Fatal("file names are visible in an encrypted archive")
	}
}

func TestTamperedEncryptedArchiveFails(t *testing.T) {
	a := pack(t, makeTree(t), "pw")
	raw, _ := os.ReadFile(a)
	rng := rand.New(rand.NewSource(1))
	detected := 0
	const trials = 40
	for i := 0; i < trials; i++ {
		bad := append([]byte(nil), raw...)
		bad[rng.Intn(len(bad))] ^= 0x40
		p := filepath.Join(t.TempDir(), "bad.mzp")
		os.WriteFile(p, bad, 0o644)
		if err := Test(TestOptions{Input: p, Password: "pw"}); err != nil {
			detected++
		}
	}
	// A flipped bit may land in a harmless spot (e.g. the unused comment
	// flag byte area) only if the header checksum misses it - it must not.
	if detected != trials {
		t.Fatalf("only %d/%d single-bit corruptions detected", detected, trials)
	}
}

func TestTamperedUnencryptedArchiveFailsUnpackNoPanic(t *testing.T) {
	a := pack(t, makeTree(t), "")
	raw, _ := os.ReadFile(a)
	rng := rand.New(rand.NewSource(2))
	for i := 0; i < 200; i++ {
		bad := append([]byte(nil), raw...)
		for k := 0; k < 1+rng.Intn(4); k++ {
			bad[rng.Intn(len(bad))] = byte(rng.Intn(256))
		}
		p := filepath.Join(t.TempDir(), "bad.mzp")
		os.WriteFile(p, bad, 0o644)
		// Must return (error or nil), never panic or hang.
		_ = Unpack(UnpackOptions{Input: p, Output: t.TempDir(), Verify: true})
		_, _ = ListEntries(p, "")
	}
}

func TestTruncatedArchiveFails(t *testing.T) {
	a := pack(t, makeTree(t), "pw")
	raw, _ := os.ReadFile(a)
	for _, cut := range []int{len(raw) - 1, len(raw) - 50, len(raw) / 2, 20} {
		p := filepath.Join(t.TempDir(), "cut.mzp")
		os.WriteFile(p, raw[:cut], 0o644)
		if err := Test(TestOptions{Input: p, Password: "pw"}); err == nil {
			t.Fatalf("truncation to %d bytes not detected", cut)
		}
	}
}

func TestHeaderLengthBombRejected(t *testing.T) {
	// magic + version + dict flag + a 4 GiB dictionary length, no data.
	hdr := append([]byte(format.Magic), format.FormatVersion, format.FlagDict, 0xFF, 0xFF, 0xFF, 0xFF)
	if _, err := format.ReadHeader(bytes.NewReader(hdr)); err == nil {
		t.Fatal("4 GiB dictionary length accepted")
	}
	hdr = append([]byte(format.Magic), format.FormatVersion, format.FlagComment, 0xFF, 0xFF, 0xFF, 0xFF)
	if _, err := format.ReadHeader(bytes.NewReader(hdr)); err == nil {
		t.Fatal("4 GiB comment length accepted")
	}
}

func TestRoundTripEncrypted(t *testing.T) {
	src := makeTree(t)
	a := pack(t, src, "pw")
	out := t.TempDir()
	if err := Unpack(UnpackOptions{Input: a, Output: out, Password: "pw", Verify: true}); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(filepath.Join(out, "d", "b.txt"))
	want, _ := os.ReadFile(filepath.Join(src, "d", "b.txt"))
	if !bytes.Equal(got, want) {
		t.Fatal("content mismatch")
	}
	if err := Unpack(UnpackOptions{Input: a, Output: t.TempDir(), Password: "nope", Verify: true}); err == nil {
		t.Fatal("wrong password accepted")
	}
}
