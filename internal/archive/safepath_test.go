package archive

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"
)

func TestCleanEntryNameRejectsEscapes(t *testing.T) {
	bad := []string{
		"", "..", "../x", "a/../../x", "a/..", "/etc/passwd", `\windows\x`, `..\x`, `a\..\..\x`,
		"C:/x", "C:x", "a\x00b", ".", "./", "//",
	}
	for _, n := range bad {
		if _, err := cleanEntryName(n); err == nil {
			t.Errorf("cleanEntryName(%q) accepted", n)
		}
	}
	good := map[string]string{"a.txt": "a.txt", "a/b/c": "a/b/c", "./a//b": "a/b", "dir/.hidden": "dir/.hidden", "a..b": "a..b"}
	for in, want := range good {
		got, err := cleanEntryName(in)
		if err != nil || got != want {
			t.Errorf("cleanEntryName(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
}

func TestSafeJoinStaysInside(t *testing.T) {
	root := t.TempDir()
	p, err := safeJoin(root, "sub/file.txt")
	if err != nil || p != filepath.Join(root, "sub", "file.txt") {
		t.Fatalf("got %q, %v", p, err)
	}
	if _, err := safeJoin(root, "../evil"); err == nil {
		t.Fatal("../evil accepted")
	}
}

func extract(t *testing.T, root, name string, content []byte) error {
	t.Helper()
	hdr := &tar.Header{Name: name, Size: int64(len(content)), Mode: 0o644}
	return writeExtractedFile(hdr, bytes.NewReader(content), newDeltaState(), root, sha256.Sum256(content), uint64(len(content)), true)
}

func TestZipSlipFileIsNotWritten(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "out")
	os.Mkdir(root, 0o755)
	if err := extract(t, root, "../escaped.txt", []byte("pwned")); err == nil {
		t.Fatal("extraction of ../escaped.txt succeeded")
	}
	if _, err := os.Stat(filepath.Join(base, "escaped.txt")); err == nil {
		t.Fatal("file escaped the output directory")
	}
}

func TestWriteThroughSymlinkDirIsRefused(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "out")
	outside := filepath.Join(base, "outside")
	os.Mkdir(root, 0o755)
	os.Mkdir(outside, 0o755)
	
	if err := os.Symlink(outside, filepath.Join(root, "link")); err != nil {
		t.Skip("symlinks unavailable:", err)
	}
	if err := extract(t, root, "link/pwned.txt", []byte("pwned")); err == nil {
		t.Fatal("wrote through a symlinked directory")
	}
	if _, err := os.Stat(filepath.Join(outside, "pwned.txt")); err == nil {
		t.Fatal("file landed outside via symlink")
	}
}

func TestFinalComponentSymlinkIsReplacedNotFollowed(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "out")
	victim := filepath.Join(base, "victim.txt")
	os.Mkdir(root, 0o755)
	os.WriteFile(victim, []byte("original"), 0o644)
	if err := os.Symlink(victim, filepath.Join(root, "f")); err != nil {
		t.Skip("symlinks unavailable:", err)
	}
	if err := extract(t, root, "f", []byte("new")); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(victim); string(b) != "original" {
		t.Fatalf("symlink target was overwritten: %q", b)
	}
	if b, _ := os.ReadFile(filepath.Join(root, "f")); string(b) != "new" {
		t.Fatalf("file not written in place of the symlink: %q", b)
	}
}

func TestSizeCapStopsDecompressionBomb(t *testing.T) {
	root := t.TempDir()
	content := bytes.Repeat([]byte("A"), 4096)
	hdr := &tar.Header{Name: "bomb", Size: int64(len(content)), Mode: 0o644}
	
	err := writeExtractedFile(hdr, bytes.NewReader(content), newDeltaState(), root, sha256.Sum256(content), 10, true)
	if err == nil {
		t.Fatal("oversized stream accepted")
	}
	if fi, _ := os.Stat(filepath.Join(root, "bomb")); fi != nil && fi.Size() > 11 {
		t.Fatalf("wrote %d bytes past the cap", fi.Size())
	}
}

func TestSymlinkEntryEscapeRefused(t *testing.T) {
	root := t.TempDir()
	hdr := &tar.Header{Typeflag: tar.TypeSymlink, Name: "../l", Linkname: "x"}
	if err := writeExtractedSymlink(hdr, root, sha256.Sum256([]byte("x")), true); err == nil {
		t.Fatal("symlink entry with ../ name accepted")
	}
}
