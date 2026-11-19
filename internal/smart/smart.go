// Package smart decides whether a file is worth compressing.
package smart

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/klauspost/compress/zstd"

	"gitlab.com/specterog/maxzip/internal/fsutil"
)

type Mode string

const (
	Off        Mode = "off"
	On         Mode = "on"
	Aggressive Mode = "aggressive"
)

func ParseMode(s string) (Mode, error) {
	switch Mode(s) {
	case Off, On, Aggressive:
		return Mode(s), nil
	default:
		return "", fmt.Errorf("unknown -smart value %q (use off, on or aggressive)", s)
	}
}

// IsStore is the cheap, extension/magic-byte-only guess, used by
// internal/block purely to GROUP likely-incompressible files together for
// locality. It is deliberately NOT trusted as a final compress/store
// decision anymore: internal/archive always actually compresses that group
// (via a fast probe, promoting to the real algorithm if the probe shows
// real gains) and falls back to raw storage only if compression genuinely
// didn't help. That real-data check is what actually fixes formats like
// APKs or JPEGs that often have a few percent of recoverable slack an
// extension guess alone would always miss.
func IsStore(fe fsutil.FileRef, mode Mode) bool {
	if mode == Off {
		return false
	}
	if isIncompressibleExt(fe.Rel) {
		return true
	}
	f, err := os.Open(fe.Abs)
	if err != nil {
		return false
	}
	defer f.Close()
	head := make([]byte, 512)
	n, _ := io.ReadFull(f, head)
	return sniffMagic(head[:n])
}

// IsStoreVerified is used by -dedup / big-file chunked mode, which has no
// equivalent per-block "try then fall back" safety net (a chunked block
// mixes chunks from many files, so it can't cheaply be rebuilt with a
// different algorithm for just one file). So here, unlike IsStore, a
// positive extension/magic match is only a hint, not the final answer: an
// actual sample compression test always makes the real call. Off mode
// still trusts the fast guess alone (skip the CPU cost entirely) since the
// user explicitly asked for no smart handling.
func IsStoreVerified(fe fsutil.FileRef, mode Mode) bool {
	if mode == Off {
		return isIncompressibleExt(fe.Rel)
	}

	f, err := os.Open(fe.Abs)
	if err != nil {
		return false
	}
	defer f.Close()

	sampleSize := 256 * 1024
	threshold := 0.97
	if mode == Aggressive {
		sampleSize = 1 << 20
		threshold = 0.99 // only give up if compression genuinely did almost nothing
	}

	sample := make([]byte, sampleSize)
	sn, _ := io.ReadFull(f, sample)
	if sn < 8192 {
		// too small to trust a compression-ratio estimate - fall back to
		// the cheap guess
		return isIncompressibleExt(fe.Rel) || sniffMagic(sample[:sn])
	}

	var out bytes.Buffer
	zw, err := zstd.NewWriter(&out, zstd.WithEncoderLevel(zstd.SpeedFastest))
	if err != nil {
		return isIncompressibleExt(fe.Rel)
	}
	if _, err := zw.Write(sample[:sn]); err != nil {
		zw.Close()
		return isIncompressibleExt(fe.Rel)
	}
	zw.Close()

	ratio := float64(out.Len()) / float64(sn)
	return ratio > threshold
}

// sniffMagic is a heuristic, not an exhaustive file-type database.
func sniffMagic(b []byte) bool {
	sigs := [][]byte{
		{0xFF, 0xD8, 0xFF},                   // JPEG
		{0x89, 0x50, 0x4E, 0x47},             // PNG
		{0x47, 0x49, 0x46, 0x38},             // GIF
		{0x50, 0x4B, 0x03, 0x04},             // ZIP/DOCX/XLSX/PPTX/JAR/APK
		{0x1F, 0x8B},                         // GZIP
		{0x42, 0x5A, 0x68},                   // BZIP2
		{0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C}, // 7Z
		{0x52, 0x61, 0x72, 0x21, 0x1A, 0x07}, // RAR
		{0x25, 0x50, 0x44, 0x46},             // PDF
		{0x49, 0x44, 0x33},                   // MP3 (ID3)
		{0xFF, 0xFB},                         // MP3 (no ID3)
	}
	for _, sig := range sigs {
		if len(b) >= len(sig) && bytes.Equal(b[:len(sig)], sig) {
			return true
		}
	}
	if len(b) >= 12 && bytes.Equal(b[4:8], []byte("ftyp")) { // MP4/MOV family
		return true
	}
	// RIFF is a generic container: WEBP and AVI are already compressed, but
	// WAV is (usually) raw PCM audio and compresses very well, so it must
	// NOT be treated as incompressible.
	if len(b) >= 12 && bytes.Equal(b[0:4], []byte("RIFF")) &&
		(bytes.Equal(b[8:12], []byte("WEBP")) || bytes.Equal(b[8:12], []byte("AVI "))) {
		return true
	}
	return false
}

var incompressibleExt = map[string]bool{
	".mp4": true, ".mkv": true, ".avi": true, ".mov": true, ".wmv": true,
	".flv": true, ".webm": true, ".m4v": true, ".ts": true,
	".mp3": true, ".aac": true, ".ogg": true, ".opus": true, ".m4a": true,
	".jpg": true, ".jpeg": true, ".png": true, ".gif": true, ".webp": true, ".heic": true,
	".zip": true, ".rar": true, ".7z": true, ".gz": true, ".bz2": true,
	".xz": true, ".zst": true, ".apk": true, ".jar": true,
	".docx": true, ".xlsx": true, ".pptx": true,
}

func isIncompressibleExt(name string) bool {
	return incompressibleExt[strings.ToLower(filepath.Ext(name))]
}
