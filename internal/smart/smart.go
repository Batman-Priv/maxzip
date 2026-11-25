
package smart

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/klauspost/compress/zstd"

	"github.com/Batman-Priv/maxzip/internal/fsutil"
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
		threshold = 0.99 
	}

	sample := make([]byte, sampleSize)
	sn, _ := io.ReadFull(f, sample)
	if sn < 8192 {
		
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

func sniffMagic(b []byte) bool {
	sigs := [][]byte{
		{0xFF, 0xD8, 0xFF},                   
		{0x89, 0x50, 0x4E, 0x47},             
		{0x47, 0x49, 0x46, 0x38},             
		{0x50, 0x4B, 0x03, 0x04},             
		{0x1F, 0x8B},                         
		{0x42, 0x5A, 0x68},                   
		{0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C}, 
		{0x52, 0x61, 0x72, 0x21, 0x1A, 0x07}, 
		{0x25, 0x50, 0x44, 0x46},             
		{0x49, 0x44, 0x33},                   
		{0xFF, 0xFB},                         
	}
	for _, sig := range sigs {
		if len(b) >= len(sig) && bytes.Equal(b[:len(sig)], sig) {
			return true
		}
	}
	if len(b) >= 12 && bytes.Equal(b[4:8], []byte("ftyp")) { 
		return true
	}
	
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
