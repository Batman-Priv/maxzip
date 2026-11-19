package dedup

import (
	"crypto/sha256"
	"hash"
	"io"
	"os"

	"gitlab.com/specterog/maxzip/internal/compressor"
	"gitlab.com/specterog/maxzip/internal/cryptoutil"
)

// BlockOutput describes a finished, on-disk (temp file) compressed block of
// unique chunks, ready to be copied into the archive by the caller.
type BlockOutput struct {
	TempPath   string
	PayloadLen int64
	SHA        [32]byte
	UncompSize int64
}

type nopWC struct{ io.Writer }

func (nopWC) Close() error { return nil }

// BlockBuilder accumulates unique chunks into a temp file, compressing (and
// optionally encrypting) them as one shared stream - the same "solid"
// principle as internal/block, just applied to chunks instead of whole
// files. Chunk discovery must stay sequential (each new chunk's uniqueness
// depends on every chunk seen before it), so unlike file-mode blocks this
// isn't built in parallel across blocks.
// BlockBuilder never applies a shared dictionary: unlike internal/block's
// solid tar blocks (one clean boundary per block), a chunked block's
// stored chunk offsets/lengths are relative to the block's own content
// only - prepending dictionary bytes here would shift every offset and
// break chunk reconstruction. Dictionary support is scoped to normal
// (non-dedup, non-big-file) mode only.
type BlockBuilder struct {
	algo   compressor.Algo
	level  string
	aead   *cryptoutil.Cipher
	aad    []byte
	target int64

	tmp         *os.File
	tmpPath     string
	hasher      hash.Hash
	finalWriter io.WriteCloser
	cw          io.WriteCloser
	uncompSize  int64
}

// aad is bound into every encrypted chunk of the builder's blocks.
func NewBlockBuilder(algo compressor.Algo, level string, aead *cryptoutil.Cipher, aad []byte, targetSize int64) (*BlockBuilder, error) {
	b := &BlockBuilder{algo: algo, level: level, aead: aead, aad: aad, target: targetSize}
	if err := b.reset(); err != nil {
		return nil, err
	}
	return b, nil
}

func (b *BlockBuilder) reset() error {
	tmp, err := os.CreateTemp("", "maxzip-dedup-*")
	if err != nil {
		return err
	}
	b.tmp = tmp
	b.tmpPath = tmp.Name()
	b.hasher = sha256.New()
	hw := io.MultiWriter(tmp, b.hasher)

	var fw io.WriteCloser = nopWC{hw}
	if b.aead != nil {
		ew, err := cryptoutil.NewEncryptWriter(hw, b.aead, b.aad)
		if err != nil {
			return err
		}
		fw = ew
	}
	b.finalWriter = fw

	cw, err := compressor.NewWriter(fw, b.algo, b.level, 1)
	if err != nil {
		return err
	}
	b.cw = cw
	b.uncompSize = 0
	return nil
}

// WriteChunk writes one chunk into the current block and returns its offset
// within the block's decompressed stream.
func (b *BlockBuilder) WriteChunk(data []byte) (int64, error) {
	offset := b.uncompSize
	if _, err := b.cw.Write(data); err != nil {
		return 0, err
	}
	b.uncompSize += int64(len(data))
	return offset, nil
}

func (b *BlockBuilder) ShouldFlush() bool { return b.uncompSize >= b.target }

// Finish closes out the current block and prepares the builder for the next
// one. Returns (nil, nil) if the block is empty (nothing to flush).
func (b *BlockBuilder) Finish() (*BlockOutput, error) {
	if b.uncompSize == 0 {
		os.Remove(b.tmpPath)
		return nil, nil
	}
	if err := b.cw.Close(); err != nil {
		return nil, err
	}
	if err := b.finalWriter.Close(); err != nil {
		return nil, err
	}
	if err := b.tmp.Close(); err != nil {
		return nil, err
	}
	var sha [32]byte
	copy(sha[:], b.hasher.Sum(nil))
	fi, err := os.Stat(b.tmpPath)
	if err != nil {
		return nil, err
	}
	out := &BlockOutput{TempPath: b.tmpPath, PayloadLen: fi.Size(), SHA: sha, UncompSize: b.uncompSize}
	if err := b.reset(); err != nil {
		return nil, err
	}
	return out, nil
}
