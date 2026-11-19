package dedup

import (
	"crypto/sha256"
	"hash"
	"io"
	"os"

	"gitlab.com/specterog/maxzip/internal/compressor"
	"gitlab.com/specterog/maxzip/internal/cryptoutil"
)

type BlockOutput struct {
	TempPath   string
	PayloadLen int64
	SHA        [32]byte
	UncompSize int64
}

type nopWC struct{ io.Writer }

func (nopWC) Close() error { return nil }

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

func (b *BlockBuilder) WriteChunk(data []byte) (int64, error) {
	offset := b.uncompSize
	if _, err := b.cw.Write(data); err != nil {
		return 0, err
	}
	b.uncompSize += int64(len(data))
	return offset, nil
}

func (b *BlockBuilder) ShouldFlush() bool { return b.uncompSize >= b.target }

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
