
package compressor

import (
	"compress/flate"
	"fmt"
	"io"
	"strings"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
	"github.com/pierrec/lz4/v4"
	"github.com/ulikunitz/xz"
)

type Algo byte

const (
	Store   Algo = 0
	Zstd    Algo = 1
	XZ      Algo = 2
	Deflate Algo = 3
	LZ4     Algo = 4
	Brotli  Algo = 5

	Auto Algo = 255
)

func (a Algo) String() string {
	switch a {
	case Zstd:
		return "zstd"
	case XZ:
		return "xz"
	case Deflate:
		return "deflate"
	case LZ4:
		return "lz4"
	case Brotli:
		return "brotli"
	case Auto:
		return "auto"
	default:
		return "store"
	}
}

func ParseAlgo(s string) (Algo, error) {
	switch strings.ToLower(s) {
	case "zstd":
		return Zstd, nil
	case "xz":
		return XZ, nil
	case "deflate":
		return Deflate, nil
	case "lz4":
		return LZ4, nil
	case "brotli":
		return Brotli, nil
	case "auto":
		return Auto, nil
	default:
		return 0, fmt.Errorf("unknown algorithm %q (use zstd, xz, deflate, lz4, brotli or auto)", s)
	}
}

func ParseLevel(s string) (string, error) {
	switch strings.ToLower(s) {
	case "fastest", "default", "better", "best":
		return strings.ToLower(s), nil
	default:
		return "", fmt.Errorf("unknown level %q (use fastest, default, better or best)", s)
	}
}

type nopWriteCloser struct{ io.Writer }

func (nopWriteCloser) Close() error { return nil }

func NewWriter(w io.Writer, algo Algo, level string, threads int) (io.WriteCloser, error) {
	switch algo {
	case Zstd:
		var el zstd.EncoderLevel
		switch level {
		case "fastest":
			el = zstd.SpeedFastest
		case "default":
			el = zstd.SpeedDefault
		case "better":
			el = zstd.SpeedBetterCompression
		default:
			el = zstd.SpeedBestCompression
		}
		opts := []zstd.EOption{zstd.WithEncoderLevel(el)}
		if threads > 0 {
			opts = append(opts, zstd.WithEncoderConcurrency(threads))
		}
		return zstd.NewWriter(w, opts...)

	case XZ:
		dictCap := map[string]int{
			"fastest": 1 << 20, "default": 8 << 20, "better": 32 << 20, "best": 64 << 20,
		}[level]
		cfg := xz.WriterConfig{DictCap: dictCap}
		if err := cfg.Verify(); err != nil {
			return nil, err
		}
		return cfg.NewWriter(w)

	case Deflate:
		lvl := map[string]int{
			"fastest": flate.BestSpeed, "default": flate.DefaultCompression,
			"better": 7, "best": flate.BestCompression,
		}[level]
		return flate.NewWriter(w, lvl)

	case LZ4:
		zw := lz4.NewWriter(w)
		var lvl lz4.CompressionLevel
		switch level {
		case "fastest":
			lvl = lz4.Fast
		case "default":
			lvl = lz4.Level5
		case "better":
			lvl = lz4.Level7
		default:
			lvl = lz4.Level9
		}
		if err := zw.Apply(lz4.CompressionLevelOption(lvl)); err != nil {
			return nil, err
		}
		return zw, nil

	case Brotli:
		lvl := map[string]int{"fastest": 1, "default": 6, "better": 9, "best": 11}[level]
		return brotli.NewWriterLevel(w, lvl), nil

	default: 
		return nopWriteCloser{w}, nil
	}
}

func NewDecompressReader(r io.Reader, algo Algo) (io.Reader, error) {
	switch algo {
	case Zstd:
		zr, err := zstd.NewReader(r)
		if err != nil {
			return nil, err
		}
		return zr, nil
	case XZ:
		return xz.NewReader(r)
	case Deflate:
		return flate.NewReader(r), nil
	case LZ4:
		return lz4.NewReader(r), nil
	case Brotli:
		return brotli.NewReader(r), nil
	default:
		return r, nil
	}
}

func CloseDecompressor(r io.Reader) {
	switch v := r.(type) {
	case *zstd.Decoder:
		v.Close()
	case io.Closer:
		_ = v.Close()
	}
}
