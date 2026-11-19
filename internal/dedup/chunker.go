
package dedup

import "io"

const windowSize = 48

var buzTable [256]uint64

func splitmix64(x *uint64) uint64 {
	*x += 0x9E3779B97F4A7C15
	z := *x
	z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9
	z = (z ^ (z >> 27)) * 0x94D049BB133111EB
	return z ^ (z >> 31)
}

func init() {
	seed := uint64(1) 
	for i := range buzTable {
		buzTable[i] = splitmix64(&seed)
	}
}

func rotl(x uint64, k uint) uint64 {
	return (x << k) | (x >> (64 - k))
}

type ChunkOptions struct {
	Min  int
	Max  int
	Mask uint64
}

func NewChunkOptions(avg int) ChunkOptions {
	if avg < 4096 {
		avg = 4096
	}
	bits := 0
	for (1<<uint(bits)) < avg && bits < 27 {
		bits++
	}
	return ChunkOptions{
		Min:  avg / 4,
		Max:  avg * 4,
		Mask: (uint64(1) << uint(bits)) - 1,
	}
}

func ChunkStream(r io.Reader, opt ChunkOptions, emit func([]byte) error) error {
	var hash uint64
	window := make([]byte, 0, windowSize)
	cur := make([]byte, 0, opt.Max)
	buf := make([]byte, 32*1024)

	flush := func() error {
		if len(cur) == 0 {
			return nil
		}
		chunk := make([]byte, len(cur))
		copy(chunk, cur)
		cur = cur[:0]
		window = window[:0]
		hash = 0
		return emit(chunk)
	}

	for {
		n, rerr := r.Read(buf)
		for i := 0; i < n; i++ {
			b := buf[i]
			cur = append(cur, b)
			if len(window) < windowSize {
				window = append(window, b)
				hash = rotl(hash, 1) ^ buzTable[b]
			} else {
				out := window[0]
				window = append(window[1:], b)
				hash = rotl(hash, 1) ^ buzTable[b] ^ rotl(buzTable[out], windowSize)
			}
			if len(cur) >= opt.Min {
				if len(cur) >= opt.Max || (hash&opt.Mask) == 0 {
					if err := flush(); err != nil {
						return err
					}
				}
			}
		}
		if rerr == io.EOF {
			return flush()
		}
		if rerr != nil {
			return rerr
		}
	}
}
