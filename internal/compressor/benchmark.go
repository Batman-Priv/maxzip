package compressor

import (
	"bytes"
	"time"
)

type BenchResult struct {
	Algo     Algo
	Size     int
	Duration time.Duration
}

// AutoSelect compresses a sample with every real codec and picks one
// according to optimize ("size", "speed", or "balanced" - default "size").
// This is a simple, honest heuristic run once per archive on a
// representative sample - not an exhaustive search, and not re-run per
// block.
func AutoSelect(sample []byte, level string, optimize string) (Algo, map[Algo]BenchResult) {
	candidates := []Algo{Zstd, XZ, Deflate, LZ4, Brotli}
	results := make(map[Algo]BenchResult, len(candidates))

	for _, a := range candidates {
		start := time.Now()
		var buf bytes.Buffer
		w, err := NewWriter(&buf, a, level, 1)
		if err != nil {
			continue
		}
		if _, err := w.Write(sample); err != nil {
			continue
		}
		if err := w.Close(); err != nil {
			continue
		}
		results[a] = BenchResult{Algo: a, Size: buf.Len(), Duration: time.Since(start)}
	}

	if len(results) == 0 {
		return Zstd, results // safe fallback
	}

	var best Algo
	bestScore := -1.0
	for a, r := range results {
		var score float64
		switch optimize {
		case "speed":
			score = float64(r.Duration.Microseconds())
		case "balanced":
			score = float64(r.Size) * (1 + r.Duration.Seconds())
		default: // "size"
			score = float64(r.Size)
		}
		if bestScore < 0 || score < bestScore {
			bestScore = score
			best = a
		}
	}
	return best, results
}
