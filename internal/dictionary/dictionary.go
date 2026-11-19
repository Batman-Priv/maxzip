// Package dictionary builds a small shared "dictionary" that zstd can use
// as prior context when compressing many small, similar files.
//
// This uses a simplified, COVER-inspired approach: it scores fixed-length
// candidate segments by how much their content (in short d-byte fragments)
// repeats across the whole file set, then greedily keeps the
// highest-scoring, non-duplicate segments up to a size budget. This is NOT
// the real COVER/COVER2 algorithm (which optimizes segment length and d
// simultaneously via suffix arrays, trying many (k,d) parameter pairs
// against a scoring function) - it's a fixed-parameter, single-pass
// approximation of the same core idea: prefer dictionary content that's
// genuinely common across the corpus, kept as coherent runs (not
// scattered fragments), since coherent runs are what actually help zstd's
// match-finder.
//
// A poorly-chosen dictionary can only ever hurt compression ratio, never
// correctness: the exact same dictionary bytes are used for both encoding
// and decoding, so even a bad selection cannot corrupt data - it can only
// fail to help.
//
// The bytes built here are stored once in the archive header, but applied
// per-block as a raw content prefix (see internal/block) rather than
// through zstd's formal dictionary API - klauspost/compress/zstd's
// WithEncoderDict requires a properly structured dictionary (magic number
// + entropy tables), and rejects a plain byte blob with "invalid input:
// magic number mismatch" (caught by real testing, not assumed). The
// prefix-trick sidesteps that entirely: it's just concatenation, so kept
// small on purpose, since each block that uses it pays to re-compress
// these bytes once.
package dictionary

import (
	"os"
	"sort"
)

const (
	maxDictSize   = 24 * 1024  // small on purpose: this is now re-compressed into EVERY block that uses it (see internal/block), not stored once and reused - see internal/dictionary's package doc
	dmerSize      = 8          // short fragment length used for frequency scoring
	segmentSize   = 1024       // candidate dictionary segment length
	segmentStride = 512        // candidate segments overlap by half
	dmerStride    = 8          // non-overlapping d-mer sampling within a segment
	sampleCap     = 512 * 1024 // read at most this much per file
)

type candidate struct {
	data  []byte
	score int
}

// BuildRaw scans the given files and returns a dictionary built from the
// segments most representative of what repeats across them.
func BuildRaw(paths []string) ([]byte, error) {
	samples := make([][]byte, 0, len(paths))
	for _, p := range paths {
		fi, err := os.Stat(p)
		if err != nil || !fi.Mode().IsRegular() {
			continue
		}
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		buf := make([]byte, sampleCap)
		n, _ := f.Read(buf)
		f.Close()
		if n > 0 {
			samples = append(samples, buf[:n])
		}
	}
	if len(samples) == 0 {
		return nil, nil
	}

	// Pass 1: global d-mer frequency across the whole corpus - this is what
	// "repeats a lot" actually means, measured directly rather than guessed.
	freq := map[string]int{}
	for _, s := range samples {
		for i := 0; i+dmerSize <= len(s); i += dmerSize {
			freq[string(s[i:i+dmerSize])]++
		}
	}

	// Pass 2: score every candidate segment by summing the frequency of
	// the d-mers it contains (sampled at a stride to bound cost).
	var candidates []candidate
	for _, s := range samples {
		if len(s) < segmentSize {
			if len(s) == 0 {
				continue
			}
			candidates = append(candidates, candidate{data: s, score: scoreSegment(s, freq)})
			continue
		}
		for start := 0; start+segmentSize <= len(s); start += segmentStride {
			seg := s[start : start+segmentSize]
			candidates = append(candidates, candidate{data: seg, score: scoreSegment(seg, freq)})
		}
	}

	sort.Slice(candidates, func(i, j int) bool { return candidates[i].score > candidates[j].score })

	var dict []byte
	seen := map[string]bool{}
	for _, c := range candidates {
		if len(dict) >= maxDictSize {
			break
		}
		key := string(c.data)
		if seen[key] {
			continue
		}
		seen[key] = true
		remain := maxDictSize - len(dict)
		if len(c.data) > remain {
			dict = append(dict, c.data[:remain]...)
			break
		}
		dict = append(dict, c.data...)
	}
	return dict, nil
}

func scoreSegment(seg []byte, freq map[string]int) int {
	score := 0
	for i := 0; i+dmerSize <= len(seg); i += dmerStride {
		score += freq[string(seg[i:i+dmerSize])]
	}
	return score
}
