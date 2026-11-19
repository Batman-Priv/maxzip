
package dictionary

import (
	"os"
	"sort"
)

const (
	maxDictSize   = 24 * 1024  
	dmerSize      = 8          
	segmentSize   = 1024       
	segmentStride = 512        
	dmerStride    = 8          
	sampleCap     = 512 * 1024 
)

type candidate struct {
	data  []byte
	score int
}

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

	freq := map[string]int{}
	for _, s := range samples {
		for i := 0; i+dmerSize <= len(s); i += dmerSize {
			freq[string(s[i:i+dmerSize])]++
		}
	}

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
