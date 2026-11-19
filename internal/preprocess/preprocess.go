// Package preprocess implements optional, exactly-invertible byte
// transforms applied before compression. Currently just one: a byte-wise
// delta filter.
//
// This is intentionally the simplest possible preprocessor, chosen because
// its correctness is trivial to verify by inspection - there is no edge
// case, no format-specific parsing, nothing that can silently produce the
// wrong answer. More ambitious preprocessors (numeric delta transforms
// tied to a specific data layout, executable filters like BCJ, CSV
// column-aware transforms) are NOT implemented - they require real
// format-specific knowledge to get exactly right, and a bug in one of
// those really can silently corrupt data in a way this simple filter
// cannot.
//
// Regardless, every file using this filter is still verified by its
// stored SHA-256 on extraction (internal/archive does this unconditionally
// for preprocessed files, even if -no-verify was passed) - so even a
// hypothetical bug here would surface as a loud "integrity check failed"
// error, never as silently wrong output.
package preprocess

import "io"

// DeltaEncodeReader wraps r, turning each byte into its difference (mod
// 256) from the previous *original* byte. Streaming, O(1) extra memory.
type DeltaEncodeReader struct {
	r    io.Reader
	prev byte
}

func NewDeltaEncodeReader(r io.Reader) *DeltaEncodeReader {
	return &DeltaEncodeReader{r: r}
}

func (e *DeltaEncodeReader) Read(p []byte) (int, error) {
	n, err := e.r.Read(p)
	for i := 0; i < n; i++ {
		cur := p[i]
		p[i] = cur - e.prev
		e.prev = cur
	}
	return n, err
}

// DeltaDecodeReader reverses DeltaEncodeReader.
type DeltaDecodeReader struct {
	r    io.Reader
	prev byte
}

func NewDeltaDecodeReader(r io.Reader) *DeltaDecodeReader {
	return &DeltaDecodeReader{r: r}
}

func (d *DeltaDecodeReader) Read(p []byte) (int, error) {
	n, err := d.r.Read(p)
	for i := 0; i < n; i++ {
		v := p[i] + d.prev
		p[i] = v
		d.prev = v
	}
	return n, err
}
