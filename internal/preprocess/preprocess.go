
package preprocess

import "io"

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
