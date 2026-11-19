
package progress

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Bar struct {
	label   string
	total   int64
	done    int64
	stop    chan struct{}
	stopped chan struct{}
	once    sync.Once
	start   time.Time
}

func New(total int64, label string) *Bar {
	return &Bar{label: label, total: total, stop: make(chan struct{}), stopped: make(chan struct{}), start: time.Now()}
}

func (b *Bar) Add(n int64) {
	if b == nil {
		return
	}
	atomic.AddInt64(&b.done, n)
}

func (b *Bar) Complete() {
	if b == nil {
		return
	}
	if rest := b.total - atomic.LoadInt64(&b.done); rest > 0 {
		atomic.AddInt64(&b.done, rest)
	}
}

func (b *Bar) Wrap(r io.Reader) io.Reader {
	if b == nil {
		return r
	}
	return &countReader{r: r, fn: b.Add}
}

func CountReader(r io.Reader, fn func(int64)) io.Reader {
	if fn == nil {
		return r
	}
	return &countReader{r: r, fn: fn}
}

type countReader struct {
	r  io.Reader
	fn func(int64)
}

func (c *countReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	if n > 0 {
		c.fn(int64(n))
	}
	return n, err
}

func (b *Bar) Start() {
	if b == nil {
		return
	}
	go func() {
		ticker := time.NewTicker(150 * time.Millisecond)
		defer ticker.Stop()
		defer close(b.stopped)
		for {
			select {
			case <-ticker.C:
				b.render()
			case <-b.stop:
				return
			}
		}
	}()
}

func (b *Bar) Finish() {
	if b == nil {
		return
	}
	b.once.Do(func() {
		close(b.stop)
		<-b.stopped
		b.render()
		fmt.Fprintln(os.Stderr)
	})
}

func (b *Bar) render() {
	done := atomic.LoadInt64(&b.done)
	total := b.total
	if total < 0 {
		total = 0
	}
	if done > total {
		done = total
	}
	pct := 0.0
	if total > 0 {
		pct = float64(done) / float64(total) * 100
	}
	const width = 30
	filled := int(pct / 100 * width)
	if filled > width {
		filled = width
	}
	if filled < 0 {
		filled = 0
	}
	bar := strings.Repeat("=", filled) + strings.Repeat("-", width-filled)
	extra := ""
	if el := time.Since(b.start).Seconds(); el >= 1 && done > 0 {
		speed := float64(done) / el
		extra = fmt.Sprintf("  %s/s", humanBytes(int64(speed)))
		if total > done {
			eta := time.Duration(float64(total-done)/speed) * time.Second
			extra += fmt.Sprintf("  ETA %s", eta.Round(time.Second))
		}
	}
	fmt.Fprintf(os.Stderr, "\r%s [%s] %5.1f%%  %s / %s%s   ", b.label, bar, pct, humanBytes(done), humanBytes(total), extra)
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%dB", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	units := "KMGTPE"
	return fmt.Sprintf("%.1f%ciB", float64(n)/float64(div), units[exp])
}
