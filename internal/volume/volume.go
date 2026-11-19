// Package volume splits an archive's raw byte stream into fixed-size
// volumes and reassembles them transparently for reading.
package volume

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

// ParseSize parses human sizes like "500MB", "4GB", "128KB" (binary,
// 1024-based). An empty string returns 0 (meaning "no limit").
func ParseSize(s string) (int64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, nil
	}
	upper := strings.ToUpper(s)
	mult := int64(1)
	numPart := upper
	switch {
	case strings.HasSuffix(upper, "GB"):
		mult = 1 << 30
		numPart = strings.TrimSuffix(upper, "GB")
	case strings.HasSuffix(upper, "MB"):
		mult = 1 << 20
		numPart = strings.TrimSuffix(upper, "MB")
	case strings.HasSuffix(upper, "KB"):
		mult = 1 << 10
		numPart = strings.TrimSuffix(upper, "KB")
	case strings.HasSuffix(upper, "B"):
		mult = 1
		numPart = strings.TrimSuffix(upper, "B")
	}
	numPart = strings.TrimSpace(numPart)
	val, err := strconv.ParseFloat(numPart, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid size %q (expected e.g. 500MB, 2GB, 128KB)", s)
	}
	if val <= 0 {
		return 0, fmt.Errorf("size must be positive: %q", s)
	}
	return int64(val * float64(mult)), nil
}

// SplitWriter writes a single logical byte stream across one or more
// physical files, cutting at an exact byte count. It operates purely on raw
// bytes - never on "logical units" like blocks or headers - so the split
// point can never drift or land on a half-written structure.
type SplitWriter struct {
	basePath string
	maxPart  int64 // 0 = never split
	partIdx  int
	cur      *os.File
	curSize  int64
	total    int64
}

func NewSplitWriter(basePath string, maxPart int64) (*SplitWriter, error) {
	sw := &SplitWriter{basePath: basePath, maxPart: maxPart}
	if err := sw.openNext(); err != nil {
		return nil, err
	}
	return sw, nil
}

func (s *SplitWriter) partPath() string {
	if s.maxPart <= 0 {
		return s.basePath
	}
	return fmt.Sprintf("%s.%03d", s.basePath, s.partIdx+1)
}

func (s *SplitWriter) openNext() error {
	if s.cur != nil {
		if err := s.cur.Close(); err != nil {
			return err
		}
	}
	f, err := os.Create(s.partPath())
	if err != nil {
		return err
	}
	s.cur = f
	s.curSize = 0
	s.partIdx++
	return nil
}

func (s *SplitWriter) Write(p []byte) (int, error) {
	written := 0
	for len(p) > 0 {
		if s.maxPart > 0 && s.curSize >= s.maxPart {
			if err := s.openNext(); err != nil {
				return written, err
			}
		}
		n := len(p)
		if s.maxPart > 0 {
			remain := s.maxPart - s.curSize
			if int64(n) > remain {
				n = int(remain)
			}
		}
		wn, err := s.cur.Write(p[:n])
		written += wn
		s.curSize += int64(wn)
		s.total += int64(wn)
		p = p[wn:]
		if err != nil {
			return written, err
		}
	}
	return written, nil
}

// Written reports the current logical offset - used as the "absolute
// offset" stored in block indexes, regardless of how many physical volume
// files that offset actually spans across.
func (s *SplitWriter) Written() int64 { return s.total }

func (s *SplitWriter) Close() error {
	if s.cur != nil {
		return s.cur.Close()
	}
	return nil
}

// MultiPartReader presents one or more volume files as a single seekable
// logical stream (io.ReadSeeker).
type MultiPartReader struct {
	paths  []string
	sizes  []int64
	starts []int64
	total  int64

	curIdx int
	curF   *os.File
	pos    int64
}

// OpenArchiveParts figures out whether path is a single-file archive or the
// first volume of a split archive (by checking for path.001, .002, ...).
func OpenArchiveParts(path string) (*MultiPartReader, error) {
	if fi, err := os.Stat(path); err == nil {
		return &MultiPartReader{
			paths: []string{path}, sizes: []int64{fi.Size()}, starts: []int64{0},
			total: fi.Size(), curIdx: -1,
		}, nil
	}

	var paths []string
	var sizes []int64
	var starts []int64
	var running int64
	for i := 1; ; i++ {
		p := fmt.Sprintf("%s.%03d", path, i)
		fi, err := os.Stat(p)
		if err != nil {
			break
		}
		paths = append(paths, p)
		sizes = append(sizes, fi.Size())
		starts = append(starts, running)
		running += fi.Size()
	}
	if len(paths) == 0 {
		return nil, fmt.Errorf("archive not found: %s (also checked for %s.001 volumes)", path, path)
	}
	return &MultiPartReader{paths: paths, sizes: sizes, starts: starts, total: running, curIdx: -1}, nil
}

func (m *MultiPartReader) openPart(idx int) error {
	if m.curF != nil {
		if err := m.curF.Close(); err != nil {
			return err
		}
	}
	f, err := os.Open(m.paths[idx])
	if err != nil {
		return err
	}
	m.curF = f
	m.curIdx = idx
	return nil
}

func (m *MultiPartReader) partIndexFor(offset int64) int {
	for i := len(m.starts) - 1; i >= 0; i-- {
		if offset >= m.starts[i] {
			return i
		}
	}
	return 0
}

func (m *MultiPartReader) Seek(offset int64, whence int) (int64, error) {
	var target int64
	switch whence {
	case io.SeekStart:
		target = offset
	case io.SeekCurrent:
		target = m.pos + offset
	case io.SeekEnd:
		target = m.total + offset
	default:
		return 0, fmt.Errorf("invalid whence")
	}
	if target < 0 || target > m.total {
		return 0, fmt.Errorf("seek out of range (offset %d, archive size %d)", target, m.total)
	}
	idx := m.partIndexFor(target)
	if idx >= len(m.paths) {
		idx = len(m.paths) - 1
	}
	if idx != m.curIdx {
		if err := m.openPart(idx); err != nil {
			return 0, err
		}
	}
	local := target - m.starts[idx]
	if _, err := m.curF.Seek(local, io.SeekStart); err != nil {
		return 0, err
	}
	m.pos = target
	return target, nil
}

func (m *MultiPartReader) Read(p []byte) (int, error) {
	if m.curIdx == -1 {
		if err := m.openPart(0); err != nil {
			return 0, err
		}
	}
	total := 0
	for total < len(p) {
		n, err := m.curF.Read(p[total:])
		total += n
		m.pos += int64(n)
		if err == io.EOF {
			if m.curIdx+1 < len(m.paths) {
				if oerr := m.openPart(m.curIdx + 1); oerr != nil {
					return total, oerr
				}
				continue
			}
			if total > 0 {
				return total, nil
			}
			return total, io.EOF
		}
		if err != nil {
			return total, err
		}
		if n == 0 {
			break
		}
	}
	return total, nil
}

// Size is the total logical size of the archive across all volumes.
func (m *MultiPartReader) Size() int64 { return m.total }

func (m *MultiPartReader) Close() error {
	if m.curF != nil {
		return m.curF.Close()
	}
	return nil
}
