package block

import (
	"archive/tar"
	"crypto/sha256"
	"io"
	"os"
	"path"
	"strings"
	"unicode"

	"gitlab.com/specterog/maxzip/internal/delta"
	"gitlab.com/specterog/maxzip/internal/fsutil"
)

// PAX record names used for delta chains inside a block's tar stream.
const (
	// PAXChain marks a file that takes part in a delta chain; the value is
	// the chain key. The extractor keeps the latest member of each chain in
	// memory so the next one can be rebuilt from it.
	PAXChain = "MAXZIP.chain"
	// PAXDelta marks a chain member stored as a delta; the value is the
	// archive name of the reference (always the previous chain member). The
	// tar entry's content is then a delta.Marshal blob, not the file.
	PAXDelta = "MAXZIP.delta"
)

// Delta mode tuning.
const (
	// DefaultDeltaMax is the largest file considered for delta chains: both
	// the file and its reference are held in memory while diffing.
	DefaultDeltaMax = int64(32) << 20
	// HardDeltaMax is what an extractor will ever accept, whatever a
	// crafted archive claims.
	HardDeltaMax = int64(256) << 20

	minDeltaFile = 1024
	// A delta must be at least this much smaller than the file to be used.
	deltaAcceptNum, deltaAcceptDen = 8, 10
)

// chainKey groups files that are plausibly versions of one another: same
// extension and the same letters in the name once digits, spaces and
// punctuation are dropped ("report_v1.docx", "Report v2 (copy).docx", and
// "2024/report-final3.docx" all share a key). It is only a hint - a delta
// is kept only when it actually comes out smaller.
func chainKey(rel string) string {
	base := path.Base(rel)
	ext := strings.ToLower(path.Ext(base))
	stem := strings.TrimSuffix(base, path.Ext(base))
	var b strings.Builder
	for _, r := range strings.ToLower(stem) {
		if unicode.IsLetter(r) {
			b.WriteRune(r)
		}
	}
	return b.String() + ext
}

type chainMember struct {
	name string
	data []byte
}

// deltaChains tracks, per chain key, the latest member written to the
// current block so the next similar file can be diffed against it.
type deltaChains struct {
	maxSize int64
	latest  map[string]chainMember
}

func newDeltaChains(maxSize int64) *deltaChains {
	if maxSize <= 0 {
		return nil
	}
	if maxSize > HardDeltaMax {
		maxSize = HardDeltaMax
	}
	return &deltaChains{maxSize: maxSize, latest: map[string]chainMember{}}
}

func (d *deltaChains) eligible(fe fsutil.FileRef) bool {
	return d != nil && !fe.IsSymlink && fe.Size >= minDeltaFile && fe.Size <= d.maxSize
}

// addChainFile writes one chain-eligible file: as a delta against the
// previous member of its chain when that is clearly smaller, otherwise in
// full (still tagged as a chain member so a later file can use it).
func (d *deltaChains) addChainFile(tw *tar.Writer, fe fsutil.FileRef) ([32]byte, error) {
	var sum [32]byte
	data, err := os.ReadFile(fe.Abs)
	if err != nil {
		return sum, err
	}
	sum = sha256.Sum256(data)
	key := chainKey(fe.Rel)

	hdr := &tar.Header{
		Name: fe.Rel, Size: int64(len(data)),
		Mode: int64(fe.Mode.Perm()), ModTime: fe.ModTime,
		PAXRecords: map[string]string{PAXChain: key},
	}
	content := data
	if prev, ok := d.latest[key]; ok {
		blob := delta.Marshal(delta.Encode(prev.data, data, delta.DefaultBlockSize))
		if int64(len(blob))*deltaAcceptDen <= int64(len(data))*deltaAcceptNum {
			hdr.PAXRecords[PAXDelta] = prev.name
			hdr.Size = int64(len(blob))
			content = blob
		}
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return sum, err
	}
	if _, err := io.Copy(tw, bytesReader(content)); err != nil {
		return sum, err
	}
	d.latest[key] = chainMember{name: fe.Rel, data: data}
	return sum, nil
}
