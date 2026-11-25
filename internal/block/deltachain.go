package block

import (
	"archive/tar"
	"crypto/sha256"
	"io"
	"os"
	"path"
	"strings"
	"unicode"

	"github.com/Batman-Priv/maxzip/internal/delta"
	"github.com/Batman-Priv/maxzip/internal/fsutil"
)

const (
	
	PAXChain = "MAXZIP.chain"
	
	PAXDelta = "MAXZIP.delta"
)

const (
	
	DefaultDeltaMax = int64(32) << 20
	
	HardDeltaMax = int64(256) << 20

	minDeltaFile = 1024
	
	deltaAcceptNum, deltaAcceptDen = 8, 10
)

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
