
package block

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gitlab.com/specterog/maxzip/internal/compressor"
	"gitlab.com/specterog/maxzip/internal/cryptoutil"
	"gitlab.com/specterog/maxzip/internal/fsutil"
	"gitlab.com/specterog/maxzip/internal/preprocess"
	"gitlab.com/specterog/maxzip/internal/progress"
	"gitlab.com/specterog/maxzip/internal/smart"
)

type FileMeta struct {
	Name     string
	OrigSize int64
	SHA      [32]byte
}

type Meta struct {
	Files      []FileMeta
	TempPath   string
	PayloadLen int64
	SHA        [32]byte
}

type Plan struct {
	Files []fsutil.FileRef
	Algo  compressor.Algo

	LikelyIncompressible bool
}

func PlanBlocks(files []fsutil.FileRef, algo compressor.Algo, smartMode smart.Mode, targetSize, incompTarget int64) []Plan {
	if incompTarget <= 0 || incompTarget > targetSize {
		incompTarget = targetSize
	}
	if smartMode == smart.Off {
		var plans []Plan
		for _, grp := range groupByExtThenPack(files, targetSize) {
			plans = append(plans, Plan{Files: grp, Algo: algo})
		}
		return plans
	}

	var compressible, likelyIncompressible []fsutil.FileRef
	for _, fe := range files {
		
		if !fe.IsSymlink && smart.IsStore(fe, smartMode) {
			likelyIncompressible = append(likelyIncompressible, fe)
		} else {
			compressible = append(compressible, fe)
		}
	}

	var plans []Plan
	for _, grp := range groupByExtThenPack(compressible, targetSize) {
		plans = append(plans, Plan{Files: grp, Algo: algo})
	}
	for _, grp := range binPack(likelyIncompressible, incompTarget) {
		plans = append(plans, Plan{Files: grp, Algo: algo, LikelyIncompressible: true})
	}
	return plans
}

func groupByExtThenPack(files []fsutil.FileRef, targetSize int64) [][]fsutil.FileRef {
	byExt := map[string][]fsutil.FileRef{}
	var extOrder []string
	for _, fe := range files {
		ext := strings.ToLower(filepath.Ext(fe.Rel))
		if _, ok := byExt[ext]; !ok {
			extOrder = append(extOrder, ext)
		}
		byExt[ext] = append(byExt[ext], fe)
	}
	sort.Strings(extOrder)

	var blocks [][]fsutil.FileRef
	for _, ext := range extOrder {
		blocks = append(blocks, binPack(byExt[ext], targetSize)...)
	}
	return blocks
}

func binPack(files []fsutil.FileRef, targetSize int64) [][]fsutil.FileRef {
	var blocks [][]fsutil.FileRef
	var cur []fsutil.FileRef
	var curSize int64
	for _, fe := range files {
		if len(cur) > 0 && curSize+fe.Size > targetSize {
			blocks = append(blocks, cur)
			cur = nil
			curSize = 0
		}
		cur = append(cur, fe)
		curSize += fe.Size
	}
	if len(cur) > 0 {
		blocks = append(blocks, cur)
	}
	return blocks
}

type nopWC struct{ io.Writer }

func (nopWC) Close() error { return nil }

type Hooks struct {
	OnRead  func(int64)
	Threads int
}

func Build(files []fsutil.FileRef, algo compressor.Algo, level string, aead *cryptoutil.Cipher, aad []byte, dict []byte, preprocessMode string, deltaMax int64, hooks Hooks) (m *Meta, err error) {
	tmp, err := os.CreateTemp("", "maxzip-block-*")
	if err != nil {
		return nil, err
	}
	tmpPath := tmp.Name()
	defer func() {
		if err != nil {
			tmp.Close()
			os.Remove(tmpPath)
		}
	}()

	hasher := sha256.New()
	hw := io.MultiWriter(tmp, hasher)

	var finalWriter io.WriteCloser = nopWC{hw}
	if aead != nil {
		ew, ferr := cryptoutil.NewEncryptWriter(hw, aead, aad)
		if ferr != nil {
			return nil, ferr
		}
		finalWriter = ew
	}

	encThreads := hooks.Threads
	if encThreads < 1 {
		encThreads = 1
	}
	cw, err := compressor.NewWriter(finalWriter, algo, level, encThreads)
	if err != nil {
		return nil, err
	}

	if algo == compressor.Zstd && len(dict) > 0 {
		if _, err := cw.Write(dict); err != nil {
			return nil, err
		}
	}

	tw := tar.NewWriter(cw)
	meta := &Meta{TempPath: tmpPath}

	var reported, totalIn int64
	for _, fe := range files {
		if !fe.IsSymlink {
			totalIn += fe.Size
		}
	}
	report := func(n int64) {
		reported += n
		if hooks.OnRead != nil {
			hooks.OnRead(n)
		}
	}
	
	var chains *deltaChains
	if preprocessMode == "" {
		chains = newDeltaChains(deltaMax)
	}
	for _, fe := range files {
		var sum [32]byte
		var ferr error
		if chains.eligible(fe) {
			sum, ferr = chains.addChainFile(tw, fe)
		} else {
			sum, ferr = addFileToTar(tw, fe, preprocessMode, report)
		}
		if ferr != nil {
			return nil, ferr
		}
		meta.Files = append(meta.Files, FileMeta{Name: fe.Rel, OrigSize: fe.Size, SHA: sum})
	}
	
	if rest := totalIn - reported; rest > 0 {
		report(rest)
	}
	if err = tw.Close(); err != nil {
		return nil, err
	}
	if err = cw.Close(); err != nil {
		return nil, err
	}
	if err = finalWriter.Close(); err != nil {
		return nil, err
	}
	if err = tmp.Close(); err != nil {
		return nil, err
	}

	copy(meta.SHA[:], hasher.Sum(nil))
	fi, statErr := os.Stat(tmpPath)
	if statErr != nil {
		return nil, statErr
	}
	meta.PayloadLen = fi.Size()
	return meta, nil
}

const PAXPreprocess = "MAXZIP.preprocess"

func addFileToTar(tw *tar.Writer, fe fsutil.FileRef, mode string, report func(int64)) ([32]byte, error) {
	var sum [32]byte

	if fe.IsSymlink {
		hdr := &tar.Header{
			Typeflag: tar.TypeSymlink,
			Name:     fe.Rel,
			Linkname: fe.LinkTarget,
			Mode:     int64(fe.Mode.Perm()),
			ModTime:  fe.ModTime,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return sum, err
		}
		copy(sum[:], sha256Sum([]byte(fe.LinkTarget)))
		return sum, nil
	}

	if mode == "bcj" && fe.Size >= 64 && fe.Size <= preprocess.MaxBCJSize {
		if s, ok, err := addBCJFile(tw, fe); ok || err != nil {
			return s, err
		}
	}

	f, err := os.Open(fe.Abs)
	if err != nil {
		return sum, err
	}
	defer f.Close()

	hdr := &tar.Header{
		Name:    fe.Rel,
		Size:    fe.Size,
		Mode:    int64(fe.Mode.Perm()),
		ModTime: fe.ModTime,
	}
	if mode == "delta" {
		hdr.PAXRecords = map[string]string{PAXPreprocess: "delta"}
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return sum, err
	}

	hasher := sha256.New()
	
	var src io.Reader = progress.CountReader(io.TeeReader(f, hasher), report)
	if mode == "delta" {
		src = preprocess.NewDeltaEncodeReader(src)
	}
	if _, err := io.Copy(tw, src); err != nil {
		return sum, err
	}
	copy(sum[:], hasher.Sum(nil))
	return sum, nil
}

func sha256Sum(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}

func bytesReader(b []byte) io.Reader { return bytes.NewReader(b) }

func addBCJFile(tw *tar.Writer, fe fsutil.FileRef) (sum [32]byte, ok bool, err error) {
	data, err := os.ReadFile(fe.Abs)
	if err != nil {
		return sum, false, err
	}
	if len(data) < 64 || !preprocess.LooksLikeX86Executable(data[:64]) {
		return sum, false, nil
	}
	sum = sha256.Sum256(data)
	preprocess.BCJEncode(data)
	hdr := &tar.Header{
		Name: fe.Rel, Size: int64(len(data)),
		Mode: int64(fe.Mode.Perm()), ModTime: fe.ModTime,
		PAXRecords: map[string]string{PAXPreprocess: "bcj"},
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return sum, true, err
	}
	if _, err := tw.Write(data); err != nil {
		return sum, true, err
	}
	return sum, true, nil
}
