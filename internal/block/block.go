// Package block implements the "solid block" architecture used by normal
// (non-dedup) archives: files are grouped into blocks of roughly targetSize
// bytes and compressed as one shared stream per block, so blocks keep most
// of the ratio benefit of a fully solid archive while staying independent
// (parallel to build, corruption-isolated, individually extractable).
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

	// LikelyIncompressible is a hint (from extension/magic-byte detection)
	// that this group probably won't compress well. It no longer skips
	// compression outright - the caller (internal/archive) always tries
	// real compression and only falls back to storing raw if it genuinely
	// didn't help - but it's used to run a cheap fast-codec probe first
	// instead of jumping straight to a possibly slow algorithm, so a
	// folder of movies doesn't waste minutes on xz just to learn what a
	// one-second zstd-fastest pass would already have shown.
	LikelyIncompressible bool
}

// PlanBlocks groups files by extension for solid-compression locality, and
// separately flags a "likely incompressible" pool (from smart's
// extension/magic-byte detection) so the caller can probe it cheaply before
// committing to full compression. Every plan gets the real chosen
// algorithm now - smart mode no longer forces Store outright, since that
// was the actual bug: some "incompressible" formats (an APK's suboptimally
// compressed DEFLATE streams, a JPEG's headers/Huffman tables) genuinely do
// have a few percent of slack that only shows up if you actually try.
//
// incompTarget is the target block size for the "likely incompressible" pool
// only (video, audio, archives...). Those files gain almost nothing from
// solid compression, so there is no ratio reason to make huge blocks - and a
// huge block can only be compressed by ONE thread, which is why a folder of
// a few videos used to take minutes while the other CPU cores sat idle.
// 0 means "same as targetSize".
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
		// Symlinks have no content of their own to test or compress (they're
		// just a name+target pair in the tar stream) - always treat them as
		// "compressible" so they land in the normal pool; it costs nothing
		// either way since there's no data block behind them.
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

// groupByExtThenPack groups files by extension before bin-packing, so
// similar file types (all the .json files, all the .log files, ...) tend to
// land in the same solid block instead of being interleaved in alphabetical
// path order. Solid compressors do better on runs of similar content than
// on a shuffle of unrelated formats, so this usually improves ratio a bit
// at the cost of slightly more blocks (one leftover partial block per
// extension instead of one for the whole set).
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

// binPack greedily accumulates files up to targetSize bytes per group. A
// single file larger than targetSize simply becomes its own group.
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

// Build streams every file in the block straight from disk, through
// tar -> compress -> (optional) encrypt, into a temp file - never holding a
// whole file's bytes in memory (only the small internal buffers io.Copy and
// the compressor use). dict is only used (and only helps) with zstd. When
// applyPreprocess is true, each file's bytes are delta-filtered (see
// internal/preprocess) before entering the tar stream; this is recorded
// per-file via a tar PAX record so extraction knows to reverse it.
// aad is mixed into every encrypted chunk (see cryptoutil) so the block can
// only be decrypted in the position it was written for; it is ignored when
// aead is nil.
// Hooks carries optional, non-format knobs for Build.
//   - OnRead is called with the number of ORIGINAL bytes consumed so far
//     (incrementally, while files are being read) so a progress bar can move
//     during a long compression. Build guarantees the calls add up to exactly
//     the block's total input size on success. nil = no reporting (used for
//     throw-away probe passes).
//   - Threads is the encoder's internal concurrency (only zstd uses it);
//     values < 1 mean 1.
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

	// Dictionary support: prepend the shared dictionary bytes directly to
	// this block's compressed stream (zstd only - see compressor.NewWriter's
	// comment for why we don't use the library's dictionary API). The
	// compressor can reference these bytes like any other earlier content
	// in the same stream; the decoder skips exactly this many bytes after
	// decompressing before parsing tar content (see archive.openBlockTar).
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
	// File-level delta chains (-delta). Mutually exclusive with the
	// byte-delta preprocessor, which already transforms every file.
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
	// Paths that don't stream through addFileToTar (delta chains, BCJ) are
	// not counted incrementally; top up so the totals always add up exactly.
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

// addFileToTar streams one file into the tar writer, hashing the ORIGINAL
// bytes (before any preprocessing) so FileMeta.SHA always verifies the
// real file content regardless of what transform was applied in between.
// addFileToTar writes one regular file or symlink into the tar stream.
// Symlinks store their target as a native tar TypeSymlink entry - no
// content to copy, no preprocessing applies. FileMeta.SHA for a symlink is
// the hash of its target string, so extraction can still verify it.
// Preprocess modes understood by Build and recorded per file in the tar
// entry (PAX record PAXPreprocess): "" (none), "delta" (byte-delta filter on
// every file) and "bcj" (x86 call/jump filter on x86 executables only).
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
	// Hashing happens inside this TeeReader on the ORIGINAL bytes as they
	// come off disk; the delta encoder (if enabled) wraps that and only
	// transforms the bytes AFTER they've already been hashed, so
	// FileMeta.SHA is always a hash of the real file content, never of the
	// transformed stream.
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

// addBCJFile stores an x86 executable run through the BCJ filter. ok is
// false (and nothing was written) when the file isn't an x86 executable, so
// the caller stores it normally. The SHA returned is of the ORIGINAL bytes.
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
