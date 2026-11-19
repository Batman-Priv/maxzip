// Package archive orchestrates every other internal package into the
// actual pack/unpack pipeline.
//
// A normal archive has two kinds of content, both always present in the
// footer (possibly empty):
//   - "blocks": ordinary files (and symlinks) grouped into solid tar
//     blocks (internal/block)
//   - "chunked": content-defined chunks, deduplicated globally
//     (internal/dedup) - used for every regular file in -dedup mode, and
//     automatically for any single file larger than -big-file-threshold
//     even without -dedup, so one huge file doesn't become one giant
//     unparallelizable, memory-heavy block
//
// -dedup mode still uses the "blocks" section for any symlinks (a chunked
// block holds raw content chunks, not tar entries, and a symlink has no
// content of its own to chunk) - so both modes share exactly the same
// footer shape, just with different proportions of each section.
package archive

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"gitlab.com/specterog/maxzip/internal/block"
	"gitlab.com/specterog/maxzip/internal/compressor"
	"gitlab.com/specterog/maxzip/internal/cryptoutil"
	"gitlab.com/specterog/maxzip/internal/dedup"
	"gitlab.com/specterog/maxzip/internal/dictionary"
	"gitlab.com/specterog/maxzip/internal/format"
	"gitlab.com/specterog/maxzip/internal/fsutil"
	"gitlab.com/specterog/maxzip/internal/progress"
	"gitlab.com/specterog/maxzip/internal/smart"
	"gitlab.com/specterog/maxzip/internal/ui"
	"gitlab.com/specterog/maxzip/internal/volume"
)

type PackOptions struct {
	Inputs     []string // files, directories, and/or glob patterns like "*.pdf"
	Output     string
	Algo       compressor.Algo
	Level      string
	Optimize   string // for -algo auto: "size" | "speed" | "balanced"
	Password   string
	Smart      smart.Mode
	Dict       string // "off" | "auto"
	Dedup      bool
	DedupChunk int64 // target average chunk size in bytes
	Threads    int
	Exclude    []string
	BlockSize  int64
	SplitBytes int64

	// BigFileThreshold: in normal (non-dedup) mode, any single file larger
	// than this is automatically routed through chunked storage instead of
	// becoming one big solid block. 0 means "off" (never auto-split) -
	// this only happens if you set it explicitly.
	BigFileThreshold int64

	// Preprocess: "off", "delta" or "bcj". "delta": every file's bytes are
	// byte-wise delta-filtered before compression. "bcj": x86 ELF/PE
	// executables get their CALL/JMP operands made absolute (see
	// internal/preprocess); other files are untouched. Normal
	// (non-dedup) mode only.
	// Files using it are always SHA-256-verified on extraction regardless
	// of -no-verify, since a bug here would otherwise only be caught if
	// verification happened to still be on.
	Preprocess string

	// Comment is optional free-text metadata stored in the archive header,
	// always in plaintext even for encrypted archives (like a zip/rar
	// comment) - read it back with `maxzip comment -i <archive>`, no
	// password needed.
	Comment string

	// Delta enables file-level delta chains: inside a solid block, a file
	// that looks like another version of an earlier file in the same block
	// (see block.chainKey) is stored as a binary diff against it when that
	// is clearly smaller. Normal (non-dedup) mode only; ignored together
	// with Preprocess "delta". DeltaMax is the largest file considered
	// (0 = block.DefaultDeltaMax).
	Delta    bool
	DeltaMax int64

	Verbose bool // print per-block/per-file detail in addition to the progress bar
}

func (o PackOptions) deltaMax() int64 {
	if !o.Delta || o.Dedup {
		return 0
	}
	if o.DeltaMax > 0 {
		return o.DeltaMax
	}
	return block.DefaultDeltaMax
}

func Pack(opt PackOptions) error {
	files, emptyDirs, err := fsutil.CollectFilesMulti(opt.Inputs, opt.Exclude)
	if err != nil {
		return err
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Rel < files[j].Rel })

	// Chunked storage (-dedup and automatic big-file splitting) has no
	// place to put a symlink - it stores raw content chunks, not tar
	// entries, and a symlink has no content of its own. Symlinks always go
	// through the normal solid-block (tar) path instead; in -dedup mode
	// specifically, that means routing them out before chunking even
	// though the rest of the archive is chunked.
	var symlinks []fsutil.FileRef
	if opt.Dedup {
		var rest []fsutil.FileRef
		for _, fe := range files {
			if fe.IsSymlink {
				symlinks = append(symlinks, fe)
			} else {
				rest = append(rest, fe)
			}
		}
		files = rest
	}

	algo := opt.Algo
	if algo == compressor.Auto {
		algo, err = resolveAutoAlgo(files, opt.Level, opt.Optimize)
		if err != nil {
			return err
		}
	}

	var dict []byte
	if opt.Dict == "auto" && algo == compressor.Zstd && !opt.Dedup {
		// Dict is scoped to normal solid tar-blocks only - see
		// dedup.BlockBuilder's doc comment for why chunked storage (both
		// -dedup and automatic big-file chunking) can't use it safely.
		paths := make([]string, len(files))
		for i, f := range files {
			paths[i] = f.Abs
		}
		if d, derr := dictionary.BuildRaw(paths); derr == nil {
			dict = d
		}
	}

	flags := (byte(algo) & format.AlgoMask) << format.AlgoShift
	if opt.Dedup {
		flags |= format.FlagDedup
	}
	if len(dict) > 0 {
		flags |= format.FlagDict
	}
	if opt.Comment != "" {
		flags |= format.FlagComment
	}

	var aead *cryptoutil.Cipher
	var salt []byte
	kdf := cryptoutil.DefaultKDF
	if opt.Password != "" {
		flags |= format.FlagEncrypted
		salt = make([]byte, format.SaltSize)
		if _, err := rand.Read(salt); err != nil {
			return err
		}
		key, kerr := cryptoutil.DeriveKey(opt.Password, salt, kdf)
		if kerr != nil {
			return kerr
		}
		if aead, err = cryptoutil.NewCipher(key); err != nil {
			return err
		}
	}

	sw, err := volume.NewSplitWriter(opt.Output, opt.SplitBytes)
	if err != nil {
		return fmt.Errorf("create output: %w", err)
	}
	defer sw.Close()

	if err := format.WriteHeader(sw, format.Header{Flags: flags, Salt: salt, KDF: kdf, Dict: dict, Comment: opt.Comment}); err != nil {
		return err
	}

	var totalInputBytes int64
	for _, fe := range files {
		totalInputBytes += fe.Size
	}
	bar := progress.New(totalInputBytes, "packing  ")
	bar.Start()
	defer bar.Finish()

	if opt.Dedup {
		symBlockOffsets, symFooterFiles, symTotalOrig, err := packBlocks(sw, symlinks, opt, algo, nil, aead, bar)
		if err != nil {
			return err
		}
		chunkTable, blockOffsets, fileList, totalOrig, err := packChunked(sw, files, opt, algo, aead, bar)
		if err != nil {
			return err
		}
		bar.Complete()
		bar.Finish()
		return writeFooter(sw, aead, symBlockOffsets, symFooterFiles, chunkTable, blockOffsets, fileList, emptyDirs, symTotalOrig+totalOrig)
	}

	blockSize := opt.BlockSize
	if blockSize <= 0 {
		blockSize = 64 << 20
	}

	// Big-file chunking is opt-in only: it happens only if the user
	// explicitly set -big-file-threshold to a positive size. No default
	// threshold is applied - unset (0) means "never split a single file,
	// no matter how large", so behavior never changes under someone's feet.
	// Symlinks are never routed here (their Size is always 0).
	var normalFiles, bigFiles []fsutil.FileRef
	if opt.BigFileThreshold > 0 {
		for _, fe := range files {
			if fe.Size > opt.BigFileThreshold {
				bigFiles = append(bigFiles, fe)
			} else {
				normalFiles = append(normalFiles, fe)
			}
		}
	} else {
		normalFiles = files
	}

	blockOffsets, footerFiles, totalOrig1, err := packBlocks(sw, normalFiles, opt, algo, dict, aead, bar)
	if err != nil {
		return err
	}
	chunkTable, bigBlockOffsets, bigFiles2, totalOrig2, err := packChunked(sw, bigFiles, opt, algo, aead, bar)
	if err != nil {
		return err
	}

	bar.Complete()
	bar.Finish()
	return writeFooter(sw, aead, blockOffsets, footerFiles, chunkTable, bigBlockOffsets, bigFiles2, emptyDirs, totalOrig1+totalOrig2)
}

func resolveAutoAlgo(files []fsutil.FileRef, level, optimize string) (compressor.Algo, error) {
	var sample []byte
	for _, fe := range files {
		if fe.IsSymlink {
			continue
		}
		if len(sample) >= 2<<20 {
			break
		}
		f, err := os.Open(fe.Abs)
		if err != nil {
			continue
		}
		remain := (2 << 20) - len(sample)
		buf := make([]byte, remain)
		n, _ := io.ReadFull(f, buf)
		f.Close()
		sample = append(sample, buf[:n]...)
	}
	if len(sample) == 0 {
		return compressor.Zstd, nil
	}
	best, results := compressor.AutoSelect(sample, level, optimize)
	fmt.Printf("auto-select (%s): ", optimize)
	for a, r := range results {
		fmt.Printf("%s=%dB/%s ", a, r.Size, r.Duration.Round(time.Millisecond))
	}
	fmt.Printf("-> chosen %s\n", best)
	return best, nil
}

// ---------- normal mode: solid file blocks ----------

func packBlocks(sw *volume.SplitWriter, files []fsutil.FileRef, opt PackOptions, algo compressor.Algo, dict []byte, aead *cryptoutil.Cipher, bar *progress.Bar) (blockOffsets []int64, footerFiles []footerFileEntry, totalOrig int64, err error) {
	if len(files) == 0 {
		return nil, nil, 0, nil
	}

	blockSize := opt.BlockSize
	if blockSize <= 0 {
		blockSize = 64 << 20
	}
	threads := opt.Threads
	if threads <= 0 {
		threads = runtime.NumCPU()
	}

	// Incompressible media: use smaller blocks so all cores get work (a
	// single 64-128MB block is compressed by one thread only).
	var incompTotal int64
	for _, fe := range files {
		incompTotal += fe.Size
	}
	incompTarget := incompTotal / int64(threads)
	if incompTarget < 8<<20 {
		incompTarget = 8 << 20
	}
	plans := block.PlanBlocks(files, algo, opt.Smart, blockSize, incompTarget)

	// If there are fewer blocks than cores, lend the spare cores to the
	// encoder itself (zstd can use several threads inside one block).
	encThreads := 1
	if len(plans) > 0 && len(plans) < threads {
		encThreads = threads / len(plans)
	}

	metas := make([]*block.Meta, len(plans))
	dictUsed := make([]bool, len(plans))
	jobs := make(chan int, len(plans))
	var wg sync.WaitGroup
	var errMu sync.Mutex
	var buildErr error

	for w := 0; w < threads; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range jobs {
				m, usedAlgo, usedDict, ferr := buildBlockWithFallback(plans[idx], uint32(idx), opt, dict, aead, bar, encThreads)
				if ferr != nil {
					errMu.Lock()
					if buildErr == nil {
						buildErr = fmt.Errorf("block %d: %w", idx, ferr)
					}
					errMu.Unlock()
					continue
				}
				plans[idx].Algo = usedAlgo
				dictUsed[idx] = usedDict
				metas[idx] = m
			}
		}()
	}
	for i := range plans {
		jobs <- i
	}
	close(jobs)
	wg.Wait()

	if buildErr != nil {
		for _, m := range metas {
			if m != nil {
				os.Remove(m.TempPath)
			}
		}
		return nil, nil, 0, buildErr
	}

	for i, m := range metas {
		offset := sw.Written()
		blockOffsets = append(blockOffsets, offset)

		var uncompSize uint64
		for _, ff := range m.Files {
			uncompSize += uint64(ff.OrigSize)
		}

		if _, err := sw.Write([]byte("BLK0")); err != nil {
			return nil, nil, 0, err
		}
		if err := binary.Write(sw, binary.BigEndian, uint32(len(m.Files))); err != nil {
			return nil, nil, 0, err
		}
		if err := binary.Write(sw, binary.BigEndian, uncompSize); err != nil {
			return nil, nil, 0, err
		}
		if err := binary.Write(sw, binary.BigEndian, uint64(m.PayloadLen)); err != nil {
			return nil, nil, 0, err
		}
		if _, err := sw.Write(m.SHA[:]); err != nil {
			return nil, nil, 0, err
		}
		algoByte := byte(plans[i].Algo)
		if dictUsed[i] {
			algoByte |= blockFlagDict
		}
		if _, err := sw.Write([]byte{algoByte}); err != nil {
			return nil, nil, 0, err
		}
		if err := copyTempFile(sw, m.TempPath); err != nil {
			return nil, nil, 0, err
		}
		os.Remove(m.TempPath)

		for _, ff := range m.Files {
			footerFiles = append(footerFiles, footerFileEntry{
				name: ff.Name, blockIndex: uint32(i), origSize: uint64(ff.OrigSize), sha: ff.SHA,
			})
			totalOrig += ff.OrigSize
		}
		if opt.Verbose {
			fmt.Printf("block %d: %d files, %d -> %d bytes (%s)\n", i, len(m.Files), uncompSize, m.PayloadLen, plans[i].Algo)
		}
	}
	return blockOffsets, footerFiles, totalOrig, nil
}

// buildBlockWithFallback builds one block and guarantees the result is
// never larger than storing the files raw would be - the actual bug this
// fixes: smart mode used to guess "this won't compress" from extension/
// magic-bytes alone and skip compression outright, but real formats like
// APKs (often DEFLATE'd at a low level by build tools) and JPEGs (headers,
// suboptimal Huffman tables) frequently DO have a few percent of slack, and
// a real archiver only finds that by actually trying, the way RAR/7-Zip do.
//
// For blocks flagged LikelyIncompressible, a cheap zstd-fastest probe runs
// first: if even that shows negligible gain, it stores directly without
// ever running the (possibly much slower) chosen algorithm. Otherwise the
// real algorithm runs. If a dictionary is in play, the block is also built
// WITHOUT it and whichever result is smaller wins - a dictionary is just
// extra bytes prepended before compression (see block.Build), so on data
// that doesn't resemble it, it's pure overhead with nothing to show for
// it. Finally, if compression still didn't help at all, it falls back to
// storing raw. Returns the algorithm actually used, which the caller must
// record (it can differ from the plan's original algorithm).
func buildBlockWithFallback(plan block.Plan, idx uint32, opt PackOptions, dict []byte, aead *cryptoutil.Cipher, bar *progress.Bar, encThreads int) (*block.Meta, compressor.Algo, bool, error) {
	// Only the pass whose output is (normally) kept reports progress. Probe
	// passes, the "without dictionary" comparison pass and the final
	// "didn't help, store raw" pass are silent so the bar never overshoots
	// or runs backwards.
	silent := block.Hooks{Threads: encThreads}
	loud := block.Hooks{OnRead: bar.Add, Threads: encThreads}
	aad := blockAAD(idx)
	var uncomp int64
	for _, fe := range plan.Files {
		uncomp += fe.Size
	}
	preprocess := opt.Preprocess
	if preprocess == "off" {
		preprocess = ""
	}

	// The quick zstd-fastest probe is only a time-saver, and it is blind to
	// what a strong codec can still squeeze out of "incompressible" files
	// (JPEG/PNG/APK/DOCX typically give 2-5% with xz or brotli, which is
	// exactly the gap to RAR). So at -level better/best it is used only for
	// media that really never shrinks (video/audio); everything else gets
	// the real algorithm, and storing raw remains the fallback if even that
	// doesn't help (below).
	level := opt.Level
	strong := opt.Level == "best" || opt.Level == "better"
	if plan.LikelyIncompressible && (!strong || allTrulyIncompressible(plan.Files)) {
		probe, err := block.Build(plan.Files, compressor.Zstd, "fastest", aead, aad, nil, preprocess, opt.deltaMax(), silent)
		if err != nil {
			return nil, 0, false, err
		}
		if probe.PayloadLen >= uncomp*99/100 {
			os.Remove(probe.TempPath)
			m, err := block.Build(plan.Files, compressor.Store, opt.Level, aead, aad, nil, preprocess, opt.deltaMax(), loud)
			if err != nil {
				return nil, 0, false, err
			}
			return m, compressor.Store, false, nil
		}
		os.Remove(probe.TempPath) // discard the probe; the real pass redoes it below

		// Video/audio gains at most a couple of percent from ANY codec, but
		// xz/brotli at -level best run at ~1 MB/s in pure Go, so they turn
		// "a few percent" into minutes. Use zstd "better" for these blocks
		// instead (the block's algorithm is recorded per block, so the
		// archive stays valid).
		if allTrulyIncompressible(plan.Files) && (plan.Algo == compressor.XZ || plan.Algo == compressor.Brotli) {
			plan.Algo = compressor.Zstd
			level = "better"
		}
	}

	var d []byte
	droppedDict := false
	if plan.Algo == compressor.Zstd {
		d = dict
	}
	m, err := block.Build(plan.Files, plan.Algo, level, aead, aad, d, preprocess, opt.deltaMax(), loud)
	if err != nil {
		return nil, 0, false, err
	}

	if len(d) > 0 {
		mNoDict, err2 := block.Build(plan.Files, plan.Algo, level, aead, aad, nil, preprocess, opt.deltaMax(), silent)
		if err2 == nil {
			if mNoDict.PayloadLen < m.PayloadLen {
				os.Remove(m.TempPath)
				m = mNoDict
				droppedDict = true
			} else {
				os.Remove(mNoDict.TempPath)
			}
		}
	}

	if m.PayloadLen >= uncomp {
		os.Remove(m.TempPath)
		m2, err := block.Build(plan.Files, compressor.Store, opt.Level, aead, aad, nil, preprocess, opt.deltaMax(), silent)
		if err != nil {
			return nil, 0, false, err
		}
		return m2, compressor.Store, false, nil
	}
	return m, plan.Algo, len(d) > 0 && !droppedDict, nil
}

// ---------- chunked storage: shared by -dedup mode and automatic big-file handling ----------

// packChunked splits files into content-defined chunks, deduplicates
// identical chunks globally, and writes unique chunks into blocks. Files
// smart-mode would store raw go into a separate Store-algo block stream
// from files that get compressed, so a block's compressor stream stays
// consistent. Chunk discovery is inherently sequential (a chunk's
// uniqueness depends on every chunk seen before it), so this isn't
// parallelized the way packBlocks is. Never uses a shared dictionary - see
// dedup.BlockBuilder's doc comment for why.
func packChunked(sw *volume.SplitWriter, files []fsutil.FileRef, opt PackOptions, algo compressor.Algo, aead *cryptoutil.Cipher, bar *progress.Bar) (chunkTable []chunkEntry, blockOffsets []int64, fileList []dedupFileEntry, totalOrig int64, err error) {
	if len(files) == 0 {
		return nil, nil, nil, 0, nil
	}

	avg := opt.DedupChunk
	if avg <= 0 {
		avg = 256 * 1024
	}
	chunkOpt := dedup.NewChunkOptions(int(avg))

	blockSize := opt.BlockSize
	if blockSize <= 0 {
		blockSize = 64 << 20
	}

	compBuilder, err := dedup.NewBlockBuilder(algo, opt.Level, aead, aadChunkBlock, blockSize)
	if err != nil {
		return nil, nil, nil, 0, err
	}
	storeBuilder, err := dedup.NewBlockBuilder(compressor.Store, opt.Level, aead, aadChunkBlock, blockSize)
	if err != nil {
		return nil, nil, nil, 0, err
	}

	var compPending, storePending []int

	flush := func(b *dedup.BlockBuilder, algoByte compressor.Algo, pending *[]int) error {
		out, ferr := b.Finish()
		if ferr != nil {
			return ferr
		}
		if out == nil {
			return nil
		}
		offset := sw.Written()
		blockOffsets = append(blockOffsets, offset)
		newIdx := uint32(len(blockOffsets) - 1)
		for _, ti := range *pending {
			chunkTable[ti].blockIndex = newIdx
		}
		*pending = (*pending)[:0]

		if _, err := sw.Write([]byte("BLKD")); err != nil {
			return err
		}
		if err := binary.Write(sw, binary.BigEndian, uint64(out.UncompSize)); err != nil {
			return err
		}
		if err := binary.Write(sw, binary.BigEndian, uint64(out.PayloadLen)); err != nil {
			return err
		}
		if _, err := sw.Write(out.SHA[:]); err != nil {
			return err
		}
		if _, err := sw.Write([]byte{byte(algoByte)}); err != nil {
			return err
		}
		if err := copyTempFile(sw, out.TempPath); err != nil {
			return err
		}
		os.Remove(out.TempPath)
		return nil
	}

	seen := map[[32]byte]uint32{}
	var totalUnique int64

	for _, fe := range files {
		useStore := opt.Smart != smart.Off && smart.IsStoreVerified(fe, opt.Smart)
		builder, pending, algoByte := compBuilder, &compPending, algo
		if useStore {
			builder, pending, algoByte = storeBuilder, &storePending, compressor.Store
		}

		f, ferr := os.Open(fe.Abs)
		if ferr != nil {
			return nil, nil, nil, 0, ferr
		}
		hasher := sha256.New()
		var idxList []uint32

		cerr := dedup.ChunkStream(bar.Wrap(io.TeeReader(f, hasher)), chunkOpt, func(chunk []byte) error {
			h := sha256.Sum256(chunk)
			if idx, ok := seen[h]; ok {
				idxList = append(idxList, idx)
				return nil
			}
			if builder.ShouldFlush() {
				if err := flush(builder, algoByte, pending); err != nil {
					return err
				}
			}
			off, werr := builder.WriteChunk(chunk)
			if werr != nil {
				return werr
			}
			chunkTable = append(chunkTable, chunkEntry{hash: h, offset: uint64(off), length: uint64(len(chunk))})
			newIdx := uint32(len(chunkTable) - 1)
			*pending = append(*pending, len(chunkTable)-1)
			seen[h] = newIdx
			idxList = append(idxList, newIdx)
			totalUnique += int64(len(chunk))
			return nil
		})
		f.Close()
		if cerr != nil {
			return nil, nil, nil, 0, fmt.Errorf("chunking %s: %w", fe.Rel, cerr)
		}

		var fsha [32]byte
		copy(fsha[:], hasher.Sum(nil))
		fileList = append(fileList, dedupFileEntry{
			name: fe.Rel, sha: fsha, origSize: uint64(fe.Size), chunkIdx: idxList,
			mode: uint32(fe.Mode.Perm()), modTime: fe.ModTime.Unix(),
		})
		totalOrig += fe.Size
	}

	if err := flush(compBuilder, algo, &compPending); err != nil {
		return nil, nil, nil, 0, err
	}
	if err := flush(storeBuilder, compressor.Store, &storePending); err != nil {
		return nil, nil, nil, 0, err
	}

	if opt.Verbose {
		fmt.Printf("chunked: %d files, %d unique chunks, %d bytes unique (of %d bytes original)\n",
			len(fileList), len(chunkTable), totalUnique, totalOrig)
	}
	return chunkTable, blockOffsets, fileList, totalOrig, nil
}

// ---------- footer writing ----------

// writeFooter writes the combined footer shared by every archive: a
// normal solid-block section (files, mostly symlinks in -dedup mode),
// a chunked section (unique content chunks), and an empty-directories
// list, followed by a checksum of the whole footer and its own offset.
func writeFooter(sw *volume.SplitWriter, aead *cryptoutil.Cipher, blockOffsets []int64, footerFiles []footerFileEntry, chunkTable []chunkEntry, chunkBlockOffsets []int64, chunkFiles []dedupFileEntry, emptyDirs []string, totalOrig int64) error {
	// The footer is assembled in memory first: for an encrypted archive it
	// is then encrypted + authenticated as one stream (so file names,
	// sizes and hashes are no longer readable or forgeable without the
	// password), and in every case it is followed by a SHA-256 of the
	// stored bytes (cheap corruption check) and the footer's offset.
	var fw bytes.Buffer

	if err := binary.Write(&fw, binary.BigEndian, uint32(len(blockOffsets))); err != nil {
		return err
	}
	for _, off := range blockOffsets {
		if err := binary.Write(&fw, binary.BigEndian, off); err != nil {
			return err
		}
	}
	if err := binary.Write(&fw, binary.BigEndian, uint32(len(footerFiles))); err != nil {
		return err
	}
	for _, ff := range footerFiles {
		if err := format.WriteString(&fw, ff.name); err != nil {
			return err
		}
		if err := binary.Write(&fw, binary.BigEndian, ff.blockIndex); err != nil {
			return err
		}
		if err := binary.Write(&fw, binary.BigEndian, ff.origSize); err != nil {
			return err
		}
		if _, err := fw.Write(ff.sha[:]); err != nil {
			return err
		}
	}
	if err := writeChunkedSection(&fw, chunkTable, chunkBlockOffsets, chunkFiles); err != nil {
		return err
	}
	if err := binary.Write(&fw, binary.BigEndian, uint32(len(emptyDirs))); err != nil {
		return err
	}
	for _, d := range emptyDirs {
		if err := format.WriteString(&fw, d); err != nil {
			return err
		}
	}

	stored := fw.Bytes()
	if aead != nil {
		var enc bytes.Buffer
		ew, err := cryptoutil.NewEncryptWriter(&enc, aead, aadFooter)
		if err != nil {
			return err
		}
		if _, err := ew.Write(stored); err != nil {
			return err
		}
		if err := ew.Close(); err != nil {
			return err
		}
		stored = enc.Bytes()
	}
	footerOffset := sw.Written()
	if _, err := sw.Write(stored); err != nil {
		return err
	}
	sum := sha256.Sum256(stored)
	if _, err := sw.Write(sum[:]); err != nil {
		return err
	}
	if err := binary.Write(sw, binary.BigEndian, footerOffset); err != nil {
		return err
	}

	ratio := 0.0
	if totalOrig > 0 {
		ratio = 100 * (1 - float64(sw.Written())/float64(totalOrig))
	}
	summary := fmt.Sprintf("\npacked %d files (%d in solid blocks, %d chunked)\noriginal: %d bytes -> archive: %d bytes (%.2f%% smaller)",
		len(footerFiles)+len(chunkFiles), len(footerFiles), len(chunkFiles), totalOrig, sw.Written(), ratio)
	fmt.Println(ui.Success(summary))
	return nil
}

// writeChunkedSection serializes a chunk table + block offset list + file
// list. Always written (even if empty) so the reader logic doesn't need to
// branch on whether it's present.
func writeChunkedSection(w io.Writer, chunkTable []chunkEntry, blockOffsets []int64, fileList []dedupFileEntry) error {
	if err := binary.Write(w, binary.BigEndian, uint32(len(chunkTable))); err != nil {
		return err
	}
	for _, c := range chunkTable {
		if _, err := w.Write(c.hash[:]); err != nil {
			return err
		}
		if err := binary.Write(w, binary.BigEndian, c.blockIndex); err != nil {
			return err
		}
		if err := binary.Write(w, binary.BigEndian, c.offset); err != nil {
			return err
		}
		if err := binary.Write(w, binary.BigEndian, c.length); err != nil {
			return err
		}
	}
	if err := binary.Write(w, binary.BigEndian, uint32(len(blockOffsets))); err != nil {
		return err
	}
	for _, off := range blockOffsets {
		if err := binary.Write(w, binary.BigEndian, off); err != nil {
			return err
		}
	}
	if err := binary.Write(w, binary.BigEndian, uint32(len(fileList))); err != nil {
		return err
	}
	for _, df := range fileList {
		if err := format.WriteString(w, df.name); err != nil {
			return err
		}
		if _, err := w.Write(df.sha[:]); err != nil {
			return err
		}
		if err := binary.Write(w, binary.BigEndian, df.origSize); err != nil {
			return err
		}
		if err := binary.Write(w, binary.BigEndian, df.mode); err != nil {
			return err
		}
		if err := binary.Write(w, binary.BigEndian, df.modTime); err != nil {
			return err
		}
		if err := binary.Write(w, binary.BigEndian, uint32(len(df.chunkIdx))); err != nil {
			return err
		}
		for _, ci := range df.chunkIdx {
			if err := binary.Write(w, binary.BigEndian, ci); err != nil {
				return err
			}
		}
	}
	return nil
}

func copyTempFile(dst io.Writer, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(dst, f)
	return err
}

// trulyIncompressibleExt lists formats whose payload is already entropy
// coded by a modern lossy codec, where even xz --best gains well under 1%.
var trulyIncompressibleExt = map[string]bool{
	".mp4": true, ".mkv": true, ".avi": true, ".mov": true, ".wmv": true,
	".flv": true, ".webm": true, ".m4v": true,
	".mp3": true, ".aac": true, ".ogg": true, ".opus": true, ".m4a": true,
}

func allTrulyIncompressible(files []fsutil.FileRef) bool {
	for _, f := range files {
		if !trulyIncompressibleExt[strings.ToLower(filepath.Ext(f.Rel))] {
			return false
		}
	}
	return true
}
