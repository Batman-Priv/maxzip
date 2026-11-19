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

	"maxzip/internal/block"
	"maxzip/internal/compressor"
	"maxzip/internal/cryptoutil"
	"maxzip/internal/dedup"
	"maxzip/internal/dictionary"
	"maxzip/internal/format"
	"maxzip/internal/fsutil"
	"maxzip/internal/progress"
	"maxzip/internal/smart"
	"maxzip/internal/ui"
	"maxzip/internal/volume"
)

type PackOptions struct {
	Inputs           []string
	Output           string
	Algo             compressor.Algo
	Level            string
	Optimize         string
	Password         string
	Smart            smart.Mode
	Dict             string
	Dedup            bool
	DedupChunk       int64
	Threads          int
	Exclude          []string
	BlockSize        int64
	SplitBytes       int64
	BigFileThreshold int64
	Preprocess       string
	Comment          string
	Delta            bool
	DeltaMax         int64
	Verbose          bool
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

	if optimize == "size" && best != compressor.Zstd {
		if zr, ok := results[compressor.Zstd]; ok {
			if br, ok2 := results[best]; ok2 && zr.Size > 0 {
				gain := float64(zr.Size-br.Size) / float64(zr.Size)
				if gain < 0.02 {
					fmt.Printf("auto-select: %s gains only %.2f%% over zstd; choosing zstd for speed\n", best, gain*100)
					return compressor.Zstd, nil
				}
			}
		}
	}
	return best, nil
}

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

	var incompTotal int64
	for _, fe := range files {
		incompTotal += fe.Size
	}
	incompTarget := incompTotal / int64(threads)
	if incompTarget < 8<<20 {
		incompTarget = 8 << 20
	}
	plans := block.PlanBlocks(files, algo, opt.Smart, blockSize, incompTarget)

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

func buildBlockWithFallback(plan block.Plan, idx uint32, opt PackOptions, dict []byte, aead *cryptoutil.Cipher, bar *progress.Bar, encThreads int) (*block.Meta, compressor.Algo, bool, error) {
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

	level := opt.Level
	strong := opt.Level == "best" || opt.Level == "better"
	explicitAlgo := plan.Algo != compressor.Auto

	if plan.LikelyIncompressible && !explicitAlgo && (!strong || allTrulyIncompressible(plan.Files)) {
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
		os.Remove(probe.TempPath)
	}

	var d []byte
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
				d = nil
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
	return m, plan.Algo, len(d) > 0, nil
}

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

func writeFooter(sw *volume.SplitWriter, aead *cryptoutil.Cipher, blockOffsets []int64, footerFiles []footerFileEntry, chunkTable []chunkEntry, chunkBlockOffsets []int64, chunkFiles []dedupFileEntry, emptyDirs []string, totalOrig int64) error {
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