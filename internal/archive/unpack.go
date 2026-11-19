package archive

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"

	"gitlab.com/specterog/maxzip/internal/block"
	"gitlab.com/specterog/maxzip/internal/compressor"
	"gitlab.com/specterog/maxzip/internal/cryptoutil"
	"gitlab.com/specterog/maxzip/internal/format"
	"gitlab.com/specterog/maxzip/internal/preprocess"
	"gitlab.com/specterog/maxzip/internal/progress"
	"gitlab.com/specterog/maxzip/internal/ui"
	"gitlab.com/specterog/maxzip/internal/volume"
)

type UnpackOptions struct {
	Input    string
	Output   string
	Password string
	OnlyFile string 
	Verify   bool
	Verbose  bool 
}

func ReadComment(path string) (comment string, has bool, err error) {
	ar, err := volume.OpenArchiveParts(path)
	if err != nil {
		return "", false, err
	}
	defer ar.Close()

	hdr, err := format.ReadHeader(ar)
	if err != nil {
		return "", false, err
	}
	return hdr.Comment, hdr.Flags&format.FlagComment != 0, nil
}

type EntryInfo struct {
	Name string
	Size int64
}

func ListEntries(path, password string) ([]EntryInfo, error) {
	ar, err := volume.OpenArchiveParts(path)
	if err != nil {
		return nil, err
	}
	defer ar.Close()

	hdr, err := format.ReadHeader(ar)
	if err != nil {
		return nil, err
	}
	aead, err := openCipher(hdr, password)
	if err != nil {
		return nil, err
	}
	idx, err := readFooter(ar, aead)
	if err != nil {
		return nil, fmt.Errorf("reading archive index (corrupted or wrong file): %w", err)
	}

	var out []EntryInfo
	for _, fe := range idx.files {
		out = append(out, EntryInfo{Name: fe.name, Size: int64(fe.origSize)})
	}
	for _, fe := range idx.bigFiles {
		out = append(out, EntryInfo{Name: fe.name, Size: int64(fe.origSize)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

type TestOptions struct {
	Input    string
	Password string
}

func Test(opt TestOptions) error {
	ar, err := volume.OpenArchiveParts(opt.Input)
	if err != nil {
		return err
	}
	defer ar.Close()

	hdr, err := format.ReadHeader(ar)
	if err != nil {
		return err
	}

	aead, err := openCipher(hdr, opt.Password)
	if err != nil {
		return err
	}

	idx, err := readFooter(ar, aead)
	if err != nil {
		return fmt.Errorf("reading archive index (corrupted or wrong file): %w", err)
	}

	count := 0
	for bi, offset := range idx.blockOffsets {
		fileCount, uncompSize, payloadLen, blockSHA, algo, usedDict, err := readBlockHeader(ar, offset)
		if err != nil {
			return fmt.Errorf("block %d: %w", bi, err)
		}
		if err := checkBlockHeaderMatchesIndex(idx, uint32(bi), fileCount, uncompSize); err != nil {
			return err
		}
		tr, cleanup, err := openBlockTar(ar, uint32(bi), payloadLen, blockSHA, algo, aead, true, dictIf(usedDict, hdr.Dict))
		if err != nil {
			return fmt.Errorf("block %d: %w (wrong password or corrupted data)", bi, err)
		}
		ds := newDeltaState()
		expected := map[string]footerFileEntry{}
		for _, fe := range idx.files {
			if fe.blockIndex == uint32(bi) {
				expected[fe.name] = fe
			}
		}
		found := 0
		for {
			th, terr := tr.Next()
			if terr == io.EOF {
				break
			}
			if terr != nil {
				cleanup()
				return fmt.Errorf("block %d: reading contents: %w", bi, terr)
			}
			if th.Typeflag != tar.TypeReg && th.Typeflag != tar.TypeSymlink {
				continue
			}
			fe, ok := expected[th.Name]
			if !ok {
				continue
			}
			if err := verifyEntry(th, tr, ds, fe.sha, fe.origSize); err != nil {
				cleanup()
				return err
			}
			found++
			count++
		}
		cleanup()
		if found != len(expected) {
			return fmt.Errorf("block %d: %d file(s) listed in the index are missing from the block (corrupted archive)", bi, len(expected)-found)
		}
	}

	cache := newBlockCache(4)
	for _, fe := range idx.bigFiles {
		if err := verifyChunkedFile(ar, cache, fe, idx.bigChunks, idx.bigBlocks, aead); err != nil {
			return err
		}
		count++
	}

	fmt.Println(ui.Success(fmt.Sprintf("OK: %d files verified intact", count)))
	return nil
}

func verifyEntry(hdr *tar.Header, r io.Reader, ds *deltaState, expectedSHA [32]byte, expectedSize uint64) error {
	if hdr.Typeflag == tar.TypeSymlink {
		sum := sha256.Sum256([]byte(hdr.Linkname))
		if sum != expectedSHA {
			return fmt.Errorf("integrity check failed for %s (symlink target corrupted)", hdr.Name)
		}
		return nil
	}
	r, err := ds.open(hdr, r, expectedSize)
	if err != nil {
		return err
	}
	src, _, err := undoPreprocess(hdr, r, expectedSize)
	if err != nil {
		return err
	}
	hasher := sha256.New()
	n, err := io.Copy(hasher, io.LimitReader(src, int64(expectedSize)+1))
	if err != nil {
		return err
	}
	if uint64(n) != expectedSize {
		return fmt.Errorf("integrity check failed for %s (size does not match the index)", hdr.Name)
	}
	var actual [32]byte
	copy(actual[:], hasher.Sum(nil))
	if actual != expectedSHA {
		return fmt.Errorf("integrity check failed for %s (file is corrupted)", hdr.Name)
	}
	return nil
}

func verifyChunkedFile(ar *volume.MultiPartReader, cache *blockCache, fe dedupFileEntry, chunkTable []chunkEntry, blockOffsets []int64, aead *cryptoutil.Cipher) error {
	hasher := sha256.New()
	var written uint64
	for _, ci := range fe.chunkIdx {
		entry := chunkTable[ci]
		data, err := cache.get(ar, blockOffsets, entry.blockIndex, aead, true)
		if err != nil {
			return err
		}
		if entry.offset > uint64(len(data)) || entry.length > uint64(len(data))-entry.offset {
			return fmt.Errorf("corrupted archive: chunk out of range in block %d", entry.blockIndex)
		}
		hasher.Write(data[entry.offset : entry.offset+entry.length])
		written += entry.length
	}
	if written != fe.origSize {
		return fmt.Errorf("integrity check failed for %s (size does not match the index)", fe.name)
	}
	var actual [32]byte
	copy(actual[:], hasher.Sum(nil))
	if actual != fe.sha {
		return fmt.Errorf("integrity check failed for %s (file is corrupted)", fe.name)
	}
	return nil
}

func Unpack(opt UnpackOptions) error {
	ar, err := volume.OpenArchiveParts(opt.Input)
	if err != nil {
		return err
	}
	defer ar.Close()

	hdr, err := format.ReadHeader(ar)
	if err != nil {
		return err
	}

	aead, err := openCipher(hdr, opt.Password)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(opt.Output, 0o755); err != nil {
		return err
	}

	idx, err := readFooter(ar, aead)
	if err != nil {
		return fmt.Errorf("reading archive index (corrupted or wrong file): %w", err)
	}
	if opt.OnlyFile != "" {
		return extractSingleFile(ar, idx, opt, aead, hdr.Dict)
	}

	var total int64
	for _, fe := range idx.files {
		total += int64(fe.origSize)
	}
	for _, fe := range idx.bigFiles {
		total += int64(fe.origSize)
	}
	bar := progress.New(total, "unpacking")
	bar.Start()
	defer bar.Finish()

	return extractAll(ar, idx, opt, aead, hdr.Dict, bar)
}

type chunkEntry struct {
	hash       [32]byte
	blockIndex uint32
	offset     uint64
	length     uint64
}

type dedupFileEntry struct {
	name     string
	sha      [32]byte
	origSize uint64
	mode     uint32 
	modTime  int64  
	chunkIdx []uint32
}

func readChunkedSection(r *bytes.Reader) (chunkTable []chunkEntry, blockOffsets []int64, fileList []dedupFileEntry, err error) {
	var chunkCount uint32
	if err = binary.Read(r, binary.BigEndian, &chunkCount); err != nil {
		return
	}
	if err = checkCount(r, chunkCount, 32+4+8+8, "chunk"); err != nil {
		return
	}
	chunkTable = make([]chunkEntry, chunkCount)
	for i := range chunkTable {
		var c chunkEntry
		if _, err = io.ReadFull(r, c.hash[:]); err != nil {
			return
		}
		if err = binary.Read(r, binary.BigEndian, &c.blockIndex); err != nil {
			return
		}
		if err = binary.Read(r, binary.BigEndian, &c.offset); err != nil {
			return
		}
		if err = binary.Read(r, binary.BigEndian, &c.length); err != nil {
			return
		}
		chunkTable[i] = c
	}

	var blockCount uint32
	if err = binary.Read(r, binary.BigEndian, &blockCount); err != nil {
		return
	}
	if err = checkCount(r, blockCount, 8, "chunk-block"); err != nil {
		return
	}
	blockOffsets = make([]int64, blockCount)
	for i := range blockOffsets {
		if err = binary.Read(r, binary.BigEndian, &blockOffsets[i]); err != nil {
			return
		}
	}

	var fileCount uint32
	if err = binary.Read(r, binary.BigEndian, &fileCount); err != nil {
		return
	}
	if err = checkCount(r, fileCount, 2+32+8+4+8+4, "chunked file"); err != nil {
		return
	}
	fileList = make([]dedupFileEntry, fileCount)
	for i := range fileList {
		var name string
		name, err = format.ReadString(r)
		if err != nil {
			return
		}
		var sha [32]byte
		if _, err = io.ReadFull(r, sha[:]); err != nil {
			return
		}
		var origSize uint64
		if err = binary.Read(r, binary.BigEndian, &origSize); err != nil {
			return
		}
		var mode uint32
		if err = binary.Read(r, binary.BigEndian, &mode); err != nil {
			return
		}
		var modTime int64
		if err = binary.Read(r, binary.BigEndian, &modTime); err != nil {
			return
		}
		var chunkN uint32
		if err = binary.Read(r, binary.BigEndian, &chunkN); err != nil {
			return
		}
		if err = checkCount(r, chunkN, 4, "file chunk"); err != nil {
			return
		}
		idxs := make([]uint32, chunkN)
		for j := range idxs {
			if err = binary.Read(r, binary.BigEndian, &idxs[j]); err != nil {
				return
			}
		}
		fileList[i] = dedupFileEntry{name: name, sha: sha, origSize: origSize, mode: mode, modTime: modTime, chunkIdx: idxs}
	}
	return
}

func readDedupBlockHeader(ar *volume.MultiPartReader, offset int64) (uncompSize, payloadLen uint64, sha [32]byte, algo compressor.Algo, err error) {
	if _, err = ar.Seek(offset, io.SeekStart); err != nil {
		return
	}
	magicBuf := make([]byte, 4)
	if _, err = io.ReadFull(ar, magicBuf); err != nil {
		return
	}
	if string(magicBuf) != "BLKD" {
		err = fmt.Errorf("corrupted archive: bad chunk-block magic at offset %d", offset)
		return
	}
	if err = binary.Read(ar, binary.BigEndian, &uncompSize); err != nil {
		return
	}
	if err = binary.Read(ar, binary.BigEndian, &payloadLen); err != nil {
		return
	}
	if _, err = io.ReadFull(ar, sha[:]); err != nil {
		return
	}
	var algoByte [1]byte
	if _, err = io.ReadFull(ar, algoByte[:]); err != nil {
		return
	}
	algo = compressor.Algo(algoByte[0])
	if uncompSize > uint64(maxBlockUncomp) {
		err = fmt.Errorf("corrupted archive: chunk-block claims %d uncompressed bytes", uncompSize)
		return
	}
	if err = checkPayloadLen(ar, payloadLen); err != nil {
		return
	}
	return
}

func checkPayloadLen(ar *volume.MultiPartReader, payloadLen uint64) error {
	pos, err := ar.Seek(0, io.SeekCurrent)
	if err != nil {
		return err
	}
	if payloadLen > uint64(ar.Size()-pos) {
		return fmt.Errorf("corrupted archive: block payload (%d bytes) extends past the end of the archive", payloadLen)
	}
	return nil
}

type blockCache struct {
	cap   int
	order []uint32
	data  map[uint32][]byte
}

func newBlockCache(cap int) *blockCache { return &blockCache{cap: cap, data: map[uint32][]byte{}} }

func (c *blockCache) get(ar *volume.MultiPartReader, offsets []int64, idx uint32, aead *cryptoutil.Cipher, verify bool) ([]byte, error) {
	if d, ok := c.data[idx]; ok {
		return d, nil
	}
	if int(idx) >= len(offsets) {
		return nil, fmt.Errorf("corrupted archive: missing chunk-block %d", idx)
	}
	uncompSize, payloadLen, sha, algo, err := readDedupBlockHeader(ar, offsets[idx])
	if err != nil {
		return nil, err
	}
	payload := make([]byte, payloadLen)
	if _, err := io.ReadFull(ar, payload); err != nil {
		return nil, err
	}
	if verify {
		sum := sha256.Sum256(payload)
		if sum != sha {
			return nil, fmt.Errorf("block %d integrity check failed (archive is corrupted)", idx)
		}
	}
	var bodyReader io.Reader = bytes.NewReader(payload)
	if aead != nil {
		dr, err := cryptoutil.NewDecryptReader(bodyReader, aead, aadChunkBlock)
		if err != nil {
			return nil, err
		}
		bodyReader = dr
	}
	decompressed, err := compressor.NewDecompressReader(bodyReader, algo)
	if err != nil {
		return nil, err
	}
	
	data, err := io.ReadAll(io.LimitReader(decompressed, int64(uncompSize)+1))
	compressor.CloseDecompressor(decompressed)
	if err != nil {
		return nil, err
	}
	if uint64(len(data)) != uncompSize {
		return nil, fmt.Errorf("block %d: decompressed size does not match its header (corrupted archive)", idx)
	}

	c.data[idx] = data
	c.order = append(c.order, idx)
	if len(c.order) > c.cap {
		evict := c.order[0]
		c.order = c.order[1:]
		delete(c.data, evict)
	}
	return data, nil
}

func reconstructChunkedFile(ar *volume.MultiPartReader, cache *blockCache, fe dedupFileEntry, chunkTable []chunkEntry, blockOffsets []int64, outputDir string, aead *cryptoutil.Cipher, verify bool) error {
	outPath, err := safeJoin(outputDir, fe.name)
	if err != nil {
		return err
	}
	out, err := createSafeFile(outPath)
	if err != nil {
		return err
	}
	hasher := sha256.New()
	mw := io.MultiWriter(out, hasher)
	var written uint64
	for _, ci := range fe.chunkIdx {
		entry := chunkTable[ci]
		data, err := cache.get(ar, blockOffsets, entry.blockIndex, aead, verify)
		if err != nil {
			out.Close()
			return err
		}
		if entry.offset > uint64(len(data)) || entry.length > uint64(len(data))-entry.offset {
			out.Close()
			return fmt.Errorf("corrupted archive: chunk out of range in block %d", entry.blockIndex)
		}
		if _, err := mw.Write(data[entry.offset : entry.offset+entry.length]); err != nil {
			out.Close()
			return err
		}
		written += entry.length
	}
	out.Close()
	if written != fe.origSize {
		return fmt.Errorf("integrity check failed for %s (size does not match the index)", fe.name)
	}
	if verify {
		var actual [32]byte
		copy(actual[:], hasher.Sum(nil))
		if actual != fe.sha {
			return fmt.Errorf("integrity check failed for %s (file is corrupted)", fe.name)
		}
	}
	if fe.mode != 0 {
		_ = os.Chmod(outPath, os.FileMode(fe.mode).Perm())
	}
	if fe.modTime != 0 {
		t := time.Unix(fe.modTime, 0)
		_ = os.Chtimes(outPath, t, t)
	}
	return nil
}

type footerFileEntry struct {
	name       string
	blockIndex uint32
	origSize   uint64
	sha        [32]byte
}

type footerIndex struct {
	blockOffsets []int64
	files        []footerFileEntry
	bigChunks    []chunkEntry
	bigBlocks    []int64
	bigFiles     []dedupFileEntry
	emptyDirs    []string
}

func readFooter(ar *volume.MultiPartReader, aead *cryptoutil.Cipher) (*footerIndex, error) {
	total := ar.Size()
	const trailer = 32 + 8 
	if total < trailer {
		return nil, fmt.Errorf("archive too small to contain an index")
	}
	if _, err := ar.Seek(-8, io.SeekEnd); err != nil {
		return nil, err
	}
	var footerOffset int64
	if err := binary.Read(ar, binary.BigEndian, &footerOffset); err != nil {
		return nil, err
	}
	storedLen := total - trailer - footerOffset
	if footerOffset < 0 || storedLen < 0 {
		return nil, fmt.Errorf("archive index offset is invalid (corrupted or wrong file)")
	}
	if _, err := ar.Seek(footerOffset, io.SeekStart); err != nil {
		return nil, err
	}
	stored, err := format.ReadBounded(ar, uint32(minInt64(storedLen, int64(^uint32(0)))), ^uint32(0), "footer")
	if err != nil {
		return nil, err
	}
	if int64(len(stored)) != storedLen {
		return nil, fmt.Errorf("archive index is too large")
	}
	var storedHash [32]byte
	if _, err := io.ReadFull(ar, storedHash[:]); err != nil {
		return nil, err
	}
	if sum := sha256.Sum256(stored); !bytes.Equal(sum[:], storedHash[:]) {
		return nil, fmt.Errorf("archive index is corrupted (footer checksum mismatch)")
	}

	plain := stored
	if aead != nil {
		dr, err := cryptoutil.NewDecryptReader(bytes.NewReader(stored), aead, aadFooter)
		if err != nil {
			return nil, err
		}
		plain, err = io.ReadAll(dr)
		if err != nil {
			return nil, fmt.Errorf("archive index could not be decrypted: %w", err)
		}
	}

	r := bytes.NewReader(plain)
	idx, err := parseFooter(r)
	if err != nil {
		return nil, err
	}
	if r.Len() != 0 {
		return nil, fmt.Errorf("archive index has %d unexpected trailing bytes", r.Len())
	}
	if err := idx.validate(footerOffset); err != nil {
		return nil, err
	}
	return idx, nil
}

func minInt64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

func checkCount(r *bytes.Reader, n uint32, minSize int, what string) error {
	if uint64(n)*uint64(minSize) > uint64(r.Len()) {
		return fmt.Errorf("corrupted archive index: %s count %d is impossible", what, n)
	}
	return nil
}

func parseFooter(tr *bytes.Reader) (*footerIndex, error) {
	var blockCount uint32
	if err := binary.Read(tr, binary.BigEndian, &blockCount); err != nil {
		return nil, err
	}
	if err := checkCount(tr, blockCount, 8, "block"); err != nil {
		return nil, err
	}
	offsets := make([]int64, blockCount)
	for i := range offsets {
		if err := binary.Read(tr, binary.BigEndian, &offsets[i]); err != nil {
			return nil, err
		}
	}

	var fileCount uint32
	if err := binary.Read(tr, binary.BigEndian, &fileCount); err != nil {
		return nil, err
	}
	if err := checkCount(tr, fileCount, 2+4+8+32, "file"); err != nil {
		return nil, err
	}
	files := make([]footerFileEntry, fileCount)
	for i := range files {
		name, err := format.ReadString(tr)
		if err != nil {
			return nil, err
		}
		var blockIdx uint32
		if err := binary.Read(tr, binary.BigEndian, &blockIdx); err != nil {
			return nil, err
		}
		var origSize uint64
		if err := binary.Read(tr, binary.BigEndian, &origSize); err != nil {
			return nil, err
		}
		var sha [32]byte
		if _, err := io.ReadFull(tr, sha[:]); err != nil {
			return nil, err
		}
		files[i] = footerFileEntry{name: name, blockIndex: blockIdx, origSize: origSize, sha: sha}
	}

	bigChunks, bigBlocks, bigFiles, err := readChunkedSection(tr)
	if err != nil {
		return nil, err
	}

	var emptyDirCount uint32
	if err := binary.Read(tr, binary.BigEndian, &emptyDirCount); err != nil {
		return nil, err
	}
	if err := checkCount(tr, emptyDirCount, 2, "directory"); err != nil {
		return nil, err
	}
	emptyDirs := make([]string, emptyDirCount)
	for i := range emptyDirs {
		d, err := format.ReadString(tr)
		if err != nil {
			return nil, err
		}
		emptyDirs[i] = d
	}

	return &footerIndex{
		blockOffsets: offsets, files: files,
		bigChunks: bigChunks, bigBlocks: bigBlocks, bigFiles: bigFiles,
		emptyDirs: emptyDirs,
	}, nil
}

func (idx *footerIndex) validate(footerOffset int64) error {
	badOffsets := func(offs []int64, what string) error {
		for _, o := range offs {
			if o < 0 || o >= footerOffset {
				return fmt.Errorf("corrupted archive index: %s offset %d out of range", what, o)
			}
		}
		return nil
	}
	if err := badOffsets(idx.blockOffsets, "block"); err != nil {
		return err
	}
	if err := badOffsets(idx.bigBlocks, "chunk-block"); err != nil {
		return err
	}
	for _, fe := range idx.files {
		if int(fe.blockIndex) >= len(idx.blockOffsets) {
			return fmt.Errorf("corrupted archive index: %s refers to missing block %d", fe.name, fe.blockIndex)
		}
	}
	for _, c := range idx.bigChunks {
		if int(c.blockIndex) >= len(idx.bigBlocks) {
			return fmt.Errorf("corrupted archive index: chunk refers to missing block %d", c.blockIndex)
		}
	}
	for _, fe := range idx.bigFiles {
		for _, ci := range fe.chunkIdx {
			if int(ci) >= len(idx.bigChunks) {
				return fmt.Errorf("corrupted archive index: %s refers to missing chunk %d", fe.name, ci)
			}
		}
	}
	return nil
}

const blockFlagDict = 0x80

func readBlockHeader(ar *volume.MultiPartReader, offset int64) (fileCount uint32, uncompSize uint64, payloadLen uint64, blockSHA [32]byte, algo compressor.Algo, usedDict bool, err error) {
	if _, err = ar.Seek(offset, io.SeekStart); err != nil {
		return
	}
	magicBuf := make([]byte, 4)
	if _, err = io.ReadFull(ar, magicBuf); err != nil {
		return
	}
	if string(magicBuf) != "BLK0" {
		err = fmt.Errorf("corrupted archive: bad block magic at offset %d", offset)
		return
	}
	if err = binary.Read(ar, binary.BigEndian, &fileCount); err != nil {
		return
	}
	if err = binary.Read(ar, binary.BigEndian, &uncompSize); err != nil {
		return
	}
	if err = binary.Read(ar, binary.BigEndian, &payloadLen); err != nil {
		return
	}
	if _, err = io.ReadFull(ar, blockSHA[:]); err != nil {
		return
	}
	var algoByte [1]byte
	if _, err = io.ReadFull(ar, algoByte[:]); err != nil {
		return
	}
	algo = compressor.Algo(algoByte[0] &^ blockFlagDict)
	usedDict = algoByte[0]&blockFlagDict != 0
	if uncompSize > uint64(maxBlockUncomp) {
		err = fmt.Errorf("corrupted archive: block claims %d uncompressed bytes", uncompSize)
		return
	}
	if err = checkPayloadLen(ar, payloadLen); err != nil {
		return
	}
	return
}

func openBlockTar(ar *volume.MultiPartReader, blockIndex uint32, payloadLen uint64, blockSHA [32]byte, algo compressor.Algo, aead *cryptoutil.Cipher, verify bool, dict []byte) (*tar.Reader, func(), error) {
	payload := make([]byte, payloadLen)
	if _, err := io.ReadFull(ar, payload); err != nil {
		return nil, nil, err
	}
	if verify {
		sum := sha256.Sum256(payload)
		if sum != blockSHA {
			return nil, nil, fmt.Errorf("block integrity check failed (archive is corrupted)")
		}
	}
	var bodyReader io.Reader = bytes.NewReader(payload)
	if aead != nil {
		dr, err := cryptoutil.NewDecryptReader(bodyReader, aead, blockAAD(blockIndex))
		if err != nil {
			return nil, nil, err
		}
		bodyReader = dr
	}
	decompressed, err := compressor.NewDecompressReader(bodyReader, algo)
	if err != nil {
		return nil, nil, err
	}
	
	if algo == compressor.Zstd && len(dict) > 0 {
		if _, err := io.CopyN(io.Discard, decompressed, int64(len(dict))); err != nil {
			compressor.CloseDecompressor(decompressed)
			return nil, nil, fmt.Errorf("reading dictionary prefix: %w", err)
		}
	}
	cleanup := func() { compressor.CloseDecompressor(decompressed) }
	return tar.NewReader(decompressed), cleanup, nil
}

func extractAll(ar *volume.MultiPartReader, idx *footerIndex, opt UnpackOptions, aead *cryptoutil.Cipher, dict []byte, bar *progress.Bar) error {
	byBlock := map[uint32][]footerFileEntry{}
	for _, fe := range idx.files {
		byBlock[fe.blockIndex] = append(byBlock[fe.blockIndex], fe)
	}
	count := 0
	for bi, offset := range idx.blockOffsets {
		fileCount, uncompSize, payloadLen, blockSHA, algo, usedDict, err := readBlockHeader(ar, offset)
		if err != nil {
			return fmt.Errorf("block %d: %w", bi, err)
		}
		if err := checkBlockHeaderMatchesIndex(idx, uint32(bi), fileCount, uncompSize); err != nil {
			return err
		}
		tr, cleanup, err := openBlockTar(ar, uint32(bi), payloadLen, blockSHA, algo, aead, opt.Verify, dictIf(usedDict, dict))
		if err != nil {
			return fmt.Errorf("block %d: %w (wrong password or corrupted data)", bi, err)
		}
		ds := newDeltaState()
		expected := map[string]footerFileEntry{}
		for _, fe := range byBlock[uint32(bi)] {
			expected[fe.name] = fe
		}
		for {
			hdr, terr := tr.Next()
			if terr == io.EOF {
				break
			}
			if terr != nil {
				cleanup()
				return fmt.Errorf("block %d: reading contents: %w", bi, terr)
			}
			if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeSymlink {
				continue
			}
			fe, ok := expected[hdr.Name]
			if !ok {
				continue
			}
			var werr error
			if hdr.Typeflag == tar.TypeSymlink {
				werr = writeExtractedSymlink(hdr, opt.Output, fe.sha, opt.Verify)
			} else {
				werr = writeExtractedFile(hdr, tr, ds, opt.Output, fe.sha, fe.origSize, opt.Verify)
			}
			if werr != nil {
				cleanup()
				return werr
			}
			bar.Add(int64(fe.origSize))
			if opt.Verbose {
				fmt.Println("extracted & verified:", hdr.Name)
			}
			count++
		}
		cleanup()
	}

	if len(idx.bigFiles) > 0 {
		cache := newBlockCache(4)
		for _, fe := range idx.bigFiles {
			if err := reconstructChunkedFile(ar, cache, fe, idx.bigChunks, idx.bigBlocks, opt.Output, aead, opt.Verify); err != nil {
				return err
			}
			bar.Add(int64(fe.origSize))
			if opt.Verbose {
				fmt.Println("extracted & verified:", fe.name)
			}
			count++
		}
	}

	for _, d := range idx.emptyDirs {
		dp, err := safeJoin(opt.Output, d)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(dp, 0o755); err != nil {
			return err
		}
	}

	bar.Finish()
	fmt.Println(ui.Success(fmt.Sprintf("\nextracted %d files, all verified intact", count)))
	return nil
}

func extractSingleFile(ar *volume.MultiPartReader, idx *footerIndex, opt UnpackOptions, aead *cryptoutil.Cipher, dict []byte) error {
	for i := range idx.files {
		if idx.files[i].name == opt.OnlyFile {
			target := &idx.files[i]
			offset := idx.blockOffsets[target.blockIndex]
			fileCount, uncompSize, payloadLen, blockSHA, algo, usedDict, err := readBlockHeader(ar, offset)
			if err != nil {
				return err
			}
			if err := checkBlockHeaderMatchesIndex(idx, target.blockIndex, fileCount, uncompSize); err != nil {
				return err
			}
			tr, cleanup, err := openBlockTar(ar, target.blockIndex, payloadLen, blockSHA, algo, aead, opt.Verify, dictIf(usedDict, dict))
			if err != nil {
				return fmt.Errorf("%w (wrong password or corrupted data)", err)
			}
			defer cleanup()
			ds := newDeltaState()
			sizes := map[string]uint64{}
			for _, fe := range idx.files {
				if fe.blockIndex == target.blockIndex {
					sizes[fe.name] = fe.origSize
				}
			}
			for {
				hdr, terr := tr.Next()
				if terr == io.EOF {
					return fmt.Errorf("file listed in index but missing from its block (archive corrupted): %s", opt.OnlyFile)
				}
				if terr != nil {
					return terr
				}
				if hdr.Name != target.name {
					
					if isChain(hdr) {
						if sz, known := sizes[hdr.Name]; known {
							if _, err := ds.open(hdr, tr, sz); err != nil {
								return err
							}
						}
					}
					continue
				}
				var werr error
				if hdr.Typeflag == tar.TypeSymlink {
					werr = writeExtractedSymlink(hdr, opt.Output, target.sha, opt.Verify)
				} else {
					werr = writeExtractedFile(hdr, tr, ds, opt.Output, target.sha, target.origSize, opt.Verify)
				}
				if werr != nil {
					return werr
				}
				fmt.Println(ui.Success("extracted & verified: " + hdr.Name))
				return nil
			}
		}
	}

	for _, fe := range idx.bigFiles {
		if fe.name == opt.OnlyFile {
			cache := newBlockCache(4)
			if err := reconstructChunkedFile(ar, cache, fe, idx.bigChunks, idx.bigBlocks, opt.Output, aead, opt.Verify); err != nil {
				return err
			}
			fmt.Println(ui.Success("extracted & verified: " + fe.name))
			return nil
		}
	}

	return fmt.Errorf("file not found in archive: %s", opt.OnlyFile)
}

func writeExtractedFile(hdr *tar.Header, r io.Reader, ds *deltaState, destRoot string, expectedSHA [32]byte, expectedSize uint64, verify bool) error {
	name := hdr.Name
	r, err := ds.open(hdr, r, expectedSize)
	if err != nil {
		return err
	}
	outPath, err := safeJoin(destRoot, name)
	if err != nil {
		return err
	}
	f, err := createSafeFile(outPath)
	if err != nil {
		return err
	}

	src, preprocessed, err := undoPreprocess(hdr, r, expectedSize)
	if err != nil {
		f.Close()
		return err
	}
	if preprocessed || isChain(hdr) {
		
		verify = true
	}

	hasher := sha256.New()
	mw := io.MultiWriter(f, hasher)
	
	n, err := io.Copy(mw, io.LimitReader(src, int64(expectedSize)+1))
	if err != nil {
		f.Close()
		return err
	}
	f.Close()
	if uint64(n) != expectedSize {
		return fmt.Errorf("integrity check failed for %s (size does not match the index)", name)
	}
	if verify {
		var actual [32]byte
		copy(actual[:], hasher.Sum(nil))
		if actual != expectedSHA {
			return fmt.Errorf("integrity check failed for %s (file is corrupted)", name)
		}
	}

	if hdr.Mode != 0 {
		_ = os.Chmod(outPath, os.FileMode(hdr.Mode).Perm())
	}
	if !hdr.ModTime.IsZero() {
		_ = os.Chtimes(outPath, hdr.ModTime, hdr.ModTime)
	}
	return nil
}

func writeExtractedSymlink(hdr *tar.Header, destRoot string, expectedSHA [32]byte, verify bool) error {
	outPath, err := safeJoin(destRoot, hdr.Name)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
		return err
	}
	if verify {
		sum := sha256.Sum256([]byte(hdr.Linkname))
		if sum != expectedSHA {
			return fmt.Errorf("integrity check failed for %s (symlink target corrupted)", hdr.Name)
		}
	}
	_ = os.Remove(outPath) 
	return os.Symlink(hdr.Linkname, outPath)
}

func dictIf(used bool, dict []byte) []byte {
	if used {
		return dict
	}
	return nil
}

func checkBlockHeaderMatchesIndex(idx *footerIndex, bi uint32, fileCount uint32, uncompSize uint64) error {
	var n uint32
	var size uint64
	for _, fe := range idx.files {
		if fe.blockIndex == bi {
			n++
			size += fe.origSize
		}
	}
	if n != fileCount || size != uncompSize {
		return fmt.Errorf("block %d: header does not match the archive index (corrupted archive)", bi)
	}
	return nil
}

func undoPreprocess(hdr *tar.Header, r io.Reader, expectedSize uint64) (out io.Reader, forced bool, err error) {
	switch hdr.PAXRecords[block.PAXPreprocess] {
	case "":
		return r, false, nil
	case "delta":
		return preprocess.NewDeltaDecodeReader(r), true, nil
	case "bcj":
		if expectedSize > uint64(preprocess.MaxBCJSize) {
			return nil, true, fmt.Errorf("%s: BCJ-filtered file larger than the %d byte limit", hdr.Name, preprocess.MaxBCJSize)
		}
		var buf bytes.Buffer
		n, err := io.Copy(&buf, io.LimitReader(r, int64(expectedSize)+1))
		if err != nil {
			return nil, true, err
		}
		if uint64(n) != expectedSize {
			return nil, true, fmt.Errorf("integrity check failed for %s (size does not match the index)", hdr.Name)
		}
		data := buf.Bytes()
		preprocess.BCJDecode(data)
		return bytes.NewReader(data), true, nil
	default:
		return nil, true, fmt.Errorf("%s: unknown preprocessing %q (archive made by a newer version?)", hdr.Name, hdr.PAXRecords[block.PAXPreprocess])
	}
}
