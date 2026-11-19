
package selftest

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"gitlab.com/specterog/maxzip/internal/archive"
	"gitlab.com/specterog/maxzip/internal/compressor"
	"gitlab.com/specterog/maxzip/internal/delta"
	"gitlab.com/specterog/maxzip/internal/smart"
	"gitlab.com/specterog/maxzip/internal/ui"
)

type scenario struct {
	name          string
	skipExecCheck bool 
	modify        func(opt *archive.PackOptions)
}

func Run() error {
	srcDir, err := os.MkdirTemp("", "maxzip-selftest-src-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(srcDir)

	if err := generateSamples(srcDir); err != nil {
		return fmt.Errorf("generating sample data: %w", err)
	}

	scenarios := []scenario{
		{name: "normal-zstd", modify: func(o *archive.PackOptions) {
			o.Algo = compressor.Zstd
		}},
		{name: "normal-xz", modify: func(o *archive.PackOptions) {
			o.Algo = compressor.XZ
		}},
		{name: "normal-auto", modify: func(o *archive.PackOptions) {
			o.Algo = compressor.Auto
			o.Optimize = "size"
		}},
		{name: "dedup", modify: func(o *archive.PackOptions) {
			o.Dedup = true
		}},
		{name: "encrypted", modify: func(o *archive.PackOptions) {
			o.Password = "correct horse battery staple"
		}},
		{name: "split-volumes", modify: func(o *archive.PackOptions) {
			o.SplitBytes = 64 * 1024
		}},
		{name: "big-file-chunking", modify: func(o *archive.PackOptions) {
			o.BigFileThreshold = 512 * 1024
		}},
		{name: "smart-aggressive", modify: func(o *archive.PackOptions) {
			o.Smart = smart.Aggressive
		}},
		{name: "dictionary", modify: func(o *archive.PackOptions) {
			o.Dict = "auto"
		}},
		{name: "delta-chains", modify: func(o *archive.PackOptions) {
			o.Delta = true
		}},
		{name: "delta-chains-encrypted", modify: func(o *archive.PackOptions) {
			o.Delta = true
			o.Password = "delta pw"
		}},
		{name: "preprocess-bcj", modify: func(o *archive.PackOptions) {
			o.Preprocess = "bcj"
		}},
		{name: "preprocess-delta", modify: func(o *archive.PackOptions) {
			o.Preprocess = "delta"
		}},
	}

	var failed []string
	report := func(name string, err error) {
		if err != nil {
			fmt.Println(ui.Fail(fmt.Sprintf("FAIL  %-20s %v", name, err)))
			failed = append(failed, name)
		} else {
			fmt.Println(ui.Success(fmt.Sprintf("PASS  %-20s", name)))
		}
	}

	for _, sc := range scenarios {
		report(sc.name, runScenario(srcDir, sc))
	}
	report("delta-engine", testDeltaEngine())
	report("comment", testComment(srcDir))
	report("multi-input-glob", testMultiInput(srcDir))
	report("symlink", testSymlink())
	report("list-and-test", testListAndTest(srcDir))

	report("bcj-helps", testBCJHelps(srcDir))
	report("delta-chains-size", testDeltaChainsHelp(srcDir))
	report("delta-single-file", testDeltaSingleFile(srcDir))

	total := len(scenarios) + 8
	if len(failed) > 0 {
		return fmt.Errorf("%d/%d scenarios failed: %v", len(failed), total, failed)
	}
	fmt.Println(ui.Success(fmt.Sprintf("\nall %d scenarios passed - pack/unpack round-trips are byte-for-byte intact", total)))
	return nil
}

func generateSamples(root string) error {
	files := map[string][]byte{}

	var text bytes.Buffer
	for i := 0; i < 2000; i++ {
		text.WriteString("the quick brown fox jumps over the lazy dog\n")
	}
	files["text.txt"] = text.Bytes()

	random1 := make([]byte, 64*1024)
	if _, err := rand.Read(random1); err != nil {
		return err
	}
	files["random.bin"] = random1
	files["bin/prog.elf"] = syntheticX86ELF()

	ver := make([]byte, 160*1024)
	if _, err := rand.Read(ver); err != nil {
		return err
	}
	files["docs/report_v1.dat"] = append([]byte(nil), ver...)
	copy(ver[30000:30064], bytes.Repeat([]byte{0x11}, 64))
	files["docs/report_v2.dat"] = append([]byte(nil), ver...)
	copy(ver[90000:90128], bytes.Repeat([]byte{0x22}, 128))
	files["docs/report_v3.dat"] = append(append([]byte(nil), ver...), []byte("tail added in v3")...)

	random2 := make([]byte, 128*1024)
	if _, err := rand.Read(random2); err != nil {
		return err
	}
	files["photo.jpg"] = random2

	files["empty.txt"] = []byte{}
	files["nested/dir/deep.txt"] = []byte("nested file content\n")

	dup := make([]byte, 32*1024)
	if _, err := rand.Read(dup); err != nil {
		return err
	}
	files["dup/a.bin"] = dup
	files["dup/b.bin"] = append([]byte(nil), dup...) 

	bigish := make([]byte, 1200*1024) 
	for i := range bigish {
		bigish[i] = byte(i % 251)
	}
	files["bigfile.bin"] = bigish

	ramp := make([]byte, 96*1024)
	v := 0
	for i := range ramp {
		v = (v + 1) % 256
		ramp[i] = byte(v)
	}
	files["ramp.bin"] = ramp

	for rel, data := range files {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(p, data, 0o644); err != nil {
			return err
		}
	}

	if err := os.MkdirAll(filepath.Join(root, "empty-dir", "nested-empty"), 0o755); err != nil {
		return err
	}

	return os.WriteFile(filepath.Join(root, "script.sh"), []byte("#!/bin/sh\necho hi\n"), 0o755)
}

func runScenario(srcDir string, sc scenario) error {
	workDir, err := os.MkdirTemp("", "maxzip-selftest-work-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(workDir)

	archivePath := filepath.Join(workDir, "test.mzp")
	restoreDir := filepath.Join(workDir, "restored")

	packOpt := archive.PackOptions{
		Inputs: []string{srcDir}, Output: archivePath,
		Algo: compressor.Zstd, Level: "default", Optimize: "size",
		Smart: smart.On, Threads: 2, BlockSize: 256 * 1024,
		DedupChunk: 8 * 1024,
	}
	sc.modify(&packOpt)

	if err := archive.Pack(packOpt); err != nil {
		return fmt.Errorf("pack: %w", err)
	}

	unpackOpt := archive.UnpackOptions{
		Input: archivePath, Output: restoreDir, Verify: true, Password: packOpt.Password,
	}
	if err := archive.Unpack(unpackOpt); err != nil {
		return fmt.Errorf("unpack: %w", err)
	}

	if err := compareTrees(srcDir, restoreDir, !sc.skipExecCheck); err != nil {
		return err
	}
	return checkEmptyDir(restoreDir)
}

func checkEmptyDir(restoreDir string) error {
	p := filepath.Join(restoreDir, "empty-dir", "nested-empty")
	info, err := os.Stat(p)
	if err != nil {
		return fmt.Errorf("empty directory not preserved: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("expected a directory at %s", p)
	}
	return nil
}

func compareTrees(srcDir, restoreDir string, checkExecBit bool) error {
	srcFiles, err := listFiles(srcDir)
	if err != nil {
		return err
	}
	restoredFiles, err := listFiles(restoreDir)
	if err != nil {
		return err
	}

	if len(srcFiles) != len(restoredFiles) {
		return fmt.Errorf("file count mismatch: %d original vs %d restored", len(srcFiles), len(restoredFiles))
	}

	for rel, srcInfo := range srcFiles {
		restInfo, ok := restoredFiles[rel]
		if !ok {
			return fmt.Errorf("missing after restore: %s", rel)
		}

		srcData, err := os.ReadFile(filepath.Join(srcDir, rel))
		if err != nil {
			return err
		}
		restData, err := os.ReadFile(filepath.Join(restoreDir, rel))
		if err != nil {
			return err
		}
		if !bytes.Equal(srcData, restData) {
			return fmt.Errorf("content mismatch: %s (%d bytes original, %d bytes restored)", rel, len(srcData), len(restData))
		}
		if sha256.Sum256(srcData) != sha256.Sum256(restData) {
			return fmt.Errorf("checksum mismatch: %s", rel)
		}

		if checkExecBit && runtime.GOOS != "windows" && rel == "script.sh" {
			wantExec := srcInfo.Mode().Perm()&0o111 != 0
			gotExec := restInfo.Mode().Perm()&0o111 != 0
			if wantExec != gotExec {
				return fmt.Errorf("executable bit not preserved: %s (want exec=%v, got exec=%v)", rel, wantExec, gotExec)
			}
		}
	}
	return nil
}

func listFiles(root string) (map[string]os.FileInfo, error) {
	out := map[string]os.FileInfo{}
	err := filepath.Walk(root, func(path string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if fi.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		out[filepath.ToSlash(rel)] = fi
		return nil
	})
	return out, err
}

func testDeltaEngine() error {
	ref := make([]byte, 100*1024)
	if _, err := rand.Read(ref); err != nil {
		return err
	}

	target := append([]byte(nil), ref...)
	changed := bytes.Repeat([]byte{0xAB}, 100)
	copy(target[40000:40100], changed)
	extra := make([]byte, 500)
	if _, err := rand.Read(extra); err != nil {
		return err
	}
	target = append(target, extra...)

	ops := delta.Encode(ref, target, 4096)
	marshaled := delta.Marshal(ops)
	unmarshaled, err := delta.Unmarshal(marshaled)
	if err != nil {
		return fmt.Errorf("unmarshal: %w", err)
	}

	decoded, err := delta.Decode(ref, unmarshaled)
	if err != nil {
		return fmt.Errorf("decode: %w", err)
	}

	if !bytes.Equal(decoded, target) {
		return fmt.Errorf("round-trip mismatch: got %d bytes, want %d bytes", len(decoded), len(target))
	}

	ops2 := delta.Encode(ref, ref, 4096)
	decoded2, err := delta.Decode(ref, ops2)
	if err != nil {
		return fmt.Errorf("identical-input decode: %w", err)
	}
	if !bytes.Equal(decoded2, ref) {
		return fmt.Errorf("identical-input round-trip mismatch: got %d bytes, want %d bytes", len(decoded2), len(ref))
	}

	unrelated := make([]byte, 50*1024)
	if _, err := rand.Read(unrelated); err != nil {
		return err
	}
	ops3 := delta.Encode(ref, unrelated, 4096)
	decoded3, err := delta.Decode(ref, ops3)
	if err != nil {
		return fmt.Errorf("unrelated-input decode: %w", err)
	}
	if !bytes.Equal(decoded3, unrelated) {
		return fmt.Errorf("unrelated-input round-trip mismatch: got %d bytes, want %d bytes", len(decoded3), len(unrelated))
	}

	return nil
}

func testComment(srcDir string) error {
	workDir, err := os.MkdirTemp("", "maxzip-selftest-comment-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(workDir)

	archivePath := filepath.Join(workDir, "test.mzp")
	want := "backup 2026-08-14 - test comment with unicode: سلام دنیا"

	opt := archive.PackOptions{
		Inputs: []string{srcDir}, Output: archivePath,
		Algo: compressor.Zstd, Level: "default", Optimize: "size",
		Smart: smart.On, Threads: 2, BlockSize: 256 * 1024, DedupChunk: 8 * 1024,
		Password: "irrelevant-password-should-not-be-needed-to-read-comment",
		Comment:  want,
	}
	if err := archive.Pack(opt); err != nil {
		return fmt.Errorf("pack: %w", err)
	}

	got, has, err := archive.ReadComment(archivePath)
	if err != nil {
		return fmt.Errorf("read comment (no password given): %w", err)
	}
	if !has {
		return fmt.Errorf("comment flag not set after packing with a comment")
	}
	if got != want {
		return fmt.Errorf("comment mismatch: got %q, want %q", got, want)
	}

	noCommentPath := filepath.Join(workDir, "nocomment.mzp")
	opt2 := opt
	opt2.Output = noCommentPath
	opt2.Comment = ""
	if err := archive.Pack(opt2); err != nil {
		return fmt.Errorf("pack (no comment): %w", err)
	}
	_, has2, err := archive.ReadComment(noCommentPath)
	if err != nil {
		return fmt.Errorf("read comment (no comment case): %w", err)
	}
	if has2 {
		return fmt.Errorf("comment flag set on an archive packed with no comment")
	}

	return nil
}

func testMultiInput(srcDir string) error {
	workDir, err := os.MkdirTemp("", "maxzip-selftest-multi-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(workDir)

	archivePath := filepath.Join(workDir, "test.mzp")
	restoreDir := filepath.Join(workDir, "restored")

	pattern := filepath.Join(srcDir, "*.bin") 
	explicitFile := filepath.Join(srcDir, "text.txt")
	subDir := filepath.Join(srcDir, "nested")

	opt := archive.PackOptions{
		Inputs: []string{pattern, explicitFile, subDir},
		Output: archivePath,
		Algo:   compressor.Zstd, Level: "default", Optimize: "size",
		Smart: smart.On, Threads: 2, BlockSize: 256 * 1024, DedupChunk: 8 * 1024,
	}
	if err := archive.Pack(opt); err != nil {
		return fmt.Errorf("pack: %w", err)
	}

	unpackOpt := archive.UnpackOptions{Input: archivePath, Output: restoreDir, Verify: true}
	if err := archive.Unpack(unpackOpt); err != nil {
		return fmt.Errorf("unpack: %w", err)
	}

	restored, err := listFiles(restoreDir)
	if err != nil {
		return err
	}

	mustExist := []string{"text.txt", "random.bin", "bigfile.bin", "ramp.bin", "nested/dir/deep.txt"}
	for _, name := range mustExist {
		if _, ok := restored[name]; !ok {
			return fmt.Errorf("expected file missing after multi-input pack/unpack: %s (got: %v)", name, keysOf(restored))
		}
	}

	mustNotExist := []string{"photo.jpg", "dup/a.bin", "dup/b.bin"} 
	for _, name := range mustNotExist {
		if _, ok := restored[name]; ok {
			return fmt.Errorf("file present that no input should have included: %s", name)
		}
	}

	return nil
}

func keysOf(m map[string]os.FileInfo) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func testSymlink() error {
	srcDir, err := os.MkdirTemp("", "maxzip-selftest-symlink-src-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(srcDir)

	if err := os.WriteFile(filepath.Join(srcDir, "target.txt"), []byte("symlink target content\n"), 0o644); err != nil {
		return err
	}
	linkPath := filepath.Join(srcDir, "link.txt")
	if err := os.Symlink("target.txt", linkPath); err != nil {
		fmt.Println(ui.Warn(fmt.Sprintf("  (symlink check skipped: could not create a test symlink in this environment: %v)", err)))
		return nil
	}

	workDir, err := os.MkdirTemp("", "maxzip-selftest-symlink-work-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(workDir)

	archivePath := filepath.Join(workDir, "test.mzp")
	restoreDir := filepath.Join(workDir, "restored")

	opt := archive.PackOptions{
		Inputs: []string{srcDir}, Output: archivePath,
		Algo: compressor.Zstd, Level: "default", Optimize: "size",
		Smart: smart.On, Threads: 2, BlockSize: 256 * 1024, DedupChunk: 8 * 1024,
	}
	if err := archive.Pack(opt); err != nil {
		return fmt.Errorf("pack: %w", err)
	}
	if err := archive.Unpack(archive.UnpackOptions{Input: archivePath, Output: restoreDir, Verify: true}); err != nil {
		return fmt.Errorf("unpack: %w", err)
	}

	restoredLink := filepath.Join(restoreDir, "link.txt")
	info, err := os.Lstat(restoredLink)
	if err != nil {
		return fmt.Errorf("restored symlink missing: %w", err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		return fmt.Errorf("restored entry is not a symlink")
	}
	target, err := os.Readlink(restoredLink)
	if err != nil {
		return fmt.Errorf("reading restored symlink: %w", err)
	}
	if target != "target.txt" {
		return fmt.Errorf("symlink target mismatch: got %q, want %q", target, "target.txt")
	}
	return nil
}

func testListAndTest(srcDir string) error {
	workDir, err := os.MkdirTemp("", "maxzip-selftest-listtest-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(workDir)

	archivePath := filepath.Join(workDir, "test.mzp")
	opt := archive.PackOptions{
		Inputs: []string{srcDir}, Output: archivePath,
		Algo: compressor.Zstd, Level: "default", Optimize: "size",
		Smart: smart.On, Threads: 2, BlockSize: 256 * 1024, DedupChunk: 8 * 1024,
		Password: "list-test-password",
	}
	if err := archive.Pack(opt); err != nil {
		return fmt.Errorf("pack: %w", err)
	}

	if _, err := archive.ListEntries(archivePath, ""); err == nil {
		return fmt.Errorf("list without a password succeeded on an encrypted archive - the index should be encrypted")
	}
	if _, err := archive.ListEntries(archivePath, "wrong-password"); err == nil {
		return fmt.Errorf("list with a wrong password succeeded")
	}
	entries, err := archive.ListEntries(archivePath, opt.Password)
	if err != nil {
		return fmt.Errorf("list (correct password): %w", err)
	}
	if len(entries) == 0 {
		return fmt.Errorf("list returned no entries")
	}
	found := false
	for _, e := range entries {
		if e.Name == "text.txt" {
			found = true
			if e.Size <= 0 {
				return fmt.Errorf("text.txt listed with non-positive size: %d", e.Size)
			}
		}
	}
	if !found {
		return fmt.Errorf("text.txt not found in listing: %v", entries)
	}

	if err := archive.Test(archive.TestOptions{Input: archivePath, Password: opt.Password}); err != nil {
		return fmt.Errorf("test (correct password): %w", err)
	}

	if err := archive.Test(archive.TestOptions{Input: archivePath, Password: "wrong-password"}); err == nil {
		return fmt.Errorf("test succeeded with a wrong password - should have failed")
	}

	return nil
}

func testDeltaChainsHelp(srcDir string) error {
	work, err := os.MkdirTemp("", "maxzip-selftest-delta-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(work)

	size := func(delta bool) (int64, string, error) {
		out := filepath.Join(work, fmt.Sprintf("d%v.mzp", delta))
		err := archive.Pack(archive.PackOptions{
			Inputs: []string{filepath.Join(srcDir, "docs")}, Output: out,
			Algo: compressor.Zstd, Level: "default", Smart: smart.On,
			Threads: 1, BlockSize: 8 << 20, Delta: delta,
		})
		if err != nil {
			return 0, "", err
		}
		fi, err := os.Stat(out)
		if err != nil {
			return 0, "", err
		}
		return fi.Size(), out, nil
	}
	plain, _, err := size(false)
	if err != nil {
		return err
	}
	withDelta, path, err := size(true)
	if err != nil {
		return err
	}
	if withDelta > plain*60/100 {
		return fmt.Errorf("-delta archive is %d bytes vs %d without it; expected well under 60%%", withDelta, plain)
	}
	if err := archive.Test(archive.TestOptions{Input: path}); err != nil {
		return fmt.Errorf("test: %w", err)
	}
	restore := filepath.Join(work, "restore")
	if err := archive.Unpack(archive.UnpackOptions{Input: path, Output: restore, Verify: true}); err != nil {
		return fmt.Errorf("unpack: %w", err)
	}
	return compareTrees(filepath.Join(srcDir, "docs"), restore, false)
}

func testDeltaSingleFile(srcDir string) error {
	work, err := os.MkdirTemp("", "maxzip-selftest-delta1-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(work)
	out := filepath.Join(work, "d.mzp")
	if err := archive.Pack(archive.PackOptions{
		Inputs: []string{filepath.Join(srcDir, "docs")}, Output: out,
		Algo: compressor.Zstd, Level: "default", Smart: smart.On,
		Threads: 1, BlockSize: 8 << 20, Delta: true, Password: "pw",
	}); err != nil {
		return err
	}
	restore := filepath.Join(work, "r")
	if err := archive.Unpack(archive.UnpackOptions{Input: out, Output: restore, Password: "pw", OnlyFile: "report_v3.dat", Verify: true}); err != nil {
		return err
	}
	got, err := os.ReadFile(filepath.Join(restore, "report_v3.dat"))
	if err != nil {
		return err
	}
	want, err := os.ReadFile(filepath.Join(srcDir, "docs", "report_v3.dat"))
	if err != nil {
		return err
	}
	if !bytes.Equal(got, want) {
		return fmt.Errorf("report_v3.dat differs after single-file extraction from a delta chain")
	}
	return nil
}

func syntheticX86ELF() []byte {
	b := make([]byte, 64)
	copy(b, "\x7fELF\x02\x01\x01")
	b[18] = 62 
	targets := []uint32{0x1000, 0x2340, 0x3a10, 0x5000, 0x7fe0}
	filler := []byte{0x55, 0x48, 0x89, 0xe5, 0x90, 0x5d, 0xc3, 0x31, 0xc0}
	for i := 0; i < 6000; i++ {
		b = append(b, filler[i%len(filler)], filler[(i*7)%len(filler)])
		pos := uint32(len(b))
		rel := targets[(i*13)%len(targets)] - (pos + 5)
		b = append(b, 0xE8, byte(rel), byte(rel>>8), byte(rel>>16), byte(rel>>24))
	}
	return b
}

func testBCJHelps(srcDir string) error {
	work, err := os.MkdirTemp("", "maxzip-selftest-bcj-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(work)
	size := func(mode string) (int64, string, error) {
		out := filepath.Join(work, "b"+mode+".mzp")
		err := archive.Pack(archive.PackOptions{
			Inputs: []string{filepath.Join(srcDir, "bin")}, Output: out,
			Algo: compressor.Zstd, Level: "default", Smart: smart.On, Threads: 1,
			BlockSize: 8 << 20, Preprocess: mode,
		})
		if err != nil {
			return 0, "", err
		}
		fi, err := os.Stat(out)
		if err != nil {
			return 0, "", err
		}
		return fi.Size(), out, nil
	}
	plain, _, err := size("off")
	if err != nil {
		return err
	}
	withBCJ, path, err := size("bcj")
	if err != nil {
		return err
	}
	if withBCJ >= plain {
		return fmt.Errorf("bcj archive is %d bytes, plain is %d: no gain on an executable full of calls", withBCJ, plain)
	}
	restore := filepath.Join(work, "r")
	if err := archive.Unpack(archive.UnpackOptions{Input: path, Output: restore, Verify: false}); err != nil {
		return err
	}
	return compareTrees(filepath.Join(srcDir, "bin"), restore, false)
}
