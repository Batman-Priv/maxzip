// maxzip - a smarter, stronger general-purpose archiver than zip/rar.
//
// See the README for the full feature list and architecture notes. This
// file is just flag parsing; all real logic lives in the internal/
// packages, one per concern:
//
//	internal/fsutil      - collecting files from disk
//	internal/format      - archive header/footer binary layout
//	internal/cryptoutil  - AES-256-GCM encryption, Argon2id KDF
//	internal/compressor  - zstd/xz/deflate/lz4/brotli + auto-benchmark
//	internal/dictionary  - frequency-based zstd dictionary
//	internal/smart       - detecting already-compressed files
//	internal/block       - solid-block packing (normal mode, symlinks)
//	internal/dedup       - content-defined chunking (dedup mode / big files)
//	internal/volume      - multi-volume split/join
//	internal/ui          - colored terminal output
//	internal/archive     - ties everything together (Pack/Unpack/List/Test)
package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"runtime"
	"strings"

	"gitlab.com/specterog/maxzip/internal/archive"
	"gitlab.com/specterog/maxzip/internal/compressor"
	"gitlab.com/specterog/maxzip/internal/selftest"
	"gitlab.com/specterog/maxzip/internal/smart"
	"gitlab.com/specterog/maxzip/internal/ui"
	"gitlab.com/specterog/maxzip/internal/volume"
)

// stringList collects a flag repeated multiple times, e.g. -i a.txt -i b.txt.
type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error {
	*s = append(*s, v)
	return nil
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}
	switch os.Args[1] {
	case "pack":
		cmdPack(os.Args[2:])
	case "unpack":
		cmdUnpack(os.Args[2:])
	case "list":
		cmdList(os.Args[2:])
	case "test":
		cmdTest(os.Args[2:])
	case "comment":
		cmdComment(os.Args[2:])
	case "selftest":
		cmdSelftest()
	default:
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Println(`maxzip - a smarter, stronger archiver than zip/rar

Usage:
  maxzip pack     -i <input dir/file/pattern> -o <output.mzp> [flags]
  maxzip unpack   -i <archive.mzp>             -o <output dir> [flags]
  maxzip list     -i <archive.mzp> [-password <pw>]
  maxzip test     -i <archive.mzp> [-password <pw>]
  maxzip comment  -i <archive.mzp>
  maxzip selftest

Run "maxzip pack -h" or "maxzip unpack -h" to see all flags.
"list" prints every file's name and size without extracting anything.
"test" verifies every checksum in the archive (header, footer, every block,
every file) without writing anything to disk.
"comment" prints an archive's stored comment (set at pack time with
-comment "text"); it never needs a password. For encrypted archives the
index (file names, sizes, hashes) is encrypted too, so "list" and "test"
need the password.
Passwords: "-password -" reads one line from stdin; if -password is not
given at all, the MAXZIP_PASSWORD environment variable is used. Passing the
password directly on the command line works but is visible to other users
via the process list and in shell history.
"selftest" packs and unpacks generated sample data through every mode and
checks the result is byte-for-byte identical to the input - the real way
to verify this build actually works, not just that it compiles.`)
}

func cmdSelftest() {
	if err := selftest.Run(); err != nil {
		fmt.Fprintln(os.Stderr, ui.Fail("\nerror: "+err.Error()))
		os.Exit(1)
	}
}

func cmdList(args []string) {
	fs := flag.NewFlagSet("list", flag.ExitOnError)
	var input, password string
	fs.StringVar(&input, "i", "", "archive file to list (required)")
	fs.StringVar(&input, "input", "", "archive file to list (required)")
	fs.StringVar(&password, "password", "", passwordHelp)
	fs.Parse(args)
	password = resolvePassword(password)

	if input == "" {
		fmt.Fprintln(os.Stderr, "error: -i/-input is required")
		fs.Usage()
		os.Exit(1)
	}

	entries, err := archive.ListEntries(input, password)
	must(err)
	if len(entries) == 0 {
		fmt.Println("(empty archive)")
		return
	}
	var total int64
	for _, e := range entries {
		fmt.Printf("%12d  %s\n", e.Size, e.Name)
		total += e.Size
	}
	fmt.Println(ui.Success(fmt.Sprintf("\n%d files, %d bytes total", len(entries), total)))
}

func cmdTest(args []string) {
	fs := flag.NewFlagSet("test", flag.ExitOnError)
	var input, password string
	fs.StringVar(&input, "i", "", "archive file to test (required)")
	fs.StringVar(&input, "input", "", "archive file to test (required)")
	fs.StringVar(&password, "password", "", passwordHelp)
	fs.Parse(args)
	password = resolvePassword(password)

	if input == "" {
		fmt.Fprintln(os.Stderr, "error: -i/-input is required")
		fs.Usage()
		os.Exit(1)
	}

	if err := archive.Test(archive.TestOptions{Input: input, Password: password}); err != nil {
		fmt.Fprintln(os.Stderr, ui.Fail("error: "+err.Error()))
		os.Exit(1)
	}
}

// presetValues holds the flag values a -preset name maps to. Only used to
// fill in flags the user did NOT explicitly pass - an explicit flag always
// wins over a preset.
type presetValues struct {
	algo, level, optimize, smart, dict, blockSize string
}

var presets = map[string]presetValues{
	"fast": {
		algo: "zstd", level: "fastest", optimize: "speed",
		smart: "on", dict: "off", blockSize: "64MB",
	},
	"balanced": {
		algo: "zstd", level: "default", optimize: "balanced",
		smart: "on", dict: "off", blockSize: "64MB",
	},
	"best": {
		algo: "xz", level: "best", optimize: "size",
		smart: "aggressive", dict: "off", blockSize: "128MB",
	},
	"ultra": {
		algo: "auto", level: "best", optimize: "size",
		smart: "aggressive", dict: "auto", blockSize: "128MB",
	},
}

func cmdPack(args []string) {
	fs := flag.NewFlagSet("pack", flag.ExitOnError)
	var inputs stringList
	var output, algoStr, level, optimize, password, excludeStr, presetStr string
	var smartStr, blockSizeStr, splitStr, dictStr, dedupChunkStr, bigFileStr, preprocessStr, comment string
	var threads int
	var dedup, verbose, deltaOn bool
	var deltaMaxStr string

	fs.Var(&inputs, "i", `input file, directory, or glob pattern (e.g. "*.pdf") - repeat to combine several, e.g. -i a.txt -i ./photos -i "*.pdf" (required; quote patterns if your shell auto-expands them)`)
	fs.Var(&inputs, "input", `same as -i - repeat to combine several inputs`)
	fs.StringVar(&output, "o", "", "output archive path (required)")
	fs.StringVar(&output, "output", "", "output archive path (required)")
	fs.StringVar(&presetStr, "preset", "", "fast, balanced, best, or ultra: fills in algo/level/optimize/smart/dict/block-size at once; any flag you also pass explicitly overrides the preset for that one setting")
	fs.StringVar(&algoStr, "algo", "zstd", "compression algorithm: zstd, xz, deflate, lz4, brotli, or auto")
	fs.StringVar(&level, "level", "best", "compression level: fastest, default, better, best")
	fs.StringVar(&optimize, "optimize", "size", "when -algo auto: size, speed, or balanced")
	fs.StringVar(&password, "password", "", "encrypt the archive with this password (AES-256-GCM); "+passwordHelp)
	fs.StringVar(&excludeStr, "exclude", "", `comma-separated glob patterns to skip, e.g. "*.tmp,*.log"`)
	fs.StringVar(&smartStr, "smart", "on", "smart store mode: off, on (extension+magic-byte), aggressive (+ sample test)")
	fs.StringVar(&blockSizeStr, "block-size", "64MB", "target uncompressed size per solid block")
	fs.StringVar(&splitStr, "split", "", "split the archive into fixed-size volumes, e.g. 700MB, 4GB (off by default - only happens if you set this)")
	fs.StringVar(&dictStr, "dict", "off", "off or auto: build a small shared zstd dictionary from the smallest files")
	fs.BoolVar(&dedup, "dedup", false, "deduplicate identical content across files using content-defined chunking")
	fs.StringVar(&dedupChunkStr, "dedup-chunk-size", "256KB", "target average chunk size for -dedup")
	fs.StringVar(&bigFileStr, "big-file-threshold", "", "off by default. If set (e.g. 500MB), any single file larger than this is chunked instead of forming one giant block - only happens if you set this")
	fs.StringVar(&preprocessStr, "preprocess", "off", "off, delta or bcj. delta: EXPERIMENTAL byte-delta filter on every file. bcj: x86 executables (ELF/PE) get call/jump addresses made absolute, which compresses better. Normal mode only; filtered files are always integrity-verified regardless of -no-verify")
	fs.BoolVar(&deltaOn, "delta", false, "store files that look like another version of an earlier file in the same block (same extension and name apart from digits/punctuation, e.g. report_v1.docx / report_v2.docx) as a binary diff against it, when that is clearly smaller; normal mode only")
	fs.StringVar(&deltaMaxStr, "delta-max", "32MB", "largest file considered by -delta (both versions are held in memory while diffing)")
	fs.StringVar(&comment, "comment", "", `optional text stored in the archive, viewable later with "maxzip comment -i <archive>" - no password needed even for encrypted archives`)
	fs.BoolVar(&verbose, "verbose", false, "print per-file/per-block detail in addition to the progress bar")
	fs.IntVar(&threads, "threads", runtime.NumCPU(), "parallel block-compression workers (ignored by -dedup, which chunks sequentially)")
	fs.Parse(args)
	password = resolvePassword(password)

	if len(inputs) == 0 || output == "" {
		fmt.Fprintln(os.Stderr, "error: -i/-input (at least one) and -o/-output are required")
		fs.Usage()
		os.Exit(1)
	}

	if presetStr != "" {
		p, ok := presets[presetStr]
		if !ok {
			must(fmt.Errorf("unknown -preset %q (use fast, balanced, best or ultra)", presetStr))
		}
		explicit := map[string]bool{}
		fs.Visit(func(f *flag.Flag) { explicit[f.Name] = true })
		if !explicit["algo"] {
			algoStr = p.algo
		}
		if !explicit["level"] {
			level = p.level
		}
		if !explicit["optimize"] {
			optimize = p.optimize
		}
		if !explicit["smart"] {
			smartStr = p.smart
		}
		if !explicit["dict"] {
			dictStr = p.dict
		}
		if !explicit["block-size"] {
			blockSizeStr = p.blockSize
		}
	}

	algo, err := compressor.ParseAlgo(algoStr)
	must(err)
	level, err = compressor.ParseLevel(level)
	must(err)
	smartMode, err := smart.ParseMode(smartStr)
	must(err)
	blockSize, err := volume.ParseSize(blockSizeStr)
	must(err)
	splitBytes, err := volume.ParseSize(splitStr)
	must(err)
	dedupChunk, err := volume.ParseSize(dedupChunkStr)
	must(err)
	bigFileThreshold, err := volume.ParseSize(bigFileStr)
	must(err)
	deltaMax, err := volume.ParseSize(deltaMaxStr)
	must(err)
	if deltaOn && dedup {
		fmt.Fprintln(os.Stderr, ui.Warn("warning: -delta has no effect together with -dedup (dedup already removes repeated content); ignoring -delta"))
	}
	if dictStr != "off" && dictStr != "auto" {
		must(fmt.Errorf("unknown -dict value %q (use off or auto)", dictStr))
	}
	if preprocessStr != "off" && preprocessStr != "delta" && preprocessStr != "bcj" {
		must(fmt.Errorf("unknown -preprocess value %q (use off, delta or bcj)", preprocessStr))
	}
	if optimize != "size" && optimize != "speed" && optimize != "balanced" {
		must(fmt.Errorf("unknown -optimize value %q (use size, speed or balanced)", optimize))
	}

	var exclude []string
	if excludeStr != "" {
		exclude = splitComma(excludeStr)
	}

	opt := archive.PackOptions{
		Inputs: inputs, Output: output, Algo: algo, Level: level, Optimize: optimize,
		Password: password, Smart: smartMode, Dict: dictStr,
		Dedup: dedup, DedupChunk: dedupChunk, Delta: deltaOn, DeltaMax: deltaMax,
		Threads: threads, Exclude: exclude, BlockSize: blockSize, SplitBytes: splitBytes,
		BigFileThreshold: bigFileThreshold, Verbose: verbose, Preprocess: preprocessStr,
		Comment: comment,
	}
	must(archive.Pack(opt))
}

func cmdUnpack(args []string) {
	fs := flag.NewFlagSet("unpack", flag.ExitOnError)
	var input, output, password, onlyFile string
	var noVerify, verbose bool

	fs.StringVar(&input, "i", "", "archive file to extract (required)")
	fs.StringVar(&input, "input", "", "archive file to extract (required)")
	fs.StringVar(&output, "o", "", "destination directory (required)")
	fs.StringVar(&output, "output", "", "destination directory (required)")
	fs.StringVar(&password, "password", "", passwordHelp)
	fs.StringVar(&onlyFile, "file", "", "extract only this single file path from the archive")
	fs.BoolVar(&noVerify, "no-verify", false, "skip SHA-256 integrity verification of file contents (not recommended: corruption would go unnoticed; filtered/delta files are still verified)")
	fs.BoolVar(&verbose, "verbose", false, "print per-file detail in addition to the progress bar")
	fs.Parse(args)
	password = resolvePassword(password)

	if input == "" || output == "" {
		fmt.Fprintln(os.Stderr, "error: -i/-input and -o/-output are required")
		fs.Usage()
		os.Exit(1)
	}

	opt := archive.UnpackOptions{
		Input: input, Output: output, Password: password,
		OnlyFile: onlyFile, Verify: !noVerify, Verbose: verbose,
	}
	must(archive.Unpack(opt))
}

func cmdComment(args []string) {
	fs := flag.NewFlagSet("comment", flag.ExitOnError)
	var input string
	fs.StringVar(&input, "i", "", "archive file to read the comment from (required)")
	fs.StringVar(&input, "input", "", "archive file to read the comment from (required)")
	fs.Parse(args)

	if input == "" {
		fmt.Fprintln(os.Stderr, "error: -i/-input is required")
		fs.Usage()
		os.Exit(1)
	}

	comment, has, err := archive.ReadComment(input)
	must(err)
	if !has || comment == "" {
		fmt.Println("(no comment)")
		return
	}
	fmt.Println(comment)
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, ui.Fail("error: "+err.Error()))
		os.Exit(1)
	}
}

func splitComma(s string) []string {
	var out []string
	cur := ""
	for _, r := range s {
		if r == ',' {
			if cur != "" {
				out = append(out, cur)
			}
			cur = ""
			continue
		}
		cur += string(r)
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}

const passwordHelp = `password ("-" = read from stdin; default: $MAXZIP_PASSWORD)`

// resolvePassword implements the password sources: an explicit value, "-"
// for one line from stdin, or the MAXZIP_PASSWORD environment variable when
// the flag was left empty.
func resolvePassword(v string) string {
	switch v {
	case "-":
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && line == "" {
			must(fmt.Errorf("reading password from stdin: %v", err))
		}
		return strings.TrimRight(line, "\r\n")
	case "":
		return os.Getenv("MAXZIP_PASSWORD")
	default:
		fmt.Fprintln(os.Stderr, ui.Warn("warning: a password given on the command line is visible to other users (process list, shell history); consider \"-password -\" or MAXZIP_PASSWORD"))
		return v
	}
}
