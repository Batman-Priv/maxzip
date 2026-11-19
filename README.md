# maxzip

**A modern, modular archiver that actually tries to beat RAR and ZIP — instead of assuming it can't.**

maxzip is a general-purpose command-line archiver written in Go. It packs and unpacks files with five compression algorithms, real deduplication, integrity verification at every layer, and a solid-block architecture designed for both ratio and speed — all in a single static binary with no external dependencies.

```bash
maxzip pack -i ./project -o backup.mzp -preset ultra
maxzip unpack -i backup.mzp -o ./restored
```

---

## Table of contents

- [Why maxzip](#why-maxzip)
- [How it compares](#how-it-compares)
- [Benchmark](#benchmark)
- [Choosing a preset](#choosing-a-preset)
- [Install](#install)
- [Quick start](#quick-start)
- [Features](#features)
- [Architecture](#architecture)
- [Command reference](#command-reference)
- [Verifying this build](#verifying-this-build)
- [Known limitations](#known-limitations)
- [Project layout](#project-layout)

---

## Why maxzip

Most "better than zip" tools stop at picking a stronger codec. maxzip goes further: it doesn't *guess* what will compress well — it tests, compares, and keeps whichever result is actually smaller. That single design principle, applied consistently, is what closes the gap with (and often beats) RAR and 7-Zip on real-world data:

- **It never trusts a heuristic when it can just check.** Old-school "smart" compression skips files by file extension alone — meaning a JPEG or APK that actually *does* have a few percent of recoverable slack (build tools rarely compress at maximum, JPEG Huffman tables are rarely optimal) gets silently stored raw and that slack is lost forever. At `-level better`/`best` (and so `-preset best`/`ultra`) maxzip runs the real algorithm on every file type except video/audio, and only stores raw when compression genuinely doesn't help. At faster levels a quick zstd probe skips the work on files that barely shrink.
- **It never lets an optimization make things worse.** Dictionaries, smart-store heuristics, and algorithm choices are all built, tested, and compared against the alternative before being committed to the archive. If a dictionary would bloat a block instead of shrinking it, maxzip throws it away and keeps the plain result. You should never see an archive that's *bigger* than doing nothing.
- **It's built to be verified, not just trusted.** Every block, every file, the footer index, and the header each carry their own checksum. A one-command self-test suite (`maxzip selftest`) round-trips real data through every mode and diffs the result byte-for-byte — because a claim of correctness is only as good as the test that backs it up.

## How it compares

| | **maxzip** | ZIP | RAR / WinRAR | 7-Zip |
|---|---|---|---|---|
| Compression algorithms | zstd, xz, deflate, lz4, brotli (+ auto-select) | deflate only | proprietary | LZMA2, deflate |
| Solid compression | ✅ block-based, parallel | ❌ | ✅ | ✅ |
| Deduplication | ✅ content-defined chunking | ❌ | ❌ | ❌ |
| Delta between file versions | ✅ `-delta` | ❌ | ❌ | ❌ |
| x86 executable filter (BCJ) | ✅ `-preprocess bcj` | ❌ | ✅ | ✅ |
| Auto compress-or-store per block | ✅ always tested, never assumed | ❌ | partial | partial |
| Shared dictionary for small files | ✅ | ❌ | ❌ | ❌ |
| Multi-volume splitting | ✅ opt-in | ✅ | ✅ | ✅ |
| Encryption | AES-256-GCM + Argon2id, encrypted file names | weak (legacy) or AES | AES-256 | AES-256 |
| Archive comment | ✅ | ✅ | ✅ | ❌ |
| List/test without extracting | ✅ | ✅ | ✅ | ✅ |
| Per-block *and* per-file integrity checks | ✅ SHA-256 (+ GCM authentication when encrypted) | CRC32 only | CRC32 | CRC32/SHA |
| Symlink support | ✅ | partial | ✅ | ✅ |
| Open source, single static binary | ✅ | varies | ❌ closed source | ✅ |
| Self-test suite included | ✅ `maxzip selftest` | ❌ | ❌ | ❌ |

maxzip won't always win — RAR and 7-Zip are mature, heavily-optimized tools with decades of tuning. But on general-purpose data, and especially on the "should compress a little but nobody bothered to check" files that make up most real backups (APKs, office documents, loosely-compressed media), maxzip's test-then-decide approach tends to close or beat the gap.

## Benchmark

These are real measurements from the author's own testing, not a synthetic suite. They are **one dataset on one machine** — treat them as an illustration of the trade-offs, not as a general ranking. Please run your own data (see "Reproduce it" below).

**Test setup:** a 23 MB folder, packed on an Android phone (Termux). RAR was run with its default settings for comparison.

| Tool / command | Output size | vs. RAR | Speed |
|---|---:|---:|---|
| RAR | ≈ 9.60 MB | — | — |
| maxzip `-algo xz -level best -block-size 4MB` | 9,636,611 B (≈ 9.64 MB) | ≈ +0.4 % | fast |
| maxzip `-preset ultra -block-size 5MB` | **9,508,158 B (≈ 9.51 MB)** | **≈ −1.0 %** | **slow** |

What the numbers say:

- `-preset ultra` produced the smallest archive, about 1 % below RAR and about 1.3 % below xz.
- In this run `-algo auto` selected **brotli at level 11**: packing the same folder with `-algo brotli -level best` produced a byte-for-byte identical size (9,508,158 B). The slow part of `ultra` is therefore brotli-11, not something specific to maxzip's container.
- The xz run was clearly faster and landed within half a percent of RAR. For most uses that is the better trade; `ultra` is for when the last percent matters more than the time.
- `-smart aggressive` and block size (4 MB vs 5 MB) did not change the xz result at all (identical byte counts), so the whole difference came from the codec.

Observations on other data types (qualitative, from the same testing):

- **Images:** maxzip came out smaller than both ZIP and RAR.
- **Video (a folder of three videos, 88 MB total):** slightly smaller than the alternatives, but slow. Already-compressed video leaves only a few percent to recover, which is rarely worth `ultra`-level effort — see [Choosing a preset](#choosing-a-preset).
- **MP3 music:** RAR came out ahead. MP3 is already lossy-compressed; no lossless archiver has much to gain, so differences are tiny and come from container overhead and per-file metadata.

Timings were not recorded for the table above, so none are claimed. If you publish your own numbers, please include the machine, core count and wall-clock time.

### Reproduce it

```bash
# Smallest output (slow): auto-select + best level
time maxzip pack -i ./folder -o a.mzp -preset ultra -block-size 5MB

# Fast and close to RAR
time maxzip pack -i ./folder -o b.mzp -algo xz -level best -block-size 4MB

# Isolate what `ultra` actually picked
time maxzip pack -i ./folder -o c.mzp -algo brotli -level best -block-size 5MB
```

`pack` prints a line like `auto-select (size): ... -> chosen brotli` when `-algo auto` is used, with the size and time of every candidate on a 2 MB sample.

## Choosing a preset

| Preset | Codec / level | Meant for |
|---|---|---|
| `fast` | zstd, fastest | Speed first; backups you want done now. |
| `balanced` | zstd, default | Good ratio at high speed. |
| `best` | xz, best, 128 MB blocks, smart aggressive | Small output; moderate time. |
| `ultra` | auto-select, best, smart aggressive, dictionary auto, 128 MB blocks | Smallest output; slowest. |

Practical tips:

- **`ultra` is slow by design.** At level `best`, xz and brotli try many alternatives per position, and they are pure-Go implementations. Brotli-11 in particular runs well below 1 MB/s per thread.
- **xz and brotli compress one block on one thread.** A block is the unit of parallelism, so a folder that fits in one block uses one CPU core no matter how many you have. Lower `-block-size` (for example `-block-size 4MB`) so there are several blocks to spread over your cores. The cost is a slightly larger archive, because blocks cannot see each other's data.
- **A single file is never split across blocks** (unless it exceeds `-big-file-threshold`), so one large file is bounded by one thread.
- **Trade ratio for speed with `-level better`**, which is much faster than `best` for xz and brotli and usually costs a few percent in size.
- **Skip the auto-select cost with an explicit codec.** `-algo auto` benchmarks five codecs on a sample before packing starts; `-algo brotli` or `-algo xz` skips that step.
- **Media (video/audio):** these blocks gain very little from any codec. Use `-preset fast`/`balanced`, or let maxzip's probe store them raw. When `ultra`/`best` picks xz or brotli, media blocks that survive the probe are compressed with zstd (`better`) instead, because xz/brotli would turn a few percent of gain into minutes.
- **zstd uses extra cores inside a block** when there are fewer blocks than workers; xz and brotli cannot.

## Install

```bash
git clone https://gitlab.com/specterog/maxzip
cd maxzip
go mod tidy
go build .
```

### Direct Install

```bash
go install gitlab.com/specterog/maxzip@v0.1.2
```

## Quick start

```bash
# Pack a folder with the best all-around preset
maxzip pack -i ./photos -o photos.mzp -preset ultra

# Pack multiple inputs, including a glob pattern (works on Windows too —
# maxzip expands the pattern itself, it doesn't rely on the shell)
maxzip pack -i "*.pdf" -i ./contracts -i notes.txt -o docs.mzp

# Encrypt and comment
maxzip pack -i ./backup -o backup.mzp -password "correct horse battery staple" -comment "Weekly backup — 2026-08-14"

# Deduplicate near-identical files (VM images, versioned backups)
maxzip pack -i ./vm-snapshots -o snapshots.mzp -dedup

# See what's inside without extracting
maxzip list -i backup.mzp

# Verify integrity without writing anything to disk
maxzip test -i backup.mzp -password "..."

# Read the comment, no password needed
maxzip comment -i backup.mzp

# Extract everything, or just one file
maxzip unpack -i backup.mzp -o ./restored
maxzip unpack -i backup.mzp -o ./restored -file "contracts/lease.pdf"
```

## Features

**Compression**
- Five codecs — zstd, xz, deflate, lz4, brotli — selectable per archive, or let `-algo auto` benchmark all five on a sample and pick the smallest.
- Solid-block architecture: files are grouped by extension for locality and compressed together in parallel blocks, keeping most of the ratio benefit of a fully solid archive while staying corruption-isolated and individually extractable.
- Compress-or-store is always decided empirically, per block — never assumed from a file extension. This is what actually closes the gap with RAR on formats like APKs and JPEGs.
- Already-compressed media (video/audio/archives) is kept in separate, smaller blocks so all CPU cores get work instead of one oversized block.
- A frequency-scored shared dictionary (`-dict auto`) helps when you're archiving many small, similar files (configs, logs, source trees) — and is automatically discarded per-block if it doesn't pay off.
- Content-defined chunking deduplication (`-dedup`) for collections with repeated content across files — VM snapshots, versioned backups, redundant project exports.
- Optional automatic chunking for individual huge files (`-big-file-threshold`), so one enormous file never becomes a single unparallelizable, memory-heavy block.

**Integrity & safety**
- SHA-256 on every file, every block, the footer index, and the header — nearly every byte of the archive is checksummed.
- `maxzip test` verifies an entire archive without touching disk.
- Encryption is AES-256-GCM with Argon2id key derivation (3 passes, 128 MiB; the parameters are stored in the header), applied after compression (encrypting first would make compression pointless).
- Every encrypted stream gets its own random 128-bit ID and its own sub-key, so nonces can never repeat under one key however large the archive is. Every chunk is authenticated together with its position, a "final" flag and the stream's role/block index, so truncating, reordering or transplanting encrypted data is detected.
- For encrypted archives the **index is encrypted and authenticated too**: file names, sizes and hashes are not readable (or forgeable) without the password. Only the archive comment stays in plaintext, by design.
- Filtered files (`-preprocess delta|bcj`) and delta-chain members (`-delta`) are *always* integrity-verified on extraction, even if you passed `-no-verify` — an experimental code path should fail loudly, never silently.
- **Hardened extraction**: entry names are validated (no `..`, no absolute paths or drive letters, no NUL), nothing is ever written through a symlink inside the output directory, extracted size is capped at what the index promises (no decompression bombs), and every length/count read from an archive is bounded by the archive's real size before anything is allocated.

**Usability**
- Multiple inputs and glob patterns in one command (`-i "*.pdf" -i ./docs`), expanded by maxzip itself so it works identically on Windows (cmd.exe/PowerShell don't expand globs) and Unix shells.
- Ready-made presets (`-preset fast|balanced|best|ultra`).
- A live progress bar on `pack` and `unpack` that advances while data is being compressed, with throughput and ETA; colored success/error output (respects `NO_COLOR`).
- Symlinks, file permissions, and modification times are preserved.
- Optional multi-volume splitting for archives that need to span several files.
- `-delta`: inside a solid block, a file that looks like another version of an earlier file (same extension, same letters in the name once digits/punctuation are dropped — `report_v1.docx`, `report_v2.docx`) is stored as a binary diff against it when that is clearly smaller. Extracting a single file rebuilds its chain in memory.
- `-preprocess bcj`: x86/x86-64 ELF and PE executables get their CALL/JMP operands rewritten to absolute addresses (the 7-Zip/xz BCJ idea), which compresses noticeably better; other files are untouched.
- Uncompressed audio (WAV) is treated as compressible, not as already-compressed media; only WEBP and AVI use the RIFF container for incompressible data.
- Archive comments, viewable without a password.
- `maxzip list` / `maxzip test` — inspect or verify an archive without ever extracting it.

## Architecture

Every package under `internal/` has exactly one responsibility and depends only on the layers below it — `fsutil`, `format`, `cryptoutil`, `compressor`, `dictionary`, and `volume` have no internal dependencies at all; `archive` is the only package that ties everything together.

## Command reference

### `pack`

| Flag | Description |
|---|---|
| `-i / -input` | File, directory, or glob pattern. Repeatable. |
| `-o / -output` | Output archive path. |
| `-preset` | `fast`, `balanced`, `best`, or `ultra` — sets several flags at once; anything you also pass explicitly wins. |
| `-algo` | `zstd`, `xz`, `deflate`, `lz4`, `brotli`, or `auto`. |
| `-level` | `fastest`, `default`, `better`, `best`. |
| `-optimize` | `size`, `speed`, or `balanced` — used with `-algo auto`. |
| `-password` | Encrypts the archive (AES-256-GCM). `-password -` reads it from stdin; if the flag is absent, `$MAXZIP_PASSWORD` is used. A password given directly on the command line is visible in the process list and shell history. |
| `-comment` | Free-text comment, readable later without a password. |
| `-smart` | `off`, `on`, or `aggressive` — how hard to check before deciding not to compress a file. |
| `-block-size` | Target uncompressed size per solid block. Smaller blocks = more parallelism for xz/brotli, slightly larger archives. |
| `-split` | Split into fixed-size volumes (off unless set). |
| `-dict` | `off` or `auto`. |
| `-dedup` | Enable content-defined-chunking deduplication. |
| `-dedup-chunk-size` | Target average chunk size for `-dedup`. |
| `-big-file-threshold` | Auto-chunk single files above this size (off unless set). |
| `-preprocess` | `off`, `delta` (experimental byte-delta) or `bcj` (x86 executables). |
| `-delta` / `-delta-max` | Store similar file versions as diffs; largest file considered (default 32MB). Normal mode only. |
| `-threads` | Parallel block-compression workers (default: all CPU cores). |
| `-exclude` | Comma-separated glob patterns to skip. |
| `-verbose` | Print per-block/per-file detail. |

### `unpack`

`-i/-input`, `-o/-output`, `-password`, `-file` (extract a single entry), `-no-verify`, `-verbose`

### `list`, `test`, `comment`

```bash
maxzip list -i archive.mzp
maxzip test -i archive.mzp [-password ...]
maxzip comment -i archive.mzp
```

`comment` never needs a password. For an encrypted archive, `list` and `test` do, because the index (file names, sizes, hashes) is encrypted too.

## Verifying this build

```bash
go build -o maxzip ./cmd/maxzip
maxzip selftest
```

`selftest` generates real sample data (text, random binary, duplicate content, an executable file, a symlink, an empty directory, a large file) and round-trips it through every mode — zstd, xz, auto-select, dedup, encryption, multi-volume splitting, automatic big-file chunking, the smart-store probe, the dictionary, the delta preprocessor, the standalone delta engine, comments, multi-input/glob packing, symlinks, and `list`/`test` — comparing every result byte-for-byte against the original. This is the definitive way to confirm a given build works correctly on your machine and OS.

## Known limitations

Said plainly, not buried in fine print:

- **Speed at the highest levels.** xz and brotli come from pure-Go libraries, which are several times slower per core than the C reference implementations, and `-level best` (especially brotli-11) is slow in any language. Neither codec can use several threads inside one block, so parallelism comes only from having several blocks. `-preset ultra` additionally benchmarks five codecs on a 2 MB sample before it starts, and may build each block twice when a zstd dictionary is in play.
- **A file is never split across blocks** (except through `-big-file-threshold` chunking), so one very large file is limited to one thread for xz/brotli.
- **Auto-select decides once per archive,** from the first ~2 MB of input, not per file type or per block.
- **No real COVER dictionary trainer.** `-dict auto` uses a frequency-scored heuristic, not zstd's official suffix-array-based training algorithm.
- **Only two preprocessors exist: the byte-delta filter and x86 BCJ.** ARM/ARM64/PowerPC executable filters, audio-aware filters for WAV/PCM, and numeric-data transforms are not implemented.
- **`-delta` is per solid block and per file.** A version chain is only found when the versions land in the same block; files larger than `-delta-max` are skipped; it is ignored with `-dedup`.
- **Each block is read into memory to extract it** (default block size 64MB), so memory use is about one block per extraction.
- **In `-dedup` mode the encrypted blocks are bound to their role but not to their position**; swapping two blocks is still caught by the authenticated index (file hashes), just later.
- **Lossless recompression of already-compressed media (JPEG, MP3, video) isn't attempted.** No general-purpose archiver can meaningfully shrink an H.264 stream, an MP3 or a JPEG without either specialized entropy-recoding (JPEG) or lossy re-encoding (video, audio) — both are out of scope for an archiver.
- **Symlink restoration on Windows** typically requires Developer Mode or an elevated process, per Go's standard library behavior — this is a Windows platform constraint, not a maxzip-specific limitation.
- **Archive format is not stable across versions yet.** Each format revision so far has been a breaking change; don't rely on long-term archival compatibility until the format is explicitly versioned as stable.

## Tests

```bash
go test ./...        # unit tests: crypto, path safety, tamper/truncation, BCJ, delta
maxzip selftest      # end-to-end round trips through every mode
```