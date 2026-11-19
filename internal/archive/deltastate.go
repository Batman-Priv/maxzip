package archive

import (
	"archive/tar"
	"bytes"
	"fmt"
	"io"

	"gitlab.com/specterog/maxzip/internal/block"
	"gitlab.com/specterog/maxzip/internal/delta"
)

// deltaState is the extractor's side of file-level delta chains (see
// block.deltaChains). Per block it remembers the latest decoded member of
// each chain, which is exactly the reference the next delta entry needs.
type deltaState struct {
	latest map[string]chainRef
}

type chainRef struct {
	name string
	data []byte
}

func newDeltaState() *deltaState { return &deltaState{latest: map[string]chainRef{}} }

// isChain reports whether the tar entry takes part in a delta chain.
func isChain(hdr *tar.Header) bool { return hdr.PAXRecords[block.PAXChain] != "" }

// open returns a reader over the entry's ORIGINAL content. For an entry
// that is not part of a chain it just returns r. For a chain member it
// reads the entry (bounded by what the authenticated index says the file
// is), rebuilds it from its reference if it was stored as a delta, and
// remembers it for the next member.
func (ds *deltaState) open(hdr *tar.Header, r io.Reader, expectedSize uint64) (io.Reader, error) {
	key := hdr.PAXRecords[block.PAXChain]
	if key == "" {
		return r, nil
	}
	if expectedSize > uint64(block.HardDeltaMax) {
		return nil, fmt.Errorf("%s: chain member larger than the %d byte limit", hdr.Name, block.HardDeltaMax)
	}
	refName, isDelta := hdr.PAXRecords[block.PAXDelta]

	var data []byte
	if !isDelta {
		var buf bytes.Buffer
		n, err := io.Copy(&buf, io.LimitReader(r, int64(expectedSize)+1))
		if err != nil {
			return nil, err
		}
		if uint64(n) != expectedSize {
			return nil, fmt.Errorf("integrity check failed for %s (size does not match the index)", hdr.Name)
		}
		data = buf.Bytes()
	} else {
		ref, ok := ds.latest[key]
		if !ok || ref.name != refName {
			return nil, fmt.Errorf("%s: delta reference %q is missing (corrupted archive)", hdr.Name, refName)
		}
		// A delta never legitimately exceeds the file it describes by much.
		maxBlob := int64(expectedSize) + int64(expectedSize)/2 + (1 << 20)
		var buf bytes.Buffer
		n, err := io.Copy(&buf, io.LimitReader(r, maxBlob+1))
		if err != nil {
			return nil, err
		}
		if n > maxBlob {
			return nil, fmt.Errorf("%s: delta data is implausibly large (corrupted archive)", hdr.Name)
		}
		ops, err := delta.Unmarshal(buf.Bytes())
		if err != nil {
			return nil, fmt.Errorf("%s: %w", hdr.Name, err)
		}
		data, err = delta.DecodeMax(ref.data, ops, int(expectedSize))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", hdr.Name, err)
		}
	}
	ds.latest[key] = chainRef{name: hdr.Name, data: data}
	return bytes.NewReader(data), nil
}
