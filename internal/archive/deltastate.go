package archive

import (
	"archive/tar"
	"bytes"
	"fmt"
	"io"

	"gitlab.com/specterog/maxzip/internal/block"
	"gitlab.com/specterog/maxzip/internal/delta"
)

type deltaState struct {
	latest map[string]chainRef
}

type chainRef struct {
	name string
	data []byte
}

func newDeltaState() *deltaState { return &deltaState{latest: map[string]chainRef{}} }

func isChain(hdr *tar.Header) bool { return hdr.PAXRecords[block.PAXChain] != "" }

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
