package archive

import (
	"encoding/binary"
	"fmt"

	"gitlab.com/specterog/maxzip/internal/cryptoutil"
	"gitlab.com/specterog/maxzip/internal/format"
)

// Associated data bound into encrypted streams (see internal/cryptoutil):
// a stream can only be decrypted in the role - and, for normal blocks, the
// position - it was written for.
var (
	aadChunkBlock = []byte("gitlab.com/specterog/maxzip/chunk-block")
	aadFooter     = []byte("gitlab.com/specterog/maxzip/footer")
)

func blockAAD(index uint32) []byte {
	b := []byte("gitlab.com/specterog/maxzip/block:")
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], index)
	return append(b, n[:]...)
}

// Sanity limits applied when reading an archive. They protect against
// crafted lengths, not against legitimate large archives.
const (
	maxBlockUncomp = int64(4) << 30 // 4 GiB of plaintext per block
)

// openCipher derives the archive's cipher from the password, or returns nil
// for an unencrypted archive.
func openCipher(hdr format.Header, password string) (*cryptoutil.Cipher, error) {
	if hdr.Flags&format.FlagEncrypted == 0 {
		return nil, nil
	}
	if password == "" {
		return nil, fmt.Errorf("archive is encrypted; provide -password")
	}
	key, err := cryptoutil.DeriveKey(password, hdr.Salt, hdr.KDF)
	if err != nil {
		return nil, err
	}
	return cryptoutil.NewCipher(key)
}
