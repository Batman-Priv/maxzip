package archive

import (
	"encoding/binary"
	"fmt"

	"gitlab.com/specterog/maxzip/internal/cryptoutil"
	"gitlab.com/specterog/maxzip/internal/format"
)

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

const (
	maxBlockUncomp = int64(4) << 30 
)

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
