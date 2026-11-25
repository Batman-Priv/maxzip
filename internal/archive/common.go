package archive

import (
	"encoding/binary"
	"fmt"

	"github.com/Batman-Priv/maxzip/internal/cryptoutil"
	"github.com/Batman-Priv/maxzip/internal/format"
)

var (
	aadChunkBlock = []byte("github.com/Batman-Priv/maxzip/chunk-block")
	aadFooter     = []byte("github.com/Batman-Priv/maxzip/footer")
)

func blockAAD(index uint32) []byte {
	b := []byte("github.com/Batman-Priv/maxzip/block:")
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
