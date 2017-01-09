// pbkdf.go - passphrase based key derivation function
//
// To the extent possible under law, Ivan Markin waived all copyright
// and related or neighboring rights to this module of onionutil, using the creative
// commons "cc0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

package onionutil

import (
	"io"
	"encoding/hex"

	"github.com/nogoegst/blake2xb"
	"golang.org/x/crypto/pbkdf2"
)

var (
	iterationsPBKDF2 = 100000
	keysizePBKDF2    = 64
	saltPBKDF2, _    = hex.DecodeString("8e8a1b3347da2672fa404eaa7276dee3")
	saltXOF, _       = hex.DecodeString("313e86e72658f5c7c3ad6e1c3d397062")
)

func KeystreamReader(passphrase []byte, person []byte) (io.Reader, error) {
	hashPBKDF2 := blake2xb.New512
	secret := pbkdf2.Key(passphrase, saltPBKDF2, iterationsPBKDF2, keysizePBKDF2, hashPBKDF2)

	b2xbConfig := blake2xb.NewXConfig(0)
	b2xbConfig.Salt = saltXOF[:16]
	b2xbConfig.Person = person[:16]
	b2xb, err := blake2xb.NewX(nil)
	if err != nil {
		return nil, err
	}
	b2xb.Write(secret)

	return b2xb, nil
}
