// pbkdf.go - passphrase based key derivation function
//
// To the extent possible under law, Ivan Markin waived all copyright
// and related or neighboring rights to this module of onionutil, using the creative
// commons "cc0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

package onionutil

import (
	"io"

	"github.com/dchest/blake2b"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/sha3"
)

var (
	iterationsPBKDF2 = 100000
	keysizePBKDF2    = 64
	saltPBKDF2, _    = Base32Decode("zx6ebetpg3dwtwhdcfc4wuqa5wnms2z4auhkpf4u725mfe5w6eei42cwvd2d7cvcl7l5sop7opcmkbvsy5snui3xv54couyihhrce6i=")
	saltSHAKE, _     = Base32Decode("rsmsb56wbadli3w5zfdt4gs4nqjnwotmj7jwl4md7mowttptk6bkoh6miuo4hrv76plmamvpkmhjiogxjdyveys3lq3fxf3s6gisgsy=")
)

func KeystreamReader(passphrase []byte, info []byte) io.Reader {
	hashPBKDF2 := blake2b.New512
	secret := pbkdf2.Key(passphrase, saltPBKDF2, iterationsPBKDF2, keysizePBKDF2, hashPBKDF2)

	shakeHash := sha3.NewShake256()
	shakeHash.Write(secret)
	shakeHash.Write(saltSHAKE)
	shakeHash.Write(info)

	return shakeHash
}
