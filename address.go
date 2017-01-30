// address.go - commonly used functions for onion addresses
//
// To the extent possible under law, Ivan Markin waived all copyright
// and related or neighboring rights to this module of onionutil, using the creative
// commons "cc0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

package onionutil

import (
	"crypto"
	"crypto/rsa"
	"io"

	"github.com/nogoegst/onionutil/pkcs1"
)

// v2 onion addresses

func RSAPubkeyHash(pk *rsa.PublicKey) (derHash []byte, err error) {
	der, err := pkcs1.EncodePublicKeyDER(pk)
	if err != nil {
		return
	}
	derHash = Hash(der)
	return derHash, err
}

func CalcPermanentID(pk *rsa.PublicKey) (permId []byte, err error) {
	derHash, err := RSAPubkeyHash(pk)
	if err != nil {
		return
	}
	permId = derHash[:10]
	return
}

// OnionAddress returns the Tor Onion Service address corresponding to a given
// rsa.PublicKey.
func OnionAddress(pubKey *rsa.PublicKey) (onionAddress string, err error) {
	permID, err := CalcPermanentID(pubKey)
	if err != nil {
		return onionAddress, err
	}
	onionAddress = Base32Encode(permID)
	return onionAddress, err
}

// Generate current onion key
func GenerateOnionKey(rand io.Reader) (crypto.PrivateKey, error) {
	return GenerateLegacyOnionKey(rand)
}

// Generate RSA-1024 key
func GenerateLegacyOnionKey(rand io.Reader) (crypto.PrivateKey, error) {
	return rsa.GenerateKey(rand, 1024)
}
