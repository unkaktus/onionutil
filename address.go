// address.go - commonly used functions for onion addresses
//
// To the extent possible under law, Ivan Markin waived all copyright
// and related or neighboring rights to this module of onionutil, using the creative
// commons "cc0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

package onionutil

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"errors"
	"io"

	"github.com/nogoegst/onionutil/pkcs1"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/sha3"
)

// Generate private key for onion service using rand as the entropy source.
// Recognized versions are "2", "3", "current", "best".
func GenerateOnionKey(rand io.Reader, version string) (crypto.PrivateKey, error) {
	switch version {
	case "2", "current":
		return GenerateOnionKeyV2(rand)
	case "3", "best":
		return GenerateOnionKeyV3(rand)
	default:
		return nil, errors.New("Unrecognized version string for onion address")
	}
}

// OnionAddress returns onion address corresponding to public/private key pk.
func OnionAddress(pk crypto.PublicKey) (string, error) {
	switch pk := pk.(type) {
	case rsa.PublicKey:
		return OnionAddressV2(pk)
	case rsa.PrivateKey:
		return OnionAddress(*(pk.Public().(*rsa.PublicKey)))
	case ed25519.PublicKey:
		return OnionAddressV3(pk)
	case ed25519.PrivateKey:
		return OnionAddressV3(pk.Public().(ed25519.PublicKey))
	default:
		return "", errors.New("Unrecognized type of public key")
	}
}

// v2 onion addresses
var (
	onionAddressLengthV2 = 10
)

// OnionAddress returns the Tor Onion Service address corresponding to a given
// rsa.PublicKey.
func OnionAddressV2(pk rsa.PublicKey) (onionAddress string, err error) {
	permID, err := CalcPermanentID(&pk)
	if err != nil {
		return onionAddress, err
	}
	onionAddress = Base32Encode(permID)
	return onionAddress, err
}

// Generate v2 onion service key (RSA-1024) using rand as the entropy source.
func GenerateOnionKeyV2(rand io.Reader) (crypto.PrivateKey, error) {
	sk, err := rsa.GenerateKey(rand, 1024)
	if err != nil {
		return nil, err
	}
	return *sk, nil
}

// Calculate hash (SHA1) of DER-encoded RSA public key pk.
func RSAPubkeyHash(pk *rsa.PublicKey) (derHash []byte, err error) {
	der, err := pkcs1.EncodePublicKeyDER(pk)
	if err != nil {
		return
	}
	derHash = Hash(der)
	return derHash, err
}

// Calculate permanent ID from RSA public key
func CalcPermanentID(pk *rsa.PublicKey) (permId []byte, err error) {
	derHash, err := RSAPubkeyHash(pk)
	if err != nil {
		return
	}
	permId = derHash[:10]
	return
}

// v3 onion addresses
var (
	onionAddressLengthV3      = 35 // 32+1+3
	onionChecksumPrefix       = []byte(".onion checksum")
	onionAddressVersionByteV3 = []byte{0x03}
)

// Calculate onion address v3 from public key pk.
func OnionAddressV3(pk ed25519.PublicKey) (onionAddress string, err error) {
	h := sha3.New256()
	h.Write(onionChecksumPrefix)
	h.Write([]byte(pk))
	h.Write(onionAddressVersionByteV3)
	chksum := h.Sum(nil)[:2]

	oab := make([]byte, 0, onionAddressLengthV3)
	oa := bytes.NewBuffer(oab)
	oa.Write([]byte(pk))
	oa.Write(chksum)
	oa.Write(onionAddressVersionByteV3)
	onionAddress = Base32Encode(oa.Bytes())
	return onionAddress, err
}

// Generate v3 onion address key (Ed25519) using rand as the entropy source
func GenerateOnionKeyV3(rand io.Reader) (crypto.PrivateKey, error) {
	_, sk, err := ed25519.GenerateKey(rand)
	return sk, err
}
