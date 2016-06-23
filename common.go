// common.go - commonly used functions for onions
//
// To the extent possible under law, Ivan Markin waived all copyright
// and related or neighboring rights to this module of onionutil, using the creative
// commons "cc0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

package onionutil

import (
    "fmt"
    "crypto/rsa"
    "crypto/sha1"
    "encoding/base32"
    "encoding/binary"
    "time"
    "strings"
    "strconv"
    "onionutil/pkcs1"
)


const (
	PublicationTimeFormat = "2006-01-02 15:04:05"
	NTorOnionKeySize = 32
)

func Hash(data []byte) (hash []byte) {
    h := sha1.New()
    h.Write(data)
    hash = h.Sum(nil)
    return hash
}

func CalcPermanentId(pk *rsa.PublicKey) ([]byte, error) {
    der, err := pkcs1.EncodePublicKeyDER(pk)
    if err != nil {
        return nil, err
    }
    der_hash := Hash(der)
    permid := der_hash[:10]
    return permid, err
}

/* XXX: here might be an error for new ed25519 addresses (! mod 5bits=0) */
func Base32Encode(binary []byte) (string) {
    hb32 := base32.StdEncoding.EncodeToString(binary)
    return strings.ToLower(hb32)
}

func Base32Decode(b32 string) (binary []byte, err error) {
    binary, err = base32.StdEncoding.DecodeString(strings.ToUpper(b32))
    return binary, err
}

// OnionAddress returns the Tor Onion Service address corresponding to a given
// rsa.PublicKey.
func OnionAddress(pk *rsa.PublicKey) (onion_address string, err error) {
    perm_id, err := CalcPermanentId(pk)
    if err != nil {
        return onion_address, err
    }
    onion_address = Base32Encode(perm_id)
    return onion_address, err
}

func InetPortFromByteString(str []byte) (port uint16, err error) {
	p, err := strconv.ParseUint(string(str), 10, 16)
	return uint16(p), err
}


type Platform struct {
    SoftwareName string
    SoftwareVersion string
    Name string
    Extra string
}

func ParsePlatformEntry(platformE [][]byte) (platform Platform, err error) {
    /* XXX: lil crafty */
    if len(platformE) != 4 {
	return platform, fmt.Errorf("Platform entry length is not equal 4")
    }
    if string(platformE[2]) != "on" {
	return platform, fmt.Errorf("No 'on' keyword found")
    }
    platform = Platform{Name: string(platformE[3]),
			      SoftwareName: string(platformE[0]),
			      SoftwareVersion: string(platformE[1]),
			      }
    return platform, err
}




type ExitPolicy struct {
	Reject []string
	Accept []string
}

type Bandwidth struct {
	Average uint64
	Burst	uint64
	Observed	uint64
}

func ParseBandwidthEntry(bandwidthE [][]byte) (bandwidth Bandwidth, err error) {
	if len(bandwidthE) != 3 {
		return bandwidth, fmt.Errorf("Bandwidth entry length is not equal 4")
	}
	average, err := strconv.ParseUint(string(bandwidthE[0]), 10, 64);
	if err != nil {
		return bandwidth, err
	}
	burst, err := strconv.ParseUint(string(bandwidthE[1]), 10, 64);
	if err !=nil {
		return bandwidth, err
	}
	observed, err := strconv.ParseUint(string(bandwidthE[2]), 10, 64);
	if err != nil {
		return bandwidth, err
	}
	bandwidth = Bandwidth{average, burst, observed}
	return
}

type Extention struct {
	ExtLength uint16
	ExtType	byte
	ExtFlags	byte
	ExtData	[]byte
}

/*
type CertKeyType byte

const (
	RESERVED0 CertKeyType	= 0x00
	RESERVED1		= 0x01
	RESERVED2		= 0x02
	RESERVED3		= 0x03
	
*/

type Certificate struct {
	Version	uint8
	CertType		byte
	ExpirationDate	time.Time
	CertKeyType	byte
	CertifiedKey	[32]byte
	NExtentions	uint8
	Extentions	[]Extention
	Signature	[64]byte
}

func ParseCertFromBytes(binCert []byte) (cert Certificate, err error) {
	i := 0 /* Index */
	cert.Version = uint8(binCert[i])
	i+=1
	cert.CertType = binCert[i]
	i+=1
	expirationHours := binary.BigEndian.Uint32(binCert[i:i+4])
	i+=4
	expirationDuration := time.Duration(expirationHours)*time.Hour
	expirationIntDate := int64(expirationDuration.Seconds())
	cert.ExpirationDate = time.Unix(expirationIntDate,0)
	cert.CertKeyType = binCert[i]
	i+=1
        copy(cert.CertifiedKey[:], binCert[i:i+32])
	i+=32
	cert.NExtentions = uint8(binCert[i])
	return
}
