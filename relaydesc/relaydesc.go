// relaydesc.go - deal with relay server descriptors [@type server-descriptor 1.0]
//
// To the extent possible under law, Ivan Markin waived all copyright
// and related or neighboring rights to this module of onionutil, using the creative
// commons "cc0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

package relaydesc

import (
    "onionutil"
    "onionutil/torparse"
    //"onionutil/pkcs1"
    "crypto/rsa"
    //"encoding/base64"
    //"strings"
    //"reflect"
    //"strconv"
    "time"
    "net"
    //"log"
)

var (
	documentType = "server-descriptor 1.0"
)

type Descriptor struct {
    Nickname	string
    InternetAddress	net.IP
    ORPort	uint16
    SOCKSPort	uint16
    DirPort	uint16
    ORAddrs	[]net.TCPAddr

    IdentityEd25519	*onionutil.Certificate
    MasterKeyEd25519	onionutil.Ed25519Pubkey
    Bandwidth	onionutil.Bandwidth
    Platform	onionutil.Platform
    Published	time.Time
    Fingerprint	string
    Hibernating	bool
    Uptime	time.Duration
    ExtraInfoDigest	string
    OnionKey	*rsa.PublicKey
    OnionKeyCrosscert	[]byte
    SigningKey	*rsa.PublicKey
    HSDir	bool
    Contact	string
    NTorOnionKey onionutil.Curve25519Pubkey
    NTorOnionKeyCrossCert *onionutil.Certificate
    ExitPolicy	onionutil.ExitPolicy
    Exit6Policy	*onionutil.Exit6Policy
    CachesExtraInfo	bool
    AllowSingleHopExits	bool

    RouterSigEd25519	onionutil.Ed25519Signature
    RouterSignature	onionutil.RSASignature
}

// TODO return a pointer to descs not descs themselves?
func ParseServerDescriptors(descs_str []byte) (descs []Descriptor, nProcessed int64) {
    docs, _ := torparse.ParseTorDocument(descs_str)
    nProcessed = int64(len(docs))
    for _, doc := range docs {
        var desc Descriptor

	if value, ok := doc["bandwidth"]; ok {
		bandwidth, err := onionutil.ParseBandwidthEntry(value[0])
		if err != nil {
			continue
		}
		desc.Bandwidth = bandwidth
	} else { continue }

        descs = append(descs, desc)
    }

    return descs, nProcessed
}

