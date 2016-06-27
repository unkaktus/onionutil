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
    "onionutil/pkcs1"
    "crypto/rsa"
    "encoding/base64"
    "strings"
    "reflect"
    "strconv"
    "time"
    "net"
    "log"
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
    HSDirVersions	[]uint8
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
func ParseServerDescriptors(descs_str []byte) (descs []Descriptor, rest string) {
    docs, _rest := torparse.ParseTorDocument(descs_str)
    for _, doc := range docs {
        var desc Descriptor
        if string(doc["@type"].FJoined()) != documentType {
            log.Printf("Got a document that is not \"%s\"", documentType )
            continue
	}
	if value, ok := doc["router"]; ok {
		if !torparse.ExactlyOnce(value) {
			goto Broken
		}
		routerF := value[0]
		desc.Nickname = string(routerF.Content[0])
		desc.InternetAddress = net.ParseIP(string(routerF.Content[1]))
		ORPort, err := onionutil.InetPortFromByteString(routerF.Content[2])
		if err != nil { goto Broken }
		desc.ORPort = ORPort
		SOCKSPort, err := onionutil.InetPortFromByteString(routerF.Content[3])
		if err != nil { goto Broken }
		desc.SOCKSPort = SOCKSPort
		DirPort, err := onionutil.InetPortFromByteString(routerF.Content[4])
		if err != nil { goto Broken }
		desc.DirPort = DirPort
		desc.ORAddrs = append(desc.ORAddrs,
			net.TCPAddr{IP: desc.InternetAddress,
				    Port: int(ORPort)})
	} else { goto Broken }

	if value, ok := doc["identity-ed25519"]; ok {
		if !torparse.AtMostOnce(value) {
			goto Broken
		}
		if len(value[0].Content) <= 0 {
			goto Broken
		}
		cert, err := onionutil.ParseCertFromBytes(value[0].Content[0])
		if err != nil {
			goto Broken
		}
		desc.IdentityEd25519 = &cert
	}

	if value, ok := doc["master-key-ed25519"]; ok {
		if !torparse.AtMostOnce(value) {
			goto Broken
		}
		var masterKey = make([]byte, onionutil.Ed25519PubkeySize)
		n, err := base64.RawStdEncoding.Decode(masterKey, value.FJoined())
		if err != nil {
			goto Broken
		}
		if n != onionutil.Ed25519PubkeySize {
			goto Broken
		}
		signedWithEd25519Key, ok :=
		desc.IdentityEd25519.Extensions[onionutil.ExtType(0x04)]
		if ok {
			if !reflect.DeepEqual(masterKey, signedWithEd25519Key.Data) {
			goto Broken
			}
		}
		copy(desc.MasterKeyEd25519[:], masterKey)
	}

	if value, ok := doc["bandwidth"]; ok {
		if !torparse.ExactlyOnce(value) {
			goto Broken
		}
		bandwidth, err := onionutil.ParseBandwidthEntry(value[0].Content)
		if err != nil {
			goto Broken
		}
		desc.Bandwidth = bandwidth
	} else { goto Broken }

	if value, ok := doc["platform"]; ok {  //XXX: maybe slow
		if !torparse.AtMostOnce(value) {
			goto Broken
		}
		platform, err := onionutil.ParsePlatformEntry(value[0].Content)
		if err != nil {
			log.Printf("platerr: %v", err)
			goto Broken
		}
		desc.Platform = platform
	}

	/* Dropping "protocols" field since it's *deprecated*  */

	if value, ok := doc["published"]; ok {
		if !torparse.ExactlyOnce(value) {
			goto Broken
		}
		published, err := time.Parse(onionutil.PublicationTimeFormat,
					string(value.FJoined()))
		if err != nil {
			goto Broken
		}
		desc.Published = published
	} else { goto Broken }

	if value, ok := doc["fingerprint"]; ok {
		if !torparse.AtMostOnce(value) {
			goto Broken
		}
		fingerprint := string(value.FJoined())
		desc.Fingerprint = strings.Replace(fingerprint, " ", "", -1)
	}

	if value, ok := doc["hibernating"]; ok {
		if !torparse.AtMostOnce(value) {
			goto Broken
		}
		desc.Hibernating = ok
	}

	if value, ok := doc["uptime"]; ok {
		if !torparse.AtMostOnce(value) {
			goto Broken
		}
		uptime, err := strconv.ParseUint(string(value.FJoined()), 10, 64)
		if err != nil {
			goto Broken
		}
		desc.Uptime = time.Duration(uptime)*time.Second
	}

	if value, ok := doc["extra-info-digest"]; ok {
		if !torparse.AtMostOnce(value) {
			goto Broken
		}
		desc.ExtraInfoDigest = string(value[0].Content[0])
		/* Ignore extra data since it it not in dir-spec. *
		/* See #16227. */
	}

	if value, ok := doc["onion-key"]; ok {
		if !torparse.ExactlyOnce(value) {
			goto Broken
		}
		OnionKey, _, err := pkcs1.DecodePublicKeyDER(value.FJoined())
		if err != nil {
		    goto Broken
		}
		desc.OnionKey = OnionKey
	} else { goto Broken }

	if value, ok := doc["signing-key"]; ok {
		if !torparse.ExactlyOnce(value) {
			goto Broken
		}
		SigningKey, _, err := pkcs1.DecodePublicKeyDER(value.FJoined())
		if err != nil {
		    goto Broken
		}
		desc.SigningKey = SigningKey
	} else { goto Broken }

	if value, ok := doc["onion-key-crosscert"]; ok {
		crosscert := value.FJoined()
		identityHash, err := onionutil.RSAPubkeyHash(desc.SigningKey)
		if err != nil {
			goto Broken
		}
		crosscertData := append(identityHash,
			desc.MasterKeyEd25519[:]...)
		//hashed := onionutil.Hash(crosscertData)
		/* XXX(dir-spec): Whoo-sch! We do sign (arbitrary long) *
		/* data without hashing it. Seriouly? */
		if err := rsa.VerifyPKCS1v15(desc.OnionKey, 0, crosscertData, crosscert); err != nil {
			goto Broken
		}
		desc.OnionKeyCrosscert = crosscert
	} else if _, required := doc["identity-ed25519"]; required {
		goto Broken
	}

	if value, ok := doc["hidden-service-dir"]; ok {
		if !torparse.AtMostOnce(value) {
			goto Broken
		}
		if len(value[0].Content) ==0 {
			desc.HSDirVersions = []uint8{2}
		} else {
			for _, version := range value[0].Content {
				hsDescVersion, err := strconv.ParseUint(string(version), 10, 8)
				if err != nil {
					goto Broken
				}
				desc.HSDirVersions = append(desc.HSDirVersions, uint8(hsDescVersion))
			}
		}
	}

	if value, ok := doc["contact"]; ok {
		if !torparse.AtMostOnce(value) {
			goto Broken
		}
		desc.Contact = string(value.FJoined())
	} //else { continue } //XXX: slow everything down 10x

	if value, ok := doc["ntor-onion-key"]; ok {
		if !torparse.AtMostOnce(value) {
			goto Broken
		}
		/* XXX: why do we need +1 here? */
		var NTorOnionKey = make([]byte, onionutil.NTorOnionKeySize+1)
		n, err := base64.StdEncoding.Decode(NTorOnionKey,
						    value.FJoined())
		if err != nil {
			n, err = base64.RawStdEncoding.Decode(NTorOnionKey,
						    value.FJoined())
			if err != nil {
				goto Broken
			}
		}
		if n != onionutil.NTorOnionKeySize {
			goto Broken
		}
		copy(desc.NTorOnionKey[:], NTorOnionKey)
	} else if _, required := doc["identity-ed25519"]; required {
		goto Broken
	}


	if value, ok := doc["ntor-onion-key-crosscert"]; ok {
		if !torparse.AtMostOnce(value) {
			goto Broken
		}
		ntorOnionKeyCrossCert, err := onionutil.ParseCertFromBytes(value[0].Content[1])
		if err != nil {
			goto Broken
		}
		switch string(value[0].Content[0]) {
			case "0":
				ntorOnionKeyCrossCert.PubkeySign = false
			case "1":
				ntorOnionKeyCrossCert.PubkeySign = true
			default:
				goto Broken
		}
		/* TODO: Skipping verification since I've found no */
		/* Curve25519->Ed25519 implementation in Go. */
		desc.NTorOnionKeyCrossCert = &ntorOnionKeyCrossCert
	} else if _, required := doc["identity-ed25519"]; required {
		goto Broken
	}
	// XXX: It doesn't check exit policy validity
	if entries, ok := doc["reject"]; ok {
		for _, entry := range entries {
		     desc.ExitPolicy.Reject =
			append(desc.ExitPolicy.Reject,
			       string(entry.Joined()))
		}
	}
	// XXX: It doesn't check exit policy validity
	if entries, ok := doc["accept"]; ok {
		for _, entry := range entries {
		     desc.ExitPolicy.Accept =
			append(desc.ExitPolicy.Accept,
			       string(entry.Joined()))
		}
	}

	if entries, ok := doc["ipv6-policy"]; ok {
		if !torparse.AtMostOnce(entries) {
			goto Broken
		}
		var exit6Policy onionutil.Exit6Policy
		switch string(entries[0].Content[0]) {
			case "reject":
				exit6Policy.Accept = false
			case "accept":
				exit6Policy.Accept = true
			default:
				goto Broken
		}

		for _, port := range entries[0].Content[1:] {
			exit6Policy.PortList =
				append(exit6Policy.PortList, string(port))
		}
		desc.Exit6Policy = &exit6Policy
	}

	/* MESSY: Skipping "family" hoping that it will be nuked soon */

	if value, ok := doc["router-sig-ed25519"]; ok {
		if !torparse.AtMostOnce(value) {
			goto Broken
		}
		copy(desc.RouterSigEd25519[:], value.FJoined())
	} else if _, required := doc["identity-ed25519"]; required {
		goto Broken
	}
	if value, ok := doc["router-signature"]; ok {
		if !torparse.ExactlyOnce(value) {
			goto Broken
		}
		copy(desc.RouterSignature[:], value.FJoined())
	} else { goto Broken }

	/* Skipping "read-history" and "write-history" due to *
	 * their nastyness. Sorry, too sensitive. */

	/* Skip "eventdns" since it's obsolete */

	if value, ok := doc["caches-extra-info"]; ok {
		if !torparse.AtMostOnce(value) {
			goto Broken
		}
		if len(value[0].Content) != 0 {
			goto Broken
		}
		desc.CachesExtraInfo = true
	}

	if value, ok := doc["allow-single-hop-exits"]; ok {
		if !torparse.AtMostOnce(value) {
			goto Broken
		}
		if len(value[0].Content) != 0 {
			goto Broken
		}
		desc.AllowSingleHopExits = true
	}

	if entries, ok := doc["or-address"]; ok {
		for _, address := range entries {
			tcpAddr, err := net.ResolveTCPAddr("tcp",
					string(address.Content[0]))
			if err != nil {
				goto Broken
			}
			desc.ORAddrs = append(desc.ORAddrs,
						*tcpAddr)
		}
	}

        descs = append(descs, desc)
	continue
	Broken:
		log.Printf("-broken-")
		// if saveBroken ...
		continue
    }

    rest = string(_rest)
    return descs, rest
}

