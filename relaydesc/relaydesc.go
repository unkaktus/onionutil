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
    "bulb/utils/pkcs1"
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

    IdentityEd25519	*onionutil.Certificate
    MasterKeyEd25519	*onionutil.Ed25519Pubkey
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

    RouterSigEd25519	onionutil.Ed25519Signature
    RouterSignature	onionutil.RSASignature
}

// TODO return a pointer to descs not descs themselves?
func ParseServerDescriptors(descs_str []byte) (descs []Descriptor, rest string) {
    docs, _rest := torparse.ParseTorDocument(descs_str)
    for _, doc := range docs {
        var desc Descriptor
        if string(doc.Entries["@type"].FJoined()) != documentType {
            log.Printf("Got a document that is not \"%s\"", documentType )
            continue
	}
	if value, ok := doc.Entries["router"]; ok {
	    routerF := value[0]
	    desc.Nickname = string(routerF[0])
	    desc.InternetAddress = net.ParseIP(string(routerF[1]))
	    ORPort, err := onionutil.InetPortFromByteString(routerF[2])
	    if err != nil { continue }
	    desc.ORPort = ORPort
	    SOCKSPort, err := onionutil.InetPortFromByteString(routerF[3])
	    if err != nil { continue }
	    desc.SOCKSPort = SOCKSPort
	    DirPort, err := onionutil.InetPortFromByteString(routerF[4])
	    if err != nil { continue }
	    desc.DirPort = DirPort
	} else { continue }

	if value, ok := doc.Entries["identity-ed25519"]; ok {
		if len(value[0]) <= 0 {
			continue
		}
		cert, err := onionutil.ParseCertFromBytes(value[0][0])
		if err != nil {
			continue
		}
		desc.IdentityEd25519 = &cert
	}

	if value, ok := doc.Entries["master-key-ed25519"]; ok {
		var masterKey = make([]byte, onionutil.Ed25519PubkeySize)
		n, err := base64.RawStdEncoding.Decode(masterKey, value.FJoined())
		if err != nil {
			continue
		}
		if n != onionutil.Ed25519PubkeySize {
			continue
		}
		signedWithEd25519Key, ok :=
		desc.IdentityEd25519.Extensions[onionutil.ExtType(0x04)]
		if ok {
			if !reflect.DeepEqual(masterKey, signedWithEd25519Key.Data) {
			continue
			}
		}
		copy(desc.MasterKeyEd25519[:], masterKey)
	}

	if value, ok := doc.Entries["bandwidth"]; ok {
		bandwidth, err := onionutil.ParseBandwidthEntry(value[0])
		if err != nil {
			continue
		}
		desc.Bandwidth = bandwidth
	} else { continue }
	if value, ok := doc.Entries["platform"]; ok {
	    platform, err := onionutil.ParsePlatformEntry(value[0])
	    if err != nil {
		continue
	    }
	    desc.Platform = platform
	} else { continue }

	/* "protocols" fiels is *deprecated* thus not implemented */

	if value, ok := doc.Entries["published"]; ok {
		published, err := time.Parse(onionutil.PublicationTimeFormat,
					string(value.FJoined()))
		if err != nil {
			continue
		}
		desc.Published = published
	} else { continue }

	if value, ok := doc.Entries["fingerprint"]; ok {
		fingerprint := string(value.FJoined())
		desc.Fingerprint = strings.Replace(fingerprint, " ", "", -1)
	} else { continue }

	_, hibernating := doc.Entries["hibernating"]
	desc.Hibernating = hibernating

	if value, ok := doc.Entries["uptime"]; ok {
		uptime, err := strconv.ParseUint(string(value.FJoined()), 10, 64)
		if err != nil {
			continue
		}
		desc.Uptime = time.Duration(uptime)*time.Second
	}

	if value, ok := doc.Entries["extra-info-digest"]; ok {
		desc.ExtraInfoDigest = string(value[0][0])
		/* Ignore extra data since it it not in dir-spec. *
		/* See #16227. */
	}

	if value, ok := doc.Entries["onion-key"]; ok {
		OnionKey, _, err := pkcs1.DecodePublicKeyDER(value.FJoined())
		if err != nil {
		    continue
		}
		desc.OnionKey = OnionKey
	} else { continue }

	if value, ok := doc.Entries["signing-key"]; ok {
		SigningKey, _, err := pkcs1.DecodePublicKeyDER(value.FJoined())
		if err != nil {
		    continue
		}
		desc.SigningKey = SigningKey
	} else { continue }

	if value, ok := doc.Entries["onion-key-crosscert"]; ok {
		crosscert := value.FJoined()
		identityHash, err := onionutil.RSAPubkeyHash(desc.SigningKey)
		if err != nil {
			continue
		}
		crosscertData := append(identityHash,
			desc.MasterKeyEd25519[:]...)
		//hashed := onionutil.Hash(crosscertData)
		/* XXX(dir-spec): Whoo-sch! We do sign (arbitrary long) *
		/* data without hashing it. Seriouly? */
		if err := rsa.VerifyPKCS1v15(desc.OnionKey, 0, crosscertData, crosscert); err != nil {
			continue
		}
		desc.OnionKeyCrosscert = crosscert
	} else if _, required := doc.Entries["identity-25519"]; required {
		continue
	}

	_, hsdir := doc.Entries["hidden-service-dir"]
	desc.HSDir = hsdir

	if value, ok := doc.Entries["contact"]; ok {
		desc.Contact = string(value.FJoined())
	} else { continue }

	if value, ok := doc.Entries["ntor-onion-key"]; ok {
		/* XXX: why do we need +1 here? */
		var NTorOnionKey = make([]byte, onionutil.NTorOnionKeySize+1)
		n, err := base64.StdEncoding.Decode(NTorOnionKey,
						    value.FJoined())
		if err != nil {
			n, err = base64.RawStdEncoding.Decode(NTorOnionKey,
						    value.FJoined())
			if err != nil {
				continue
			}
		}
		if n != onionutil.NTorOnionKeySize {
			continue
		}
		copy(desc.NTorOnionKey[:], NTorOnionKey)
	}

	if value, ok := doc.Entries["ntor-onion-key-crosscert"]; ok {
		ntorOnionKeyCrossCert, err := onionutil.ParseCertFromBytes(value[0][1])
		if err != nil {
			continue
		}
		switch string(value[0][0]) {
			case "0":
				ntorOnionKeyCrossCert.PubkeySign = false
			case "1":
				ntorOnionKeyCrossCert.PubkeySign = true
			default:
				continue
		}
		/* TODO: Skipping verification since I've found no */
		/* Curve25519->Ed25519 implementation in Go. */
		desc.NTorOnionKeyCrossCert = &ntorOnionKeyCrossCert
	} else if _, required := doc.Entries["identity-25519"]; required {
		continue
	}

	if entries, ok := doc.Entries["reject"]; ok {
		for _, entry := range entries {
		     desc.ExitPolicy.Reject =
			append(desc.ExitPolicy.Reject,
			       string(entry.Joined()))
		}
	}
	if entries, ok := doc.Entries["accept"]; ok {
		for _, entry := range entries {
		     desc.ExitPolicy.Accept =
			append(desc.ExitPolicy.Accept,
			       string(entry.Joined()))
		}
	}

	if entries, ok := doc.Entries["ipv6-policy"]; ok {
		var exit6Policy onionutil.Exit6Policy
		switch string(entries[0][0]) {
			case "reject":
				exit6Policy.Accept = false
			case "accept":
				exit6Policy.Accept = true
			default:
				continue
		}

		for _, port := range entries[0][1:] {
			exit6Policy.PortList =
				append(exit6Policy.PortList, string(port))
		}
		desc.Exit6Policy = &exit6Policy
	}

	if value, ok := doc.Entries["router-sig-ed25519"]; ok {
		copy(desc.RouterSigEd25519[:], value.FJoined())
	} else if _, required := doc.Entries["identity-ed25519"]; required {
		continue
	}
	if value, ok := doc.Entries["router-signature"]; ok {
		copy(desc.RouterSignature[:], value.FJoined())
	} else { continue }



/*
        version, err := strconv.ParseInt(string(doc.Entries["version"].FJoined()), 10, 0)
        if err != nil {
            log.Printf("Error parsing descriptor version: %v", err)
            continue
        }
        desc.Version = int(version)

            desc.IntroductionPoints, _ = intropoint.ParseIntroPoints(
                                        string(doc.Entries["introduction-points"].FJoined()))
        if len(doc.Entries["signature"][0]) < 1 {
            log.Printf("Empty signature")
            continue
        }
        desc.Signature = doc.Entries["signature"].FJoined()

	*/
        descs = append(descs, desc)
    }

    rest = string(_rest)
    return descs, rest
}

