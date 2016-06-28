// consensus.go - deal with consensus [@type network-status-consensus-3 1.0]
//
// To the extent possible under law, Ivan Markin waived all copyright
// and related or neighboring rights to this module of onionutil, using the creative
// commons "cc0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

package netstatus

import (
    "onionutil"
    "onionutil/torparse"
    //"onionutil/pkcs1"
    //"crypto/rsa"
    //"encoding/base64"
    //"strings"
    //"reflect"
    "bytes"
    "strconv"
    "time"
    "net"
    "log"
)

var (
	documentType = "network-status-consensus-3 1.0"
)


type Bandwidth struct {
	Value		uint64
	Measured	uint64
	Unmeasured	bool
}

type Router struct {
	Nickname	string
	Identity	[]byte
	Digest		[]byte
	Published	time.Time
	InternetAddress	net.IP
	ORPort		uint16
	DirPort		uint16
	ORAddrs		[]net.TCPAddr
	Flags		map[string]bool
	Platform	onionutil.Platform
	Bandwidth	Bandwidth
	Policy		onionutil.Exit6Policy
}

//func ParseRouterEntry(

type Netstatus struct {
	Routers		[]Router
}

func ParseNetstatuses(data []byte) (netstatuses []Netstatus, rest string) {
    docs, _rest := torparse.ParseTorDocument(data)
    for _, doc := range docs {
        var netstatus Netstatus

        if value, ok := doc["@type"]; ok {
            if string(value[0].Joined()) != documentType {
                log.Printf("Got a document that is not \"%s\"", documentType )
                goto Broken
	    }
        }
	log.Printf("%+v", doc["@type"])
	if rEntries, ok := doc["r"]; ok {
		dirFooter, ok := doc["directory-footer"]
		if !ok {
			goto Broken
		}
		if len(dirFooter) != 1 {
			goto Broken
		}
		if len(dirFooter[0].Content) != 0 {
			goto Broken
		}


		for n, rEntry := range rEntries {
			var router Router
			router.Flags = make(map[string]bool)

			var nextIndex uint
			if n == len(rEntries)-1 {
				nextIndex = dirFooter[0].Index
			} else {
				nextIndex = rEntries[n+1].Index
			}

			if len(rEntry.Content) < 8 {
				goto Broken
			}

			router.Nickname = string(rEntry.Content[0])

			identity, _, err := onionutil.Base64Decode(rEntry.Content[1])
			if err != nil {
				goto Broken
			}
			router.Identity = identity

			digest, _, err := onionutil.Base64Decode(rEntry.Content[2])
			if err != nil {
				goto Broken
			}
			router.Digest = digest
			published, err := time.Parse(onionutil.PublicationTimeFormat,
						     string(bytes.Join([][]byte{rEntry.Content[3],
									 rEntry.Content[4]},
										[]byte(" "))))
			if err != nil {
				goto Broken
			}
			router.Published = published

			router.InternetAddress = net.ParseIP(string(rEntry.Content[5]))
			ORPort, err := onionutil.InetPortFromByteString(rEntry.Content[6])
			if err != nil { goto Broken }
			router.ORPort = ORPort
			DirPort, err := onionutil.InetPortFromByteString(rEntry.Content[7])
			if err != nil { goto Broken }
			router.DirPort = DirPort
			router.ORAddrs = append(router.ORAddrs,
				net.TCPAddr{IP: router.InternetAddress,
					    Port: int(ORPort)})

			/* Parse router fields */
			for _, entry := range doc["a"] {
				if rEntry.Index<entry.Index && entry.Index<=nextIndex {
					tcpAddr, err := net.ResolveTCPAddr("tcp",
							string(entry.Content[0]))
					if err != nil {
						goto Broken
					}
					router.ORAddrs = append(router.ORAddrs,
								*tcpAddr)

				}
			}
			for _, entry := range doc["s"] {
				if rEntry.Index<entry.Index && entry.Index<=nextIndex {
					for _, flag := range entry.Content {
						router.Flags[string(flag)] = true
					}
				}
			}
			for _, entry := range doc["v"] {
				if rEntry.Index<entry.Index && entry.Index<=nextIndex {
					platform, err := onionutil.ParseRouterSoftwareVersion(entry.Content)
					if err != nil {
						goto Broken
					}
					router.Platform = platform
				}
			}
			for _, entry := range doc["w"] {
				if rEntry.Index<entry.Index && entry.Index<=nextIndex {
					for _, keyword := range entry.Content {
						if bytes.HasPrefix(keyword, []byte("Bandwidth=")) {
							bw := bytes.TrimPrefix(keyword, []byte("Bandwidth="))
							bandwidth, err := strconv.ParseUint(string(bw), 10, 64);
							if err != nil {
								goto Broken
							}
							router.Bandwidth.Value = bandwidth
						}
						if bytes.HasPrefix(keyword, []byte("Measured=")) {
							m := bytes.TrimPrefix(keyword, []byte("Measured="))
							measured, err := strconv.ParseUint(string(m), 10, 64);
							if err != nil {
								goto Broken
							}
							router.Bandwidth.Measured = measured
						}
						if bytes.HasPrefix(keyword, []byte("Unmeasured=")) {
							um := bytes.TrimPrefix(keyword, []byte("Unmeasured="))
							unmeasured, err := strconv.ParseUint(string(um), 10, 64);
							if err != nil {
								goto Broken
							}
							if unmeasured == 1 {
								router.Bandwidth.Unmeasured = true
							}
						}
					}
				}
			}
			for _, entry := range doc["p"] {
				if rEntry.Index<entry.Index && entry.Index<=nextIndex {
					policy, err := onionutil.ParsePolicy(entry.Content)
					if err != nil {
						goto Broken
					}
					router.Policy = policy
				}
			}
			netstatus.Routers = append(netstatus.Routers, router)
		}

	} else { goto Broken }


        netstatuses = append(netstatuses, netstatus)
	continue
	Broken:
		log.Printf("-broken-")
		// if saveBroken ...
		continue
    }

    rest = string(_rest)
    return netstatuses, rest
}

