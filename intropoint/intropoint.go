// intropoint.go - deal with intopoints
//
// To the extent possible under law, Ivan Markin waived all copyright
// and related or neighboring rights to this module of onionutil, using the creative
// commons "cc0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

package intropoint

import (
    "strings"
    "log"
    "strconv"
    "net"
    "fmt"
    "encoding/pem"
    "crypto/rsa"
    "onionutil"
    "onionutil/torparse"
    "onionutil/pkcs1"
)

type IntroductionPoint struct {
    Identity  []byte
    InternetAddress   net.IP
    OnionPort   uint16
    OnionKey    *rsa.PublicKey
    ServiceKey  *rsa.PublicKey
}


func ParseIntroPoints(ips_str string) (ips []IntroductionPoint, rest string) {
    docs, _rest := torparse.ParseTorDocument([]byte(ips_str))
    for _, doc := range docs {
        if _, ok := doc.Entries["introduction-point"]; !ok {
            log.Printf("Got a document that is not an introduction point")
            continue
        }
        var ip IntroductionPoint

        identity, err := onionutil.Base32Decode(string(doc.Entries["introduction-point"].FJoined()))
        if err != nil {
            log.Printf("The IP has invalid idenity. Skipping")
            continue
        }
        ip.Identity = identity

        ip.InternetAddress = net.ParseIP(string(doc.Entries["ip-address"].FJoined()))
        if ip.InternetAddress == nil {
            log.Printf("Not a valid Internet address for an IntroPoint")
            continue
        }
        onion_port, err := strconv.ParseUint(string(doc.Entries["onion-port"].FJoined()), 10, 16)
        if err != nil {
            log.Printf("Error parsing IP port: %v", err)
            continue
        }
        ip.OnionPort = uint16(onion_port)
        onion_key, _, err := pkcs1.DecodePublicKeyDER(doc.Entries["onion-key"].FJoined())
        if err != nil {
            log.Printf("Decoding DER sequence of PulicKey has failed: %v.", err)
            continue
        }
        ip.OnionKey = onion_key
        service_key, _, err := pkcs1.DecodePublicKeyDER(doc.Entries["service-key"].FJoined())
        if err != nil {
            log.Printf("Decoding DER sequence of PulicKey has failed: %v.", err)
            continue
        }
        ip.ServiceKey = service_key

        ips = append(ips, ip)
    }
    rest = string(_rest)
    return ips, rest
}




func TearApartIntroPoints(ips_str string) (ips []string) {
    title := "introduction-point"
    ips = strings.Split(ips_str, title)[1:]
    for index,ip := range ips {
        ips[index] = strings.Trim(title + ip, "\n")
    }
    return ips
}

func MakeIntroPointDocument(ip IntroductionPoint) (ip_str string) {
    ip_str += fmt.Sprintf("introduction-point %v\n", onionutil.Base32Encode(ip.Identity))
    ip_str += fmt.Sprintf("ip-address %v\n", ip.InternetAddress)
    ip_str += fmt.Sprintf("onion-port %v\n", ip.OnionPort)
    onion_key_der, err := pkcs1.EncodePublicKeyDER(ip.OnionKey)
    if err != nil {
        log.Fatalf("Cannot encode public key into DER sequence.")
    }
    onion_key_pem := pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY",
                                                   Bytes: onion_key_der})
    ip_str += fmt.Sprintf("onion-key\n%s", onion_key_pem)
    service_key_der, err := pkcs1.EncodePublicKeyDER(ip.ServiceKey)
    if err != nil {
        log.Fatalf("Cannot encode public key into DER sequence.")
    }
    service_key_pem := pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY",
                                                   Bytes: service_key_der})
    ip_str += fmt.Sprintf("service-key\n%s", service_key_pem)

    return ip_str
}

func MakeIntroPointsDocument(ips []IntroductionPoint) (ips_str string) {
    for _, ip := range ips {
        ip_str := MakeIntroPointDocument(ip)
        ips_str += ip_str
    }
    return ips_str
}

