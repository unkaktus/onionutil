// oniondesc.go - deal with onion service descriptors
//
// To the extent possible under law, Ivan Markin waived all copyright
// and related or neighboring rights to this module of onionutil, using the creative
// commons "cc0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

package oniondesc

import (
    "fmt"
    "strconv"
    "crypto/rsa"
    "crypto/sha1"
    "bytes"
    "time"
    "strings"
    "encoding/binary"
    "encoding/pem"
    "onionutil"
    "onionutil/torparse"
    "onionutil/intropoint"
    "onionutil/pkcs1"
    "log"
)


type OnionDescriptor struct {
    DescId  []byte
    Version int
    PermanentKey    *rsa.PublicKey
    SecretIdPart    []byte
    PublicationTime time.Time
    ProtocolVersions    []int
    IntroductionPoints  []intropoint.IntroductionPoint
    Signature   []byte
}

// Initialize defaults
func ComposeDescriptor(perm_pk *rsa.PublicKey,
                       ips []intropoint.IntroductionPoint, replica int,
                       ) (desc OnionDescriptor) {
    /* v hardcoded values */
    desc.Version = 2
    desc.ProtocolVersions = []int{2, 3}
    /* ^ hardcoded values */
    current_time := time.Now().Unix()
    rounded_current_time := current_time-current_time%(60*60)
    desc.PublicationTime = time.Unix(rounded_current_time, 0)
    desc.PermanentKey = perm_pk
    perm_id, _ := onionutil.CalcPermanentId(desc.PermanentKey)
    desc.SecretIdPart = calcSecretId(perm_id, current_time, byte(replica))
    desc.DescId = calcDescriptorId(perm_id, desc.SecretIdPart)
    desc.IntroductionPoints = ips
    return desc
}


// TODO return a pointer to descs not descs themselves?
func ParseOnionDescriptors(descs_str string) (descs []OnionDescriptor, rest string) {
    docs, _rest := torparse.ParseTorDocument([]byte(descs_str))
    for _, doc := range docs {
        if doc.Name != "rendezvous-service-descriptor" {
            log.Printf("Got a document that is not an onion service")
            continue
        }
        var desc OnionDescriptor

        version, err := strconv.ParseInt(string(doc.Fields["version"]), 10, 0)
        if err != nil {
            log.Printf("Error parsing descriptor version: %v", err)
            continue
        }
        desc.Version = int(version)

        permanent_key, _, err := pkcs1.DecodePublicKeyDER(doc.Fields["permanent-key"])
        if err != nil {
            log.Printf("Decoding DER sequence of PulicKey has failed: %v.", err)
            continue
        }
        desc.PermanentKey = permanent_key
        //if (doc.Fields["introduction-points"]) {
            desc.IntroductionPoints, _ = intropoint.ParseIntroPoints(
                                        string(doc.Fields["introduction-points"]))
        //}
        if len(doc.Fields["signature"]) < 1 {
            log.Printf("Empty signature")
            continue
        }
        desc.Signature = doc.Fields["signature"]

        // XXX: Check the signature? And strore unparsed original??

        descs = append(descs, desc)
    }

    rest = string(_rest)
    return descs, rest
}

func MakeDescriptorBody(desc OnionDescriptor) (desc_body string) {
    perm_pk_der, err := pkcs1.EncodePublicKeyDER(desc.PermanentKey)
    if err != nil {
        log.Fatalf("Cannot encode public key into DER sequence.")
    }
    desc_body += fmt.Sprintf("rendezvous-service-descriptor %s\n",
                              onionutil.Base32Encode(desc.DescId))
    desc_body += fmt.Sprintf("version %d\n",
                              desc.Version)
    desc_body += fmt.Sprintf("permanent-key\n%s\n",
                              pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY",
                                                              Bytes: perm_pk_der}))
    desc_body += fmt.Sprintf("secret-id-part %s\n",
                              onionutil.Base32Encode(desc.SecretIdPart))
    desc_body += fmt.Sprintf("publication-time %v\n",
                              desc.PublicationTime.Format("2006-01-02 15:04:05"))
    var protoversions_strs []string
    for _, v := range desc.ProtocolVersions {
        protoversions_strs = append(protoversions_strs, fmt.Sprintf("%d", v))
    }
    desc_body += fmt.Sprintf("protocol-versions %v\n",
                              strings.Join(protoversions_strs, ","))
    if len(desc.IntroductionPoints) != 0 {
        intro_block := intropoint.MakeIntroPointsDocument(desc.IntroductionPoints)
        desc_body += fmt.Sprintf("introduction-points\n%s\n",
                                  pem.EncodeToMemory(&pem.Block{Type: "MESSAGE",
                                        Bytes: []byte(intro_block)}))
    }
    desc_body += fmt.Sprintf("signature\n",)

    // Sanitize double NL if any XXX: is it fine?
    desc_body = strings.Replace(desc_body, "\n\n", "\n", -1)

    return desc_body
}

func SignDescriptor(desc_body string, doSign func(digest []byte) ([]byte, error)) (signed_desc string) {
    desc_digest := CalcDescriptorBodyDigest(desc_body)
    signature, err := doSign(desc_digest)
    //signature, err := keycity.SignPlease(front_onion, desc_digest)
    //signature, err := signDescriptorBodyDigest(desc_digest, front_onion)
    if err != nil {
        log.Fatalf("Cannot sign: %v.", err)
    }
    signed_desc = MakeSignedDescriptor(desc_body, signature)
    return signed_desc
}

func MakeSignedDescriptor(desc_body string, signature []byte) (signed_desc string){
    pem_signature := pem.EncodeToMemory(&pem.Block{Type: "SIGNATURE",
                                                   Bytes: signature})
    signed_desc = fmt.Sprintf("%s%s", desc_body, pem_signature)
    return signed_desc
}

/* TODO: there is no `descriptor-cookie` now (because we need IP list encryption etc) */

func calcSecretId(perm_id []byte, current_time int64, replica byte) (secret_id []byte) {
    perm_id_byte := uint32(perm_id[0])

    time_period_int := (uint32(current_time) + perm_id_byte*86400/256)/86400
    var time_period = new(bytes.Buffer)
    binary.Write(time_period, binary.BigEndian, time_period_int)

    secret_id_h := sha1.New()
    secret_id_h.Write(time_period.Bytes())
    secret_id_h.Write([]byte{replica})
    secret_id = secret_id_h.Sum(nil)
    return secret_id
}

func calcDescriptorId(perm_id, secret_id []byte) (desc_id []byte){
    desc_id_h := sha1.New()
    desc_id_h.Write(perm_id)
    desc_id_h.Write(secret_id)
    desc_id_bin := desc_id_h.Sum(nil)
    return desc_id_bin
}
func CalcDescriptorBodyDigest(desc_body string) (digest []byte) {
    h := sha1.New()
    h.Write([]byte(desc_body))
    digest = h.Sum(nil)
    return digest
}

/*
func verifyDescSignature(desc *Descriptor) (err error) {
    desc_body := MakeDescriptorBody(desc)
    desc_digest := CalcDescriptorBodyDigest(desc_body)
    err = rsa.VerifyPKCS1v15(desc.PermanentKey, 0, desc_digest, desc.Signature)
    return err
    /*
    return errors.New("Reassembled descriptor signature verification failed (%v).",
                        err)
    
}
*/
