// torparse.go - parse various documents produced by Tor
//
// To the extent possible under law, Ivan Markin waived all copyright
// and related or neighboring rights to this module of onionutil, using the creative
// commons "cc0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

package torparse

import (
    "fmt"
    "bytes"
    "encoding/pem"
)

type TorDocument struct {
    Name    string
    Id      string
    Fields  map[string][]byte
}


func ParseOutNextField(data []byte) (field string, content []byte, rest []byte, err error) {
        nl_split := bytes.SplitN(data, []byte("\n"), 2)
        if len(nl_split) != 2 {
            return field, content, data,
                   fmt.Errorf("Cannot split by NL")
        }
        /* Overwrite with the rest */
        data = nl_split[1]

        sp_split := bytes.SplitN(nl_split[0], []byte(" "), 2)
        switch len(sp_split) {
        case 2: /* We've got ASCII field */
            return string(sp_split[0]), sp_split[1], data, err
        case 1: /* We've got binary data in PEM */
            if len(sp_split[0])!=0 {
                block, pem_rest := pem.Decode(data)
                return string(sp_split[0]), block.Bytes, pem_rest, err
            }
            fallthrough
        case 0: /* We have no data left */
            return field, content, data,
                   fmt.Errorf("No data left")
        }
        return field, content, data,
               fmt.Errorf("Unexpected error")
}

// TODO: trim/skip empty strings/separators
func ParseTorDocument(doc_data []byte) (docs []TorDocument, rest []byte) {
        var doc *TorDocument
        var field string
        var content []byte
        var doc_name string

        var parse_err error
        for true {
            field, content, doc_data, parse_err = ParseOutNextField(doc_data)
            if parse_err != nil {
                //log.Printf("Error parsing document: %v", parse_err)
                break;
            }
            if doc_name == "" { /* We're just in the begining - doc name */
                doc_name = field
            }
            if field == doc_name {
                if doc != nil {
                    docs = append(docs, *doc) /* Append previous doc */
                }
                doc = &TorDocument{
                    Fields: make(map[string][]byte),
                }
                doc.Name = doc_name
                doc.Id   = string(content)
            } else { /* Non-special field */
                doc.Fields[field] = content
            }
        }
        if doc != nil {
            docs = append(docs, *doc) /* Append a doc */
        }

        return docs, doc_data
    }

