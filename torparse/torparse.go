// torparse.go - parse various documents produced by Tor
//
// To the extent possible under law, Ivan Markin waived all copyright
// and related or neighboring rights to this module of onionutil, using the creative
// commons "cc0" public domain dedication. See LICENSE or
// <http://creativecommons.org/publicdomain/zero/1.0/> for full details.

package torparse

import (
    "fmt"
//    "log"
    "bytes"
    "encoding/pem"
)

type TorEntry [][]byte
type TorEntries map[string][]TorEntry

type TorDocument struct {
    Docs  []TorDocument
    Entries  TorEntries
}

func (te TorEntry) Joined() (joined []byte) {
	for index, subentry := range te {
		if index != 0 {
			joined = append(joined, byte(' '))
		}
		joined = append(joined, subentry...)
	}
	return joined
}

var pemStart = []byte("-----BEGIN ")

func ParseOutNextField(data []byte) (field string, content TorEntry, rest []byte, err error) {
        nl_split := bytes.SplitN(data, []byte("\n"), 2)
        if len(nl_split) != 2 {
            return field, content, data,
                   fmt.Errorf("Cannot split by newline")
        }
        /* Overwrite with the rest */
        rest = nl_split[1]
        sp_split := bytes.SplitN(nl_split[0], []byte(" "), -1)
        if len(sp_split) <= 0 { /* We have no data left */
            return field, content, data,
                   fmt.Errorf("No data left")
        }

	field = string(sp_split[0])
	content = sp_split[1:]
	/* test if we have pem data now. if so append to previous field */
        if bytes.HasPrefix(rest, pemStart) {
		block, pem_rest := pem.Decode(data)
                content = append(content, block.Bytes)
		rest = pem_rest
	}
        return field, content, rest, err
}

// TODO: trim/skip empty strings/separators
func ParseTorDocument(doc_data []byte) (docs []TorDocument, rest []byte) {
        var doc *TorDocument
        var field string
        var content TorEntry
        var firstField string

        var parse_err error
        for {
            field, content, doc_data, parse_err = ParseOutNextField(doc_data)
            //log.Printf("parsed: %v : %v", field, content)
	    if parse_err != nil {
                //log.Printf("Error parsing document: %v", parse_err)
                break;
            }
            if firstField == "" { /* We're just in the begining - doc name */
                firstField = field
            }
            if field == firstField {
                if doc != nil {
		    /* Append previous doc */
                    docs = append(docs, *doc)
		}
                doc = &TorDocument{
			Docs: make([]TorDocument, 1),
			Entries: make(TorEntries),
                }
            }
	    doc.Entries[field] = append(doc.Entries[field], content)
        }
        if doc != nil {
            docs = append(docs, *doc) /* Append a doc */
        }

        return docs, doc_data
    }

