package torparse

import (
	"testing"
	"io/ioutil"
	"reflect"
	"encoding/hex"
	"crypto/sha256"
	"fmt"
)

func TestParseTorDocument(t *testing.T) {
	servicedesc, err := ioutil.ReadFile("../test/service-descriptor")
	if err != nil {
		t.Error("Unable to find open a file: %v", err)
	}
	parsed, rest := ParseTorDocument(servicedesc)
	if len(rest) > 0 {
		t.Error("Some fields left unparsed: '%v'", rest)
	}
	if len(parsed) != 1 {
		t.Error("There is not exactly one descriptor")
	}
	/* Binary fields [$ echo <base64 data> | base64 -d | sha256sum] */
	permanentKeyHash, _ := hex.DecodeString(
		"15eeb4a49803fa308877a1dd5cfc8a456d87e50c68803340f98839198bb3d371",
		)
	intropointsHash, _ := hex.DecodeString(
		"d4a0f36a24f9e09d1b3ce1d7e49fdc77e696f693e860a95f8d7182745258d6db",
		)
	signatureHash, _ := hex.DecodeString(
		"971786f8ee99940506b2cd4a7d39b90957f081f0b404351f0d4950be55c2efec",
		)
	/* Short fields */
	expected := map[string][]byte{
		"rendezvous-service-descriptor": []byte("6iedtc4w36h35ln3ntklmbiawjhgdjud"),
		"version": []byte("2"),
		"permanent-key": permanentKeyHash,
		"secret-id-part": []byte("tvoxg732caicyulsvpu4wh7lkw3jqqsa"),
		"publication-time":  []byte("2016-06-21 20:00:00"),
		"protocol-versions": []byte("2,3"),
		"introduction-points": intropointsHash,
		"signature": signatureHash,
	}
	for key, value := range expected {
		if !reflect.DeepEqual(value, expected[key]) {
			hash := sha256.Sum256(value)
			if !reflect.DeepEqual(hash[:], expected[key]) {
				fmt.Printf("%x - real\n%x - expected\n", sha256.Sum256(value), expected[key])
				t.Errorf("Field mismatch at '%v'", key)
			}
		}
	}
}
