package certs

import (
	"encoding/pem"
	"fmt"
	"io/ioutil"
)

func load(file string) (*pem.Block, error) {
	b, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("failed to read PEM file '%v': %v", file, err)
	}

	der, _ := pem.Decode(b)
	if der == nil {
		return nil, fmt.Errorf("failed to decode PEM file '%v'", file)
	}

	return der, nil
}
