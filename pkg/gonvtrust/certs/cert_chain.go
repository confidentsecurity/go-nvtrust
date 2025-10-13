// Copyright 2025 Nonvolatile Inc. d/b/a Confident Security
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package certs

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
)

type CertChain struct {
	certs [][]byte
}

func NewCertChainFromData(chainData []byte) *CertChain {
	var certs [][]byte
	remainingData := chainData
	for {
		block, rest := pem.Decode(remainingData)
		if block == nil {
			break
		}
		certs = append(certs, block.Bytes)
		remainingData = rest
	}

	return &CertChain{certs: certs}
}

func (c *CertChain) Verify() error {
	var parsedCerts []*x509.Certificate

	for _, certData := range c.certs {
		cert, err := x509.ParseCertificate(certData)
		if err != nil {
			return fmt.Errorf("failed to parse certificate: %v", err)
		}
		parsedCerts = append(parsedCerts, cert)
	}

	if len(parsedCerts) < 2 {
		return errors.New("certificate chain must contain at least two certificates")
	}

	roots := x509.NewCertPool()
	intermediates := x509.NewCertPool()
	for i, cert := range parsedCerts {
		if i == len(parsedCerts)-1 {
			roots.AddCert(cert)
		} else {
			intermediates.AddCert(cert)
		}
	}

	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
	}

	_, err := parsedCerts[0].Verify(opts)
	return err
}

func (c *CertChain) EncodeBase64() (string, error) {
	var pemBuffer bytes.Buffer
	for _, certData := range c.certs {
		err := pem.Encode(&pemBuffer, &pem.Block{Type: "CERTIFICATE", Bytes: certData})
		if err != nil {
			return "", fmt.Errorf("failed to encode certificate: %v", err)
		}
	}

	base64PEM := base64.StdEncoding.EncodeToString(pemBuffer.Bytes())

	return base64PEM, nil
}
