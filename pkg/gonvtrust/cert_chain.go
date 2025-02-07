package gonvtrust

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

func (c *CertChain) verify() error {
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

func (c *CertChain) encodeBase64() (string, error) {
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
