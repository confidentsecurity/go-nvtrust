package attestation

import (
	"crypto/ecdsa"
	"crypto/x509"
	"hash"
	"math/big"
)

type AttestationReport struct {
	requestData     []byte
	responseData    []byte
	signatureLength int
	RequestMessage  SpdmMeasurementRequestMessage
	ResponseMessag  SpdmMeasurementResponseMessage
}

func (a *AttestationReport) VerifySignature(cert *x509.Certificate, hash hash.Hash) bool {
	publicKey := cert.PublicKey

	signedMessage := append(a.requestData, a.responseData...)
	message := signedMessage[:len(signedMessage)-a.signatureLength]
	signature := signedMessage[len(signedMessage)-a.signatureLength:]

	r := big.NewInt(0).SetBytes(signature[:len(signature)/2])
	s := big.NewInt(0).SetBytes(signature[len(signature)/2:])

	hash.Write(message)
	sum := hash.Sum(nil)

	switch publicKey := publicKey.(type) {
	case *ecdsa.PublicKey:
		return ecdsa.Verify(publicKey, sum, r, s)
	}

	return false

}

func ParseAttestationReport(data []byte, signatureLength int) (*AttestationReport, error) {
	req, err := ParseSpdmMeasurementRequestMessage(data)
	if err != nil {
		return nil, err
	}
	res, err := ParseSpdmMeasurementResponseMessage(data[37:], signatureLength)
	if err != nil {
		return nil, err
	}
	att := AttestationReport{
		requestData:     data[:37],
		responseData:    data[37:],
		signatureLength: signatureLength,
		RequestMessage:  *req,
		ResponseMessag:  *res,
	}
	return &att, nil
}
