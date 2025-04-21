package attestation_test

import (
	"crypto"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"testing"

	testdata "github.com/confidentsecurity/go-nvtrust/pkg/gonvtrust/mocks"
	attestation "github.com/confidentsecurity/go-nvtrust/pkg/gonvtrust/verifier/attestation"
	"github.com/stretchr/testify/assert"
)

func TestAttestationReport_Verify_Ok(t *testing.T) {
	attReportData, err := hex.DecodeString(string(testdata.AttestationReportData))
	assert.NoError(t, err)

	block, _ := pem.Decode(testdata.ValidCertChainData)
	assert.NotNil(t, block)

	cert, err := x509.ParseCertificate(block.Bytes)
	assert.NoError(t, err)

	att, err := attestation.ParseAttestationReport(attReportData, 96)
	assert.NoError(t, err)

	assert.True(t, att.VerifySignature(cert, crypto.SHA384.New()))
}

func TestAttestationReport_Verify_InvalidSignature(t *testing.T) {
	attReportData, err := hex.DecodeString(string(testdata.AttestationReportData))
	assert.NoError(t, err)

	attReportData[0] ^= 0x01 // flip the one bit in the message to invalidate the signature

	block, _ := pem.Decode(testdata.ValidCertChainData)
	assert.NotNil(t, block)

	cert, err := x509.ParseCertificate(block.Bytes)
	assert.NoError(t, err)

	att, err := attestation.ParseAttestationReport(attReportData, 96)
	assert.NoError(t, err)

	assert.False(t, att.VerifySignature(cert, crypto.SHA384.New()))
}
