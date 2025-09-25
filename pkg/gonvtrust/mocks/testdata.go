package mocks

import _ "embed"

//go:embed gpuAkCertChain.txt
var ValidCertChainData []byte

//go:embed attestationReport.txt
var AttestationReportData []byte

//go:embed invalidCertChain.txt
var InvalidCertChainData []byte
