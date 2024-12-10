package gonvtrust

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"

	"github.com/NVIDIA/go-nvml/pkg/nvml"
)

type RemoteEvidence struct {
	certificate string
	evidence    string
}

type GpuAttester struct {
	nvmlHandler NvmlHandler
}

func NewGpuAttester(testMode bool) *GpuAttester {
	if testMode {
		return &GpuAttester{
			nvmlHandler: &NvmlHandlerMock{},
		}
	}

	return &GpuAttester{
		nvmlHandler: &NvmlHandlerImpl{},
	}
}

func (g *GpuAttester) GetRemoteEvidence(nonce int) ([]RemoteEvidence, error) {
	ret := g.nvmlHandler.Init()

	if ret != nvml.SUCCESS {
		return nil, fmt.Errorf("Unable to initialize NVML: %v", nvml.ErrorString(ret))
	}

	computeState, ret := g.nvmlHandler.SystemGetConfComputeState()
	if ret != nvml.SUCCESS {
		return nil, fmt.Errorf("Unable to get compute state: %v", nvml.ErrorString(ret))
	}
	if computeState.CcFeature != nvml.CC_SYSTEM_FEATURE_ENABLED {
		return nil, fmt.Errorf("Confidential computing is not enabled")
	}

	count, ret := g.nvmlHandler.DeviceGetCount()
	if ret != nvml.SUCCESS {
		return nil, fmt.Errorf("Unable to get device count: %v", nvml.ErrorString(ret))
	}

	var remoteEvidence []RemoteEvidence

	for i := 0; i < count; i++ {
		device, ret := g.nvmlHandler.DeviceGetHandleByIndex(i)

		if ret != nvml.SUCCESS {
			return nil, fmt.Errorf("Unable to get device at index %d: %v", i, nvml.ErrorString(ret))
		}

		deviceArchitecture, ret := device.GetArchitecture()
		if ret != nvml.SUCCESS {
			return nil, fmt.Errorf("Unable to get architecture of device at index %d: %v", i, nvml.ErrorString(ret))
		}

		if deviceArchitecture != nvml.DEVICE_ARCH_HOPPER {
			return nil, fmt.Errorf("Device at index %d is not supported", i)
		}

		report, ret := device.GetConfComputeGpuAttestationReport()

		if ret != nvml.SUCCESS {
			return nil, fmt.Errorf("Unable to get attestation report of device at index %d: %v", i, nvml.ErrorString(ret))

		}

		attestationReportData := report.AttestationReport[:report.AttestationReportSize]
		encodedAttestationReport := base64.StdEncoding.EncodeToString(attestationReportData)

		certificate, ret := device.GetConfComputeGpuCertificate()

		if ret != nvml.SUCCESS {
			return nil, fmt.Errorf("Unable to get certificate of device at index %d: %v", i, nvml.ErrorString(ret))
		}

		attestationCertChainData := certificate.AttestationCertChain[:certificate.AttestationCertChainSize]
		certs := splitCertificates(attestationCertChainData)
		err := verifyCertificateChain(certs)
		if err != nil {
			return nil, fmt.Errorf("Failed to verify certificate chain: %v", err)
		}

		encodedCertChain, err := convertAndBase64Encode(certs)
		if err != nil {
			return nil, fmt.Errorf("Failed to encode certificate chain: %v", err)
		}

		remoteEvidence = append(remoteEvidence, RemoteEvidence{evidence: encodedAttestationReport, certificate: encodedCertChain})
	}

	return remoteEvidence, nil
}

func splitCertificates(chainData []byte) [][]byte {
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

	return certs
}

func verifyCertificateChain(certs [][]byte) error {
	var parsedCerts []*x509.Certificate

	for _, certData := range certs {
		cert, err := x509.ParseCertificate(certData)
		if err != nil {
			return fmt.Errorf("failed to parse certificate: %v", err)
		}
		parsedCerts = append(parsedCerts, cert)
	}

	if len(parsedCerts) < 2 {
		return fmt.Errorf("certificate chain must contain at least two certificates")
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

func convertAndBase64Encode(certs [][]byte) (string, error) {
	var pemBuffer bytes.Buffer
	for _, certData := range certs {
		err := pem.Encode(&pemBuffer, &pem.Block{Type: "CERTIFICATE", Bytes: certData})
		if err != nil {
			return "", fmt.Errorf("failed to encode certificate: %v", err)
		}
	}

	base64PEM := base64.StdEncoding.EncodeToString(pemBuffer.Bytes())

	return base64PEM, nil
}
