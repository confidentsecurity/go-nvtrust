package gonvtrust

import (
	"encoding/base64"
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
		certChain := NewCertChainFromData(attestationCertChainData)
		err := certChain.verify()
		if err != nil {
			return nil, fmt.Errorf("Failed to verify certificate chain: %v", err)
		}

		encodedCertChain, err := certChain.encodeBase64()
		if err != nil {
			return nil, fmt.Errorf("Failed to encode certificate chain: %v", err)
		}

		remoteEvidence = append(remoteEvidence, RemoteEvidence{evidence: encodedAttestationReport, certificate: encodedCertChain})
	}

	return remoteEvidence, nil
}
