package gonvtrust

import (
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/NVIDIA/go-nvml/pkg/nvml"
)

type RemoteEvidence struct {
	Certificate string
	Evidence    string
}

type GpuAttester struct {
	nvmlHandler NvmlHandler
}

func NewGpuAttester(h NvmlHandler) *GpuAttester {
	if h == nil {
		h = &DefaultNVMLHandler{}
	}
	return &GpuAttester{
		nvmlHandler: h,
	}
}

func (g *GpuAttester) GetRemoteEvidence(nonce []byte) ([]RemoteEvidence, error) {
	ret := g.nvmlHandler.Init()

	if ret != nvml.SUCCESS {
		return nil, fmt.Errorf("unable to initialize NVML: %v", nvml.ErrorString(ret))
	}

	computeState, ret := g.nvmlHandler.SystemGetConfComputeState()
	if ret != nvml.SUCCESS {
		return nil, fmt.Errorf("unable to get compute state: %v", nvml.ErrorString(ret))
	}
	if computeState.CcFeature != nvml.CC_SYSTEM_FEATURE_ENABLED {
		return nil, errors.New("confidential computing is not enabled")
	}

	count, ret := g.nvmlHandler.DeviceGetCount()
	if ret != nvml.SUCCESS {
		return nil, fmt.Errorf("unable to get device count: %v", nvml.ErrorString(ret))
	}

	var remoteEvidence []RemoteEvidence

	for i := 0; i < count; i++ {
		device, ret := g.nvmlHandler.DeviceGetHandleByIndex(i)

		if ret != nvml.SUCCESS {
			return nil, fmt.Errorf("unable to get device at index %d: %v", i, nvml.ErrorString(ret))
		}

		deviceArchitecture, ret := device.GetArchitecture()

		if ret != nvml.SUCCESS {
			return nil, fmt.Errorf("unable to get architecture of device at index %d: %v", i, nvml.ErrorString(ret))
		}

		if deviceArchitecture != nvml.DEVICE_ARCH_HOPPER {
			return nil, fmt.Errorf("device at index %d is not supported", i)
		}

		report, ret := device.GetConfComputeGpuAttestationReport(nonce)

		if ret != nvml.SUCCESS {
			return nil, fmt.Errorf("unable to get attestation report of device at index %d: %v", i, nvml.ErrorString(ret))
		}

		attestationReportData := report.AttestationReport[:report.AttestationReportSize]
		encodedAttestationReport := base64.StdEncoding.EncodeToString(attestationReportData)

		certificate, ret := device.GetConfComputeGpuCertificate()

		if ret != nvml.SUCCESS {
			return nil, fmt.Errorf("unable to get certificate of device at index %d: %v", i, nvml.ErrorString(ret))
		}

		attestationCertChainData := certificate.AttestationCertChain[:certificate.AttestationCertChainSize]
		certChain := NewCertChainFromData(attestationCertChainData)
		err := certChain.verify()
		if err != nil {
			return nil, fmt.Errorf("failed to verify certificate chain: %v", err)
		}

		encodedCertChain, err := certChain.encodeBase64()
		if err != nil {
			return nil, fmt.Errorf("failed to encode certificate chain: %v", err)
		}

		remoteEvidence = append(remoteEvidence, RemoteEvidence{Evidence: encodedAttestationReport, Certificate: encodedCertChain})
	}

	return remoteEvidence, nil
}
