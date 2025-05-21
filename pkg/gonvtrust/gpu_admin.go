package gonvtrust

import (
	"errors"
	"fmt"

	"github.com/NVIDIA/go-nvml/pkg/nvml"
)

type NvmlGpuAdmin struct {
	nvmlHandler NvmlHandler
}

type GPUInfo struct {
	Arch                  nvml.DeviceArchitecture
	AttestationReportData []byte
	CertificateData       *CertChain
}

func NewNvmlGpuAdmin(h NvmlHandler) *NvmlGpuAdmin {
	if h == nil {
		h = &DefaultNVMLHandler{}
	}

	return &NvmlGpuAdmin{
		nvmlHandler: h,
	}
}

func (g *NvmlGpuAdmin) CollectEvidence(nonce []byte) ([]GPUInfo, error) {
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

	var gpuInfos []GPUInfo

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

		gpuInfos = append(gpuInfos, GPUInfo{
			Arch:                  deviceArchitecture,
			AttestationReportData: report.AttestationReport[:report.AttestationReportSize],
			CertificateData:       certChain,
		})
	}

	return gpuInfos, nil
}

func (g *NvmlGpuAdmin) AllGPUsInPersistenceMode() (bool, error) {
	ret := g.nvmlHandler.Init()
	if ret != nvml.SUCCESS {
		return false, fmt.Errorf("unable to initialize NVML: %v", nvml.ErrorString(ret))
	}

	count, ret := g.nvmlHandler.DeviceGetCount()
	if ret != nvml.SUCCESS {
		return false, fmt.Errorf("unable to get device count: %v", nvml.ErrorString(ret))
	}

	for i := 0; i < count; i++ {
		device, ret := g.nvmlHandler.DeviceGetHandleByIndex(i)
		if ret != nvml.SUCCESS {
			return false, fmt.Errorf("unable to get device at index %d: %v", i, nvml.ErrorString(ret))
		}

		mode, ret := device.GetPersistenceMode()
		if ret != nvml.SUCCESS {
			return false, fmt.Errorf("unable to get persistence mode for device at index %d: %v", i, nvml.ErrorString(ret))
		}

		if mode != nvml.FEATURE_ENABLED {
			return false, nil
		}
	}

	return true, nil
}

func (g *NvmlGpuAdmin) IsConfidentialComputeEnabled() (bool, error) {
	ret := g.nvmlHandler.Init()
	if ret != nvml.SUCCESS {
		return false, fmt.Errorf("unable to initialize NVML: %v", nvml.ErrorString(ret))
	}

	computeState, ret := g.nvmlHandler.SystemGetConfComputeState()
	if ret != nvml.SUCCESS {
		return false, fmt.Errorf("unable to get compute state: %v", nvml.ErrorString(ret))
	}

	return computeState.CcFeature == nvml.CC_SYSTEM_FEATURE_ENABLED, nil
}

func (g *NvmlGpuAdmin) IsGpuReadyStateDisabled() (bool, error) {
	ret := g.nvmlHandler.Init()
	if ret != nvml.SUCCESS {
		return false, fmt.Errorf("unable to initialize NVML: %v", nvml.ErrorString(ret))
	}

	readyState, ret := g.nvmlHandler.SystemGetConfComputeGpusReadyState()
	if ret != nvml.SUCCESS {
		return false, fmt.Errorf("unable to get GPU ready state: %v", nvml.ErrorString(ret))
	}

	return readyState == 0, nil
}

func (g *NvmlGpuAdmin) EnableGpuReadyState() error {
	ret := g.nvmlHandler.Init()
	if ret != nvml.SUCCESS {
		return fmt.Errorf("unable to initialize NVML: %v", nvml.ErrorString(ret))
	}

	ret = g.nvmlHandler.SystemSetConfComputeGpusReadyState(1)
	if ret != nvml.SUCCESS {
		return fmt.Errorf("unable to enable GPU ready state: %v", nvml.ErrorString(ret))
	}

	return nil
}
