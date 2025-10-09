package gpu

import (
	"errors"
	"fmt"

	"github.com/NVIDIA/go-nvml/pkg/nvml"
	"github.com/confidentsecurity/go-nvtrust/pkg/gonvtrust/certs"
)

type NvmlGPUAdmin struct {
	nvmlHandler NvmlHandler
}

type GPUDevice struct {
	arch                  nvml.DeviceArchitecture
	attestationReportData []byte
	certificateData       *certs.CertChain
}

func (d GPUDevice) Arch() string {
	switch d.arch {
	case nvml.DEVICE_ARCH_HOPPER:
		return "HOPPER"
	case nvml.DEVICE_ARCH_BLACKWELL:
		return "BLACKWELL"
	}
	return "UNSUPPORTED"
}

func (d GPUDevice) AttestationReport() []byte {
	return d.attestationReportData
}

func (d GPUDevice) Certificate() *certs.CertChain {
	return d.certificateData
}

func NewNvmlGPUAdmin(h NvmlHandler) (*NvmlGPUAdmin, error) {
	if h == nil {
		h = &DefaultNVMLHandler{}
	}

	ret := h.Init()

	if ret != nvml.SUCCESS {
		return nil, fmt.Errorf("unable to initialize NVML: %v", nvml.ErrorString(ret))
	}

	return &NvmlGPUAdmin{
		nvmlHandler: h,
	}, nil
}

func (g *NvmlGPUAdmin) CollectEvidence(nonce []byte) ([]GPUDevice, error) {
	ccSettings, ret := g.nvmlHandler.SystemGetConfComputeSettings()
	if ret != nvml.SUCCESS {
		return nil, fmt.Errorf("unable to get compute state: %v", nvml.ErrorString(ret))
	}

	if ccSettings.CcFeature != nvml.CC_SYSTEM_FEATURE_ENABLED && ccSettings.MultiGpuMode != nvml.CC_SYSTEM_MULTIGPU_PROTECTED_PCIE {
		return nil, errors.New("confidential computing is not enabled")
	}

	count, ret := g.nvmlHandler.DeviceGetCount()
	if ret != nvml.SUCCESS {
		return nil, fmt.Errorf("unable to get device count: %v", nvml.ErrorString(ret))
	}

	var gpuInfos []GPUDevice

	for i := 0; i < count; i++ {
		device, ret := g.nvmlHandler.DeviceGetHandleByIndex(i)

		if ret != nvml.SUCCESS {
			return nil, fmt.Errorf("unable to get device at index %d: %v", i, nvml.ErrorString(ret))
		}

		deviceArchitecture, ret := device.GetArchitecture()

		if ret != nvml.SUCCESS {
			return nil, fmt.Errorf("unable to get architecture of device at index %d: %v", i, nvml.ErrorString(ret))
		}

		if deviceArchitecture != nvml.DEVICE_ARCH_HOPPER && deviceArchitecture != nvml.DEVICE_ARCH_BLACKWELL {
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
		certChain := certs.NewCertChainFromData(attestationCertChainData)
		err := certChain.Verify()
		if err != nil {
			return nil, fmt.Errorf("failed to verify certificate chain: %v", err)
		}

		gpuInfos = append(gpuInfos, GPUDevice{
			arch:                  deviceArchitecture,
			attestationReportData: report.AttestationReport[:report.AttestationReportSize],
			certificateData:       certChain,
		})
	}

	return gpuInfos, nil
}

func (g *NvmlGPUAdmin) AllGPUInPersistenceMode() (bool, error) {
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

func (g *NvmlGPUAdmin) IsConfidentialComputeEnabled() (bool, error) {
	computeState, ret := g.nvmlHandler.SystemGetConfComputeState()
	if ret != nvml.SUCCESS {
		return false, fmt.Errorf("unable to get compute state: %v", nvml.ErrorString(ret))
	}

	return computeState.CcFeature == nvml.CC_SYSTEM_FEATURE_ENABLED, nil
}

func (g *NvmlGPUAdmin) IsGPUReadyStateEnabled() (bool, error) {
	readyState, ret := g.nvmlHandler.SystemGetConfComputeGpusReadyState()
	if ret != nvml.SUCCESS {
		return false, fmt.Errorf("unable to get GPU ready state: %v", nvml.ErrorString(ret))
	}

	return readyState == 1, nil
}

func (g *NvmlGPUAdmin) EnableGPUReadyState() error {
	ret := g.nvmlHandler.SystemSetConfComputeGpusReadyState(1)
	if ret != nvml.SUCCESS {
		return fmt.Errorf("unable to enable GPU ready state: %v", nvml.ErrorString(ret))
	}

	return nil
}

func (g *NvmlGPUAdmin) Shutdown() error {
	ret := g.nvmlHandler.Shutdown()
	if ret != nvml.SUCCESS {
		return fmt.Errorf("unable to shutdown NVML: %v", nvml.ErrorString(ret))
	}

	return nil
}
