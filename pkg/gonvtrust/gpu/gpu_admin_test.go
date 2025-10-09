package gpu_test

import (
	_ "embed"
	"testing"

	"github.com/NVIDIA/go-nvml/pkg/nvml"
	"github.com/confidentsecurity/go-nvtrust/pkg/gonvtrust/gpu"
	testdata "github.com/confidentsecurity/go-nvtrust/pkg/gonvtrust/gpu/mocks"
	"github.com/stretchr/testify/require"
)

type MockNvmlHandler struct {
	gpu.NVMLHandlerMock

	initFunc                               func() nvml.Return
	deviceGetCountFunc                     func() (int, nvml.Return)
	deviceGetHandleByIndexFunc             func(index int) (gpu.NVMLDevice, nvml.Return)
	systemGetConfComputeStateFunc          func() (nvml.ConfComputeSystemState, nvml.Return)
	systemGetConfComputeGpusReadyStateFunc func() (uint32, nvml.Return)
	systemSetConfComputeGpusReadyStateFunc func(state uint32) nvml.Return
	mockDevice                             *MockNvmlDevice
}

func (m *MockNvmlHandler) Init() nvml.Return {
	if m.initFunc != nil {
		return m.initFunc()
	}

	return m.NVMLHandlerMock.Init()
}

func (m *MockNvmlHandler) SystemGetConfComputeState() (nvml.ConfComputeSystemState, nvml.Return) {
	if m.systemGetConfComputeStateFunc != nil {
		return m.systemGetConfComputeStateFunc()
	}

	return m.NVMLHandlerMock.SystemGetConfComputeState()
}

func (m *MockNvmlHandler) DeviceGetCount() (int, nvml.Return) {
	if m.deviceGetCountFunc != nil {
		return m.deviceGetCountFunc()
	}

	return m.NVMLHandlerMock.DeviceGetCount()
}

func (m *MockNvmlHandler) DeviceGetHandleByIndex(index int) (gpu.NVMLDevice, nvml.Return) {
	if m.deviceGetHandleByIndexFunc != nil {
		return m.deviceGetHandleByIndexFunc(index)
	}
	return m.mockDevice, nvml.SUCCESS
}

func (*MockNvmlHandler) SystemGetDriverVersion() (string, nvml.Return) {
	return "fake-driver-version", nvml.SUCCESS
}

func (m *MockNvmlHandler) SystemGetConfComputeGpusReadyState() (uint32, nvml.Return) {
	if m.systemGetConfComputeGpusReadyStateFunc != nil {
		return m.systemGetConfComputeGpusReadyStateFunc()
	}
	return m.NVMLHandlerMock.SystemGetConfComputeGpusReadyState()
}

func (m *MockNvmlHandler) SystemSetConfComputeGpusReadyState(state uint32) nvml.Return {
	if m.systemSetConfComputeGpusReadyStateFunc != nil {
		return m.systemSetConfComputeGpusReadyStateFunc(state)
	}
	return m.NVMLHandlerMock.SystemSetConfComputeGpusReadyState(state)
}

type MockNvmlDevice struct {
	gpu.NVMLDeviceMock

	getArchitectureFunc                    func() (nvml.DeviceArchitecture, nvml.Return)
	getConfComputeGpuAttestationReportFunc func() (nvml.ConfComputeGpuAttestationReport, nvml.Return)
	getConfComputeGpuCertificateFunc       func() (nvml.ConfComputeGpuCertificate, nvml.Return)
	getPersistenceModeFunc                 func() (nvml.EnableState, nvml.Return)
}

func (m *MockNvmlDevice) GetArchitecture() (nvml.DeviceArchitecture, nvml.Return) {
	if m.getArchitectureFunc != nil {
		return m.getArchitectureFunc()
	}
	return m.NVMLDeviceMock.GetArchitecture()
}

func (m *MockNvmlDevice) GetConfComputeGpuAttestationReport(_ []byte) (nvml.ConfComputeGpuAttestationReport, nvml.Return) {
	if m.getConfComputeGpuAttestationReportFunc != nil {
		return m.getConfComputeGpuAttestationReportFunc()
	}
	return m.NVMLDeviceMock.GetConfComputeGpuAttestationReport([]byte{})
}

func (m *MockNvmlDevice) GetConfComputeGpuCertificate() (nvml.ConfComputeGpuCertificate, nvml.Return) {
	if m.getConfComputeGpuCertificateFunc != nil {
		return m.getConfComputeGpuCertificateFunc()
	}
	return m.NVMLDeviceMock.GetConfComputeGpuCertificate()
}

func (m *MockNvmlDevice) GetPersistenceMode() (nvml.EnableState, nvml.Return) {
	if m.getPersistenceModeFunc != nil {
		return m.getPersistenceModeFunc()
	}
	return m.NVMLDeviceMock.GetPersistenceMode()
}

func TestCollectEvidence(t *testing.T) {
	t.Parallel()
	t.Run("Success", func(t *testing.T) {
		mockDevice := &MockNvmlDevice{
			getArchitectureFunc: func() (nvml.DeviceArchitecture, nvml.Return) {
				return nvml.DEVICE_ARCH_HOPPER, nvml.SUCCESS
			},
		}

		mockHandler := &MockNvmlHandler{
			initFunc: func() nvml.Return {
				return nvml.SUCCESS
			},
			systemGetConfComputeStateFunc: func() (nvml.ConfComputeSystemState, nvml.Return) {
				return nvml.ConfComputeSystemState{
					CcFeature: nvml.CC_SYSTEM_FEATURE_ENABLED,
				}, nvml.SUCCESS
			},
			deviceGetCountFunc: func() (int, nvml.Return) {
				return 1, nvml.SUCCESS
			},
			deviceGetHandleByIndexFunc: func(_ int) (gpu.NVMLDevice, nvml.Return) {
				return mockDevice, nvml.SUCCESS
			},
			mockDevice: mockDevice,
		}

		admin := gpu.NewNvmlGPUAdmin(mockHandler)
		nonce := []byte("test-nonce")
		gpuInfos, err := admin.CollectEvidence(nonce)

		require.NoError(t, err)
		require.Len(t, gpuInfos, 1)
		require.Equal(t, "HOPPER", gpuInfos[0].Arch())
		require.NotNil(t, gpuInfos[0].AttestationReport())
		require.NotNil(t, gpuInfos[0].Certificate())
	})

	t.Run("InvalidCertificateFailure", func(t *testing.T) {
		mockHandler := &MockNvmlHandler{
			mockDevice: &MockNvmlDevice{
				getConfComputeGpuCertificateFunc: func() (nvml.ConfComputeGpuCertificate, nvml.Return) {
					var certArray [5120]uint8
					copy(certArray[:], testdata.InvalidCertChainData)

					return nvml.ConfComputeGpuCertificate{
						AttestationCertChain:     certArray,
						AttestationCertChainSize: uint32(len(testdata.InvalidCertChainData)),
					}, nvml.SUCCESS
				},
			},
		}

		admin := gpu.NewNvmlGPUAdmin(mockHandler)
		nonce := []byte("test-nonce")
		gpuInfos, err := admin.CollectEvidence(nonce)

		require.Error(t, err)
		require.Nil(t, gpuInfos)
		require.Contains(t, err.Error(), "failed to verify certificate chain")
	})

	t.Run("InitFailure", func(t *testing.T) {
		mockHandler := &MockNvmlHandler{
			initFunc: func() nvml.Return {
				return nvml.ERROR_UNKNOWN
			},
		}

		admin := gpu.NewNvmlGPUAdmin(mockHandler)
		gpuInfos, err := admin.CollectEvidence([]byte{})

		require.Error(t, err)
		require.Nil(t, gpuInfos)
		require.Contains(t, err.Error(), "unable to initialize NVML")
	})

	t.Run("ConfidentialComputingNotEnabled", func(t *testing.T) {
		mockHandler := &MockNvmlHandler{
			initFunc: func() nvml.Return {
				return nvml.SUCCESS
			},
			systemGetConfComputeStateFunc: func() (nvml.ConfComputeSystemState, nvml.Return) {
				return nvml.ConfComputeSystemState{
					CcFeature: nvml.CC_SYSTEM_FEATURE_DISABLED,
				}, nvml.SUCCESS
			},
		}

		admin := gpu.NewNvmlGPUAdmin(mockHandler)
		gpuInfos, err := admin.CollectEvidence([]byte{})

		require.Error(t, err)
		require.Nil(t, gpuInfos)
		require.Equal(t, "confidential computing is not enabled", err.Error())
	})

	t.Run("DeviceCountFailure", func(t *testing.T) {
		mockHandler := &MockNvmlHandler{
			initFunc: func() nvml.Return {
				return nvml.SUCCESS
			},
			systemGetConfComputeStateFunc: func() (nvml.ConfComputeSystemState, nvml.Return) {
				return nvml.ConfComputeSystemState{
					CcFeature: nvml.CC_SYSTEM_FEATURE_ENABLED,
				}, nvml.SUCCESS
			},
			deviceGetCountFunc: func() (int, nvml.Return) {
				return 0, nvml.ERROR_NOT_SUPPORTED
			},
		}

		admin := gpu.NewNvmlGPUAdmin(mockHandler)
		gpuInfos, err := admin.CollectEvidence([]byte{})

		require.Error(t, err)
		require.Nil(t, gpuInfos)
		require.Contains(t, err.Error(), "unable to get device count")
	})

	t.Run("UnsupportedArchitecture", func(t *testing.T) {
		mockDevice := &MockNvmlDevice{
			getArchitectureFunc: func() (nvml.DeviceArchitecture, nvml.Return) {
				return nvml.DEVICE_ARCH_AMPERE, nvml.SUCCESS
			},
		}

		mockHandler := &MockNvmlHandler{
			initFunc: func() nvml.Return {
				return nvml.SUCCESS
			},
			systemGetConfComputeStateFunc: func() (nvml.ConfComputeSystemState, nvml.Return) {
				return nvml.ConfComputeSystemState{
					CcFeature: nvml.CC_SYSTEM_FEATURE_ENABLED,
				}, nvml.SUCCESS
			},
			deviceGetCountFunc: func() (int, nvml.Return) {
				return 1, nvml.SUCCESS
			},
			deviceGetHandleByIndexFunc: func(_ int) (gpu.NVMLDevice, nvml.Return) {
				return mockDevice, nvml.SUCCESS
			},
			mockDevice: mockDevice,
		}

		admin := gpu.NewNvmlGPUAdmin(mockHandler)
		gpuInfos, err := admin.CollectEvidence([]byte{})

		require.Error(t, err)
		require.Nil(t, gpuInfos)
		require.Contains(t, err.Error(), "device at index 0 is not supported")
	})
}

func TestAllGPUsInPersistenceMode(t *testing.T) {
	t.Parallel()
	t.Run("Success", func(t *testing.T) {
		mockDevice := &MockNvmlDevice{}
		mockHandler := &MockNvmlHandler{
			initFunc: func() nvml.Return {
				return nvml.SUCCESS
			},
			deviceGetCountFunc: func() (int, nvml.Return) {
				return 2, nvml.SUCCESS
			},
			deviceGetHandleByIndexFunc: func(_ int) (gpu.NVMLDevice, nvml.Return) {
				return mockDevice, nvml.SUCCESS
			},
			mockDevice: mockDevice,
		}

		admin := gpu.NewNvmlGPUAdmin(mockHandler)
		result, err := admin.AllGPUInPersistenceMode()

		require.NoError(t, err)
		require.True(t, result)
	})

	t.Run("NotAllEnabled", func(t *testing.T) {
		mockDevice := &MockNvmlDevice{}

		mockHandler := &MockNvmlHandler{
			initFunc: func() nvml.Return {
				return nvml.SUCCESS
			},
			deviceGetCountFunc: func() (int, nvml.Return) {
				return 1, nvml.SUCCESS
			},
			deviceGetHandleByIndexFunc: func(index int) (gpu.NVMLDevice, nvml.Return) {
				if index == 0 {
					// Return a device with persistence mode disabled
					return &MockNvmlDevice{
						getPersistenceModeFunc: func() (nvml.EnableState, nvml.Return) {
							return nvml.FEATURE_DISABLED, nvml.SUCCESS
						},
					}, nvml.SUCCESS
				}
				return mockDevice, nvml.SUCCESS
			},
		}

		admin := gpu.NewNvmlGPUAdmin(mockHandler)
		result, err := admin.AllGPUInPersistenceMode()

		require.NoError(t, err)
		require.False(t, result)
	})
}

func TestIsConfidentialComputeEnabled(t *testing.T) {
	t.Parallel()
	t.Run("Success", func(t *testing.T) {
		mockHandler := &MockNvmlHandler{
			initFunc: func() nvml.Return {
				return nvml.SUCCESS
			},
			systemGetConfComputeStateFunc: func() (nvml.ConfComputeSystemState, nvml.Return) {
				return nvml.ConfComputeSystemState{
					CcFeature: nvml.CC_SYSTEM_FEATURE_ENABLED,
				}, nvml.SUCCESS
			},
		}

		admin := gpu.NewNvmlGPUAdmin(mockHandler)
		enabled, err := admin.IsConfidentialComputeEnabled()

		require.NoError(t, err)
		require.True(t, enabled)
	})

	t.Run("Disabled", func(t *testing.T) {
		mockHandler := &MockNvmlHandler{
			initFunc: func() nvml.Return {
				return nvml.SUCCESS
			},
			systemGetConfComputeStateFunc: func() (nvml.ConfComputeSystemState, nvml.Return) {
				return nvml.ConfComputeSystemState{
					CcFeature: nvml.CC_SYSTEM_FEATURE_DISABLED,
				}, nvml.SUCCESS
			},
		}

		admin := gpu.NewNvmlGPUAdmin(mockHandler)
		enabled, err := admin.IsConfidentialComputeEnabled()

		require.NoError(t, err)
		require.False(t, enabled)
	})
}

func TestIsGpuReadyStateEnabled(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		mockHandler := &MockNvmlHandler{
			initFunc: func() nvml.Return {
				return nvml.SUCCESS
			},
			systemGetConfComputeGpusReadyStateFunc: func() (uint32, nvml.Return) {
				return 1, nvml.SUCCESS
			},
		}

		admin := gpu.NewNvmlGPUAdmin(mockHandler)
		enabled, err := admin.IsGPUReadyStateEnabled()

		require.NoError(t, err)
		require.True(t, enabled)
	})

	t.Run("Disabled", func(t *testing.T) {
		mockHandler := &MockNvmlHandler{
			initFunc: func() nvml.Return {
				return nvml.SUCCESS
			},
			systemGetConfComputeGpusReadyStateFunc: func() (uint32, nvml.Return) {
				return 0, nvml.SUCCESS
			},
		}

		admin := gpu.NewNvmlGPUAdmin(mockHandler)
		enabled, err := admin.IsGPUReadyStateEnabled()

		require.NoError(t, err)
		require.False(t, enabled)
	})
}

func TestEnableGpuReadyState(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		mockHandler := &MockNvmlHandler{
			initFunc: func() nvml.Return {
				return nvml.SUCCESS
			},
			systemSetConfComputeGpusReadyStateFunc: func(state uint32) nvml.Return {
				require.Equal(t, uint32(1), state)
				return nvml.SUCCESS
			},
		}

		admin := gpu.NewNvmlGPUAdmin(mockHandler)
		err := admin.EnableGPUReadyState()

		require.NoError(t, err)
	})

	t.Run("Failure", func(t *testing.T) {
		mockHandler := &MockNvmlHandler{
			initFunc: func() nvml.Return {
				return nvml.SUCCESS
			},
			systemSetConfComputeGpusReadyStateFunc: func(_ uint32) nvml.Return {
				return nvml.ERROR_NOT_SUPPORTED
			},
		}

		admin := gpu.NewNvmlGPUAdmin(mockHandler)
		err := admin.EnableGPUReadyState()

		require.Error(t, err)
		require.Contains(t, err.Error(), "unable to enable GPU ready state")
	})
}
