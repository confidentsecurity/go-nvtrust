package gonvtrust

import (
	_ "embed"
	"testing"

	"github.com/NVIDIA/go-nvml/pkg/nvml"
	"github.com/stretchr/testify/assert"
)

type MockNvmlHandler struct {
	NVMLHandlerMock

	initFunc                      func() nvml.Return
	deviceGetCountFunc            func() (int, nvml.Return)
	deviceGetHandleByIndexFunc    func(index int) (NVMLDevice, nvml.Return)
	systemGetConfComputeStateFunc func() (nvml.ConfComputeSystemState, nvml.Return)
	mockDevice                    *MockNvmlDevice
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

func (m *MockNvmlHandler) DeviceGetHandleByIndex(index int) (NVMLDevice, nvml.Return) {
	if m.deviceGetHandleByIndexFunc != nil {
		return m.deviceGetHandleByIndexFunc(index)
	}
	return m.mockDevice, nvml.SUCCESS
}

func (m *MockNvmlHandler) SystemGetDriverVersion() (string, nvml.Return) {
	return "fake-driver-version", nvml.SUCCESS
}

type MockNvmlDevice struct {
	NVMLDeviceMock

	getArchitectureFunc                    func() (nvml.DeviceArchitecture, nvml.Return)
	getConfComputeGpuAttestationReportFunc func() (nvml.ConfComputeGpuAttestationReport, nvml.Return)
	getConfComputeGpuCertificateFunc       func() (nvml.ConfComputeGpuCertificate, nvml.Return)
}

func (m *MockNvmlDevice) GetArchitecture() (nvml.DeviceArchitecture, nvml.Return) {
	if m.getArchitectureFunc != nil {
		return m.getArchitectureFunc()
	}
	return m.NVMLDeviceMock.GetArchitecture()
}

func (m *MockNvmlDevice) GetConfComputeGpuAttestationReport(nonce []byte) (nvml.ConfComputeGpuAttestationReport, nvml.Return) {
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

func TestNewGpuAttester(t *testing.T) {
	attester := NewGpuAttester(false)

	assert.NotNil(t, attester)
	assert.IsType(t, &GpuAttester{}, attester)
}

func TestGetRemoteEvidence_Success(t *testing.T) {
	mockHandler := &MockNvmlHandler{
		mockDevice: &MockNvmlDevice{},
	}

	attester := &GpuAttester{nvmlHandler: mockHandler}

	evidence, err := attester.GetRemoteEvidence([]byte{})

	assert.NoError(t, err)
	assert.NotNil(t, evidence)
	assert.Equal(t, 1, len(evidence))
}

func TestGetRemoteEvidence_InitFailure(t *testing.T) {
	mockHandler := &MockNvmlHandler{
		initFunc: func() nvml.Return { return nvml.ERROR_UNKNOWN },
	}

	attester := &GpuAttester{nvmlHandler: mockHandler}

	evidence, err := attester.GetRemoteEvidence([]byte{})

	assert.Error(t, err)
	assert.EqualError(t, err, "unable to initialize NVML: ERROR_UNKNOWN")
	assert.Nil(t, evidence)
}

func TestGetRemoteEvidence_GetSystemStateFailure(t *testing.T) {
	mockHandler := &MockNvmlHandler{
		systemGetConfComputeStateFunc: func() (nvml.ConfComputeSystemState, nvml.Return) {
			return nvml.ConfComputeSystemState{}, nvml.ERROR_UNKNOWN
		},
	}

	attester := &GpuAttester{nvmlHandler: mockHandler}

	evidence, err := attester.GetRemoteEvidence([]byte{})

	assert.Error(t, err)
	assert.EqualError(t, err, "unable to get compute state: ERROR_UNKNOWN")
	assert.Nil(t, evidence)
}

func TestGetRemoteEvidence_ComputeStateNotEnabled(t *testing.T) {
	mockHandler := &MockNvmlHandler{
		systemGetConfComputeStateFunc: func() (nvml.ConfComputeSystemState, nvml.Return) {
			return nvml.ConfComputeSystemState{CcFeature: nvml.CC_SYSTEM_FEATURE_DISABLED}, nvml.SUCCESS
		},
	}

	attester := &GpuAttester{nvmlHandler: mockHandler}

	evidence, err := attester.GetRemoteEvidence([]byte{})

	assert.Error(t, err)
	assert.EqualError(t, err, "confidential computing is not enabled")
	assert.Nil(t, evidence)
}

func TestGetRemoteEvidence_GetDeviceCountFailure(t *testing.T) {
	mockHandler := &MockNvmlHandler{
		deviceGetCountFunc: func() (int, nvml.Return) { return 0, nvml.ERROR_UNKNOWN },
	}

	attester := &GpuAttester{nvmlHandler: mockHandler}

	evidence, err := attester.GetRemoteEvidence([]byte{})

	assert.Error(t, err)
	assert.EqualError(t, err, "unable to get device count: ERROR_UNKNOWN")
	assert.Nil(t, evidence)
}

func TestGetRemoteEvidence_GetDeviceHandleByIndexFailure(t *testing.T) {
	mockHandler := &MockNvmlHandler{
		deviceGetHandleByIndexFunc: func(index int) (NVMLDevice, nvml.Return) { return nil, nvml.ERROR_UNKNOWN },
	}

	attester := &GpuAttester{nvmlHandler: mockHandler}

	evidence, err := attester.GetRemoteEvidence([]byte{})

	assert.Error(t, err)
	assert.EqualError(t, err, "unable to get device at index 0: ERROR_UNKNOWN")
	assert.Nil(t, evidence)
}

func TestGetRemoteEvidence_GetAttestationReportFailure(t *testing.T) {
	mockHandler := &MockNvmlHandler{
		mockDevice: &MockNvmlDevice{
			getConfComputeGpuAttestationReportFunc: func() (nvml.ConfComputeGpuAttestationReport, nvml.Return) {
				return nvml.ConfComputeGpuAttestationReport{}, nvml.ERROR_UNKNOWN
			},
		},
	}

	attester := &GpuAttester{nvmlHandler: mockHandler}

	evidence, err := attester.GetRemoteEvidence([]byte{})

	assert.Error(t, err)
	assert.Nil(t, evidence)
}

func TestGetRemoteEvidence_FailedToRetrieveArchitecture(t *testing.T) {
	mockHandler := &MockNvmlHandler{
		mockDevice: &MockNvmlDevice{
			getArchitectureFunc: func() (nvml.DeviceArchitecture, nvml.Return) { return 0, nvml.ERROR_UNKNOWN },
		},
	}

	attester := &GpuAttester{nvmlHandler: mockHandler}

	evidence, err := attester.GetRemoteEvidence([]byte{})

	assert.Error(t, err)
	assert.Nil(t, evidence)
}

func TestGetRemoteEvidence_ArchitectureNotSupported(t *testing.T) {
	mockHandler := &MockNvmlHandler{
		mockDevice: &MockNvmlDevice{
			getArchitectureFunc: func() (nvml.DeviceArchitecture, nvml.Return) { return nvml.DEVICE_ARCH_TURING, nvml.SUCCESS },
		},
	}

	attester := &GpuAttester{nvmlHandler: mockHandler}

	evidence, err := attester.GetRemoteEvidence([]byte{})

	assert.Error(t, err)
	assert.Nil(t, evidence)
}

func TestGetRemoteEvidence_CertificateRetrievalFailure(t *testing.T) {
	mockHandler := &MockNvmlHandler{
		mockDevice: &MockNvmlDevice{
			getConfComputeGpuCertificateFunc: func() (nvml.ConfComputeGpuCertificate, nvml.Return) {
				return nvml.ConfComputeGpuCertificate{}, nvml.ERROR_UNKNOWN
			},
		},
	}

	attester := &GpuAttester{nvmlHandler: mockHandler}

	evidence, err := attester.GetRemoteEvidence([]byte{})

	assert.Error(t, err)
	assert.Nil(t, evidence)
}

//go:embed mocks/invalidCertChain.txt
var invalidCertChainData []byte

func TestGetRemoteEvidence_InvalidCertificateFailure(t *testing.T) {
	mockHandler := &MockNvmlHandler{
		mockDevice: &MockNvmlDevice{
			getConfComputeGpuCertificateFunc: func() (nvml.ConfComputeGpuCertificate, nvml.Return) {
				var certArray [5120]uint8
				copy(certArray[:], invalidCertChainData)

				return nvml.ConfComputeGpuCertificate{
					AttestationCertChain:     certArray,
					AttestationCertChainSize: uint32(len(invalidCertChainData)),
				}, nvml.SUCCESS
			},
		},
	}

	attester := &GpuAttester{nvmlHandler: mockHandler}

	evidence, err := attester.GetRemoteEvidence([]byte{})

	assert.Error(t, err)
	assert.Nil(t, evidence)
}
