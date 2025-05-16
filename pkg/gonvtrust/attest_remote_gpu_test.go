package gonvtrust_test

import (
	_ "embed"
	"testing"

	"context"
	"fmt"

	"github.com/NVIDIA/go-nvml/pkg/nvml"
	"github.com/confidentsecurity/go-nvtrust/pkg/gonvtrust"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

type MockNvmlHandler struct {
	gonvtrust.NVMLHandlerMock

	initFunc                      func() nvml.Return
	deviceGetCountFunc            func() (int, nvml.Return)
	deviceGetHandleByIndexFunc    func(index int) (gonvtrust.NVMLDevice, nvml.Return)
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

func (m *MockNvmlHandler) DeviceGetHandleByIndex(index int) (gonvtrust.NVMLDevice, nvml.Return) {
	if m.deviceGetHandleByIndexFunc != nil {
		return m.deviceGetHandleByIndexFunc(index)
	}
	return m.mockDevice, nvml.SUCCESS
}

func (m *MockNvmlHandler) SystemGetDriverVersion() (string, nvml.Return) {
	return "fake-driver-version", nvml.SUCCESS
}

type MockNvmlDevice struct {
	gonvtrust.NVMLDeviceMock

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

type MockAttestationVerifier struct {
	verifyJWTFunc          func(ctx context.Context, signedToken string) (*jwt.Token, error)
	requestAttestationFunc func(ctx context.Context, request *gonvtrust.GPUAttestationRequest) (*gonvtrust.GPUAttestationResponse, error)
}

func (m *MockAttestationVerifier) RequestRemoteAttestation(ctx context.Context, request *gonvtrust.GPUAttestationRequest) (*gonvtrust.GPUAttestationResponse, error) {
	if m.requestAttestationFunc != nil {
		return m.requestAttestationFunc(ctx, request)
	}

	return &gonvtrust.GPUAttestationResponse{
		JWTData: []string{"header", "validJWTtoken"},
		DeviceJWTs: map[string]string{
			"gpu1": "token1",
		},
	}, nil
}

func (m *MockAttestationVerifier) VerifyJWT(ctx context.Context, signedToken string) (*jwt.Token, error) {
	if m.verifyJWTFunc != nil {
		return m.verifyJWTFunc(ctx, signedToken)
	}

	mockToken := &jwt.Token{}
	mockClaims := jwt.MapClaims{
		"x-nvidia-overall-att-result": true,
	}
	mockToken.Claims = mockClaims
	return mockToken, nil
}

func TestNewGpuAttester(t *testing.T) {
	attester := gonvtrust.NewGpuAttester(nil)

	assert.NotNil(t, attester)
	assert.IsType(t, &gonvtrust.GpuAttester{}, attester)
}

func TestGetRemoteEvidence_Success(t *testing.T) {
	mockHandler := &MockNvmlHandler{
		mockDevice: &MockNvmlDevice{},
	}

	attester := gonvtrust.NewGpuAttester(mockHandler)

	evidence, err := attester.GetRemoteEvidence([]byte{})

	assert.NoError(t, err)
	assert.NotNil(t, evidence)
	assert.Equal(t, 1, len(evidence))
}

func TestGetRemoteEvidence_InitFailure(t *testing.T) {
	mockHandler := &MockNvmlHandler{
		initFunc: func() nvml.Return { return nvml.ERROR_UNKNOWN },
	}

	attester := gonvtrust.NewGpuAttester(mockHandler)

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

	attester := gonvtrust.NewGpuAttester(mockHandler)

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

	attester := gonvtrust.NewGpuAttester(mockHandler)

	evidence, err := attester.GetRemoteEvidence([]byte{})

	assert.Error(t, err)
	assert.EqualError(t, err, "confidential computing is not enabled")
	assert.Nil(t, evidence)
}

func TestGetRemoteEvidence_GetDeviceCountFailure(t *testing.T) {
	mockHandler := &MockNvmlHandler{
		deviceGetCountFunc: func() (int, nvml.Return) { return 0, nvml.ERROR_UNKNOWN },
	}

	attester := gonvtrust.NewGpuAttester(mockHandler)

	evidence, err := attester.GetRemoteEvidence([]byte{})

	assert.Error(t, err)
	assert.EqualError(t, err, "unable to get device count: ERROR_UNKNOWN")
	assert.Nil(t, evidence)
}

func TestGetRemoteEvidence_GetDeviceHandleByIndexFailure(t *testing.T) {
	mockHandler := &MockNvmlHandler{
		deviceGetHandleByIndexFunc: func(index int) (gonvtrust.NVMLDevice, nvml.Return) { return nil, nvml.ERROR_UNKNOWN },
	}

	attester := gonvtrust.NewGpuAttester(mockHandler)

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

	attester := gonvtrust.NewGpuAttester(mockHandler)

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

	attester := gonvtrust.NewGpuAttester(mockHandler)

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

	attester := gonvtrust.NewGpuAttester(mockHandler)

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

	attester := gonvtrust.NewGpuAttester(mockHandler)

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

	attester := gonvtrust.NewGpuAttester(mockHandler)

	evidence, err := attester.GetRemoteEvidence([]byte{})

	assert.Error(t, err)
	assert.Nil(t, evidence)
}

func TestAttestRemoteEvidence_Success(t *testing.T) {
	mockVerifier := &MockAttestationVerifier{
		requestAttestationFunc: func(ctx context.Context, request *gonvtrust.GPUAttestationRequest) (*gonvtrust.GPUAttestationResponse, error) {
			assert.Equal(t, "48656c6c6f2c20776f726c6421", request.Nonce)
			assert.Equal(t, "HOPPER", request.Arch)
			assert.Equal(t, "3.0", request.ClaimsVersion)
			assert.Equal(t, 1, len(request.EvidenceList))

			return &gonvtrust.GPUAttestationResponse{
				JWTData: []string{"header", "validJWTtoken"},
				DeviceJWTs: map[string]string{
					"gpu1": "token1",
				},
			}, nil
		},
		verifyJWTFunc: func(ctx context.Context, signedToken string) (*jwt.Token, error) {
			mockToken := &jwt.Token{}
			mockClaims := jwt.MapClaims{
				"x-nvidia-overall-att-result": true,
			}
			mockToken.Claims = mockClaims
			return mockToken, nil
		},
	}

	mockHandler := &MockNvmlHandler{}
	attester := gonvtrust.NewGpuAttesterWithVerifier(mockHandler, mockVerifier)
	nonce := []byte("Hello, world!")
	evidence := []gonvtrust.RemoteEvidence{
		{
			Certificate: "mockCertificate",
			Evidence:    "mockEvidence",
		},
	}

	result, err := attester.AttestRemoteEvidence(context.Background(), nonce, evidence)

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.True(t, result.Result)
	assert.NotNil(t, result.JWTToken)
	assert.Equal(t, 1, len(result.GPUsTokens))
	assert.Equal(t, "token1", result.GPUsTokens["gpu1"])
}
func TestAttestRemoteEvidence_InvalidResponseStatus(t *testing.T) {
	mockVerifier := &MockAttestationVerifier{
		requestAttestationFunc: func(ctx context.Context, request *gonvtrust.GPUAttestationRequest) (*gonvtrust.GPUAttestationResponse, error) {
			return nil, fmt.Errorf("failed to attest: 400 Bad Request")
		},
	}

	mockHandler := &MockNvmlHandler{}
	attester := gonvtrust.NewGpuAttesterWithVerifier(mockHandler, mockVerifier)
	evidence := []gonvtrust.RemoteEvidence{
		{
			Certificate: "mockCertificate",
			Evidence:    "mockEvidence",
		},
	}

	result, err := attester.AttestRemoteEvidence(context.Background(), []byte{}, evidence)

	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "failed to attest")
}

func TestAttestRemoteEvidence_JWTVerificationFailure(t *testing.T) {
	mockVerifier := &MockAttestationVerifier{
		requestAttestationFunc: func(ctx context.Context, request *gonvtrust.GPUAttestationRequest) (*gonvtrust.GPUAttestationResponse, error) {
			return &gonvtrust.GPUAttestationResponse{
				JWTData: []string{"header", "invalidJWTtoken"},
				DeviceJWTs: map[string]string{
					"gpu1": "token1",
				},
			}, nil
		},
		verifyJWTFunc: func(ctx context.Context, signedToken string) (*jwt.Token, error) {
			return nil, fmt.Errorf("JWT verification failed")
		},
	}

	mockHandler := &MockNvmlHandler{}
	attester := gonvtrust.NewGpuAttesterWithVerifier(mockHandler, mockVerifier)
	evidence := []gonvtrust.RemoteEvidence{
		{
			Certificate: "mockCertificate",
			Evidence:    "mockEvidence",
		},
	}

	result, err := attester.AttestRemoteEvidence(context.Background(), []byte{}, evidence)

	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "failed to verify JWT")
}

func TestAttestRemoteEvidence_InvalidClaims(t *testing.T) {
	mockVerifier := &MockAttestationVerifier{
		requestAttestationFunc: func(ctx context.Context, request *gonvtrust.GPUAttestationRequest) (*gonvtrust.GPUAttestationResponse, error) {
			return &gonvtrust.GPUAttestationResponse{
				JWTData: []string{"header", "validJWTtoken"},
				DeviceJWTs: map[string]string{
					"gpu1": "token1",
				},
			}, nil
		},
		verifyJWTFunc: func(ctx context.Context, signedToken string) (*jwt.Token, error) {
			return &jwt.Token{}, nil
		},
	}

	mockHandler := &MockNvmlHandler{}
	attester := gonvtrust.NewGpuAttesterWithVerifier(mockHandler, mockVerifier)
	evidence := []gonvtrust.RemoteEvidence{
		{
			Certificate: "mockCertificate",
			Evidence:    "mockEvidence",
		},
	}

	result, err := attester.AttestRemoteEvidence(context.Background(), []byte{}, evidence)

	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "failed to parse claims")
}

func TestAttestRemoteEvidence_MissingAttestationResult(t *testing.T) {
	mockVerifier := &MockAttestationVerifier{
		requestAttestationFunc: func(ctx context.Context, request *gonvtrust.GPUAttestationRequest) (*gonvtrust.GPUAttestationResponse, error) {
			return &gonvtrust.GPUAttestationResponse{
				JWTData: []string{"header", "validJWTtoken"},
				DeviceJWTs: map[string]string{
					"gpu1": "token1",
				},
			}, nil
		},
		verifyJWTFunc: func(ctx context.Context, signedToken string) (*jwt.Token, error) {
			mockToken := &jwt.Token{}
			mockClaims := jwt.MapClaims{
				// Missing the "x-nvidia-overall-att-result" claim
				"other-claim": "value",
			}
			mockToken.Claims = mockClaims
			return mockToken, nil
		},
	}

	mockHandler := &MockNvmlHandler{}
	attester := gonvtrust.NewGpuAttesterWithVerifier(mockHandler, mockVerifier)
	evidence := []gonvtrust.RemoteEvidence{
		{
			Certificate: "mockCertificate",
			Evidence:    "mockEvidence",
		},
	}

	result, err := attester.AttestRemoteEvidence(context.Background(), []byte{}, evidence)

	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "failed to get overall attestation result")
}
