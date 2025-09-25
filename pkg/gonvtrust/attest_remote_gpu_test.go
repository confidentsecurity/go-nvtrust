package gonvtrust_test

import (
	_ "embed"
	"testing"

	"context"
	"errors"

	"github.com/NVIDIA/go-nvml/pkg/nvml"
	"github.com/confidentsecurity/go-nvtrust/pkg/gonvtrust"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
)

// MockGPUAdmin implements the GpuAdmin interface for testing
type MockGPUAdmin struct {
	collectEvidenceFunc func(nonce []byte) ([]gonvtrust.GPUInfo, error)
}

func (m *MockGPUAdmin) CollectEvidence(nonce []byte) ([]gonvtrust.GPUInfo, error) {
	if m.collectEvidenceFunc != nil {
		return m.collectEvidenceFunc(nonce)
	}

	// Default successful implementation
	return []gonvtrust.GPUInfo{
		{
			Arch:                  nvml.DEVICE_ARCH_HOPPER,
			AttestationReportData: []byte("mock-attestation-data"),
			CertificateData:       &gonvtrust.CertChain{},
		},
	}, nil
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

func TestRemoteGpuAttester(t *testing.T) {
	t.Run("NewGpuAttester", func(t *testing.T) {
		attester := gonvtrust.NewRemoteGPUAttester(nil)

		require.NotNil(t, attester)
		require.IsType(t, &gonvtrust.RemoteGPUAttester{}, attester)
	})
}

func TestGetRemoteEvidence(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		mockGpuAdmin := &MockGPUAdmin{}
		attester := gonvtrust.NewRemoteGPUAttester(mockGpuAdmin)

		evidence, err := attester.GetRemoteEvidence([]byte{})

		require.NoError(t, err)
		require.NotNil(t, evidence)
		require.Equal(t, 1, len(evidence))
	})

	t.Run("CollectEvidenceFailure", func(t *testing.T) {
		mockGpuAdmin := &MockGPUAdmin{
			collectEvidenceFunc: func(_ []byte) ([]gonvtrust.GPUInfo, error) {
				return nil, errors.New("unable to initialize NVML: ERROR_UNKNOWN")
			},
		}

		attester := gonvtrust.NewRemoteGPUAttester(mockGpuAdmin)

		evidence, err := attester.GetRemoteEvidence([]byte{})

		require.Error(t, err)
		require.EqualError(t, err, "failed to collect evidence: unable to initialize NVML: ERROR_UNKNOWN")
		require.Nil(t, evidence)
	})
}

func TestAttestRemoteEvidence(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		mockVerifier := &MockAttestationVerifier{
			requestAttestationFunc: func(_ context.Context, request *gonvtrust.GPUAttestationRequest) (*gonvtrust.GPUAttestationResponse, error) {
				require.Equal(t, "48656c6c6f2c20776f726c6421", request.Nonce)
				require.Equal(t, "HOPPER", request.Arch)
				require.Equal(t, "3.0", request.ClaimsVersion)
				require.Equal(t, 1, len(request.EvidenceList))

				return &gonvtrust.GPUAttestationResponse{
					JWTData: []string{"header", "validJWTtoken"},
					DeviceJWTs: map[string]string{
						"gpu1": "token1",
					},
				}, nil
			},
			verifyJWTFunc: func(_ context.Context, _ string) (*jwt.Token, error) {
				mockToken := &jwt.Token{}
				mockClaims := jwt.MapClaims{
					"x-nvidia-overall-att-result": true,
				}
				mockToken.Claims = mockClaims
				return mockToken, nil
			},
		}

		mockAdmin := &MockGPUAdmin{}
		attester := gonvtrust.NewRemoteGPUAttesterWithVerifier(mockAdmin, mockVerifier)
		nonce := []byte("Hello, world!")
		evidence := []gonvtrust.RemoteEvidence{
			{
				Certificate: "mockCertificate",
				Evidence:    "mockEvidence",
			},
		}

		result, err := attester.AttestRemoteEvidence(context.Background(), nonce, evidence)

		require.NoError(t, err)
		require.NotNil(t, result)
		require.True(t, result.Result)
		require.NotNil(t, result.JWTToken)
		require.Equal(t, 1, len(result.GPUsTokens))
		require.Equal(t, "token1", result.GPUsTokens["gpu1"])
	})

	t.Run("InvalidResponseStatus", func(t *testing.T) {
		mockVerifier := &MockAttestationVerifier{
			requestAttestationFunc: func(_ context.Context, _ *gonvtrust.GPUAttestationRequest) (*gonvtrust.GPUAttestationResponse, error) {
				return nil, errors.New("failed to attest: 400 Bad Request")
			},
		}

		mockAdmin := &MockGPUAdmin{}
		attester := gonvtrust.NewRemoteGPUAttesterWithVerifier(mockAdmin, mockVerifier)
		evidence := []gonvtrust.RemoteEvidence{
			{
				Certificate: "mockCertificate",
				Evidence:    "mockEvidence",
			},
		}

		result, err := attester.AttestRemoteEvidence(context.Background(), []byte{}, evidence)

		require.Error(t, err)
		require.Nil(t, result)
		require.Contains(t, err.Error(), "failed to attest")
	})

	t.Run("JWTVerificationFailure", func(t *testing.T) {
		mockVerifier := &MockAttestationVerifier{
			requestAttestationFunc: func(_ context.Context, _ *gonvtrust.GPUAttestationRequest) (*gonvtrust.GPUAttestationResponse, error) {
				return &gonvtrust.GPUAttestationResponse{
					JWTData: []string{"header", "invalidJWTtoken"},
					DeviceJWTs: map[string]string{
						"gpu1": "token1",
					},
				}, nil
			},
			verifyJWTFunc: func(_ context.Context, _ string) (*jwt.Token, error) {
				return nil, errors.New("JWT verification failed")
			},
		}

		mockAdmin := &MockGPUAdmin{}
		attester := gonvtrust.NewRemoteGPUAttesterWithVerifier(mockAdmin, mockVerifier)
		evidence := []gonvtrust.RemoteEvidence{
			{
				Certificate: "mockCertificate",
				Evidence:    "mockEvidence",
			},
		}

		result, err := attester.AttestRemoteEvidence(context.Background(), []byte{}, evidence)

		require.Error(t, err)
		require.Nil(t, result)
		require.Contains(t, err.Error(), "failed to verify JWT")
	})

	t.Run("InvalidClaims", func(t *testing.T) {
		mockVerifier := &MockAttestationVerifier{
			requestAttestationFunc: func(_ context.Context, _ *gonvtrust.GPUAttestationRequest) (*gonvtrust.GPUAttestationResponse, error) {
				return &gonvtrust.GPUAttestationResponse{
					JWTData: []string{"header", "validJWTtoken"},
					DeviceJWTs: map[string]string{
						"gpu1": "token1",
					},
				}, nil
			},
			verifyJWTFunc: func(_ context.Context, _ string) (*jwt.Token, error) {
				return &jwt.Token{}, nil
			},
		}

		mockAdmin := &MockGPUAdmin{}
		attester := gonvtrust.NewRemoteGPUAttesterWithVerifier(mockAdmin, mockVerifier)
		evidence := []gonvtrust.RemoteEvidence{
			{
				Certificate: "mockCertificate",
				Evidence:    "mockEvidence",
			},
		}

		result, err := attester.AttestRemoteEvidence(context.Background(), []byte{}, evidence)

		require.Error(t, err)
		require.Nil(t, result)
		require.Contains(t, err.Error(), "failed to parse claims")
	})

	t.Run("MissingAttestationResult", func(t *testing.T) {
		mockVerifier := &MockAttestationVerifier{
			requestAttestationFunc: func(_ context.Context, _ *gonvtrust.GPUAttestationRequest) (*gonvtrust.GPUAttestationResponse, error) {
				return &gonvtrust.GPUAttestationResponse{
					JWTData: []string{"header", "validJWTtoken"},
					DeviceJWTs: map[string]string{
						"gpu1": "token1",
					},
				}, nil
			},
			verifyJWTFunc: func(_ context.Context, _ string) (*jwt.Token, error) {
				mockToken := &jwt.Token{}
				mockClaims := jwt.MapClaims{
					// Missing the "x-nvidia-overall-att-result" claim
					"other-claim": "value",
				}
				mockToken.Claims = mockClaims
				return mockToken, nil
			},
		}

		mockAdmin := &MockGPUAdmin{}
		attester := gonvtrust.NewRemoteGPUAttesterWithVerifier(mockAdmin, mockVerifier)
		evidence := []gonvtrust.RemoteEvidence{
			{
				Certificate: "mockCertificate",
				Evidence:    "mockEvidence",
			},
		}

		result, err := attester.AttestRemoteEvidence(context.Background(), []byte{}, evidence)

		require.Error(t, err)
		require.Nil(t, result)
		require.Contains(t, err.Error(), "failed to get overall attestation result")
	})
}
