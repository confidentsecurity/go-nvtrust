// Copyright 2025 Nonvolatile Inc. d/b/a Confident Security
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package gonvtrust_test

import (
	"context"
	"errors"
	"testing"

	"github.com/confidentsecurity/go-nvtrust/pkg/gonvtrust"
	"github.com/confidentsecurity/go-nvtrust/pkg/gonvtrust/certs"
	"github.com/confidentsecurity/go-nvtrust/pkg/gonvtrust/nras"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
)

type MockDeviceInfo struct {
	arch              string
	attestationReport []byte
	certificate       *certs.CertChain
}

func (m *MockDeviceInfo) Arch() string {
	return m.arch
}

func (m *MockDeviceInfo) AttestationReport() []byte {
	return m.attestationReport
}

func (m *MockDeviceInfo) Certificate() *certs.CertChain {
	return m.certificate
}

type MockDeviceAdmin struct {
	collectEvidenceFunc func(nonce []byte) ([]*MockDeviceInfo, error)
}

func (m *MockDeviceAdmin) CollectEvidence(nonce []byte) ([]*MockDeviceInfo, error) {
	if m.collectEvidenceFunc != nil {
		return m.collectEvidenceFunc(nonce)
	}

	certChain := certs.NewCertChainFromData([]byte("mock-cert-data"))
	return []*MockDeviceInfo{
		{
			arch:              "HOPPER",
			attestationReport: []byte("mock-attestation-report"),
			certificate:       certChain,
		},
	}, nil
}

type MockRemoteVerifier struct {
	attestGPUFunc    func(ctx context.Context, request *nras.AttestationRequest) (*nras.AttestationResponse, error)
	attestSwitchFunc func(ctx context.Context, request *nras.AttestationRequest) (*nras.AttestationResponse, error)
	verifyJWTFunc    func(ctx context.Context, signedToken string) (*jwt.Token, error)
}

func (m *MockRemoteVerifier) AttestGPU(ctx context.Context, request *nras.AttestationRequest) (*nras.AttestationResponse, error) {
	if m.attestGPUFunc != nil {
		return m.attestGPUFunc(ctx, request)
	}

	return &nras.AttestationResponse{
		JWTData: []string{"header", "validJWTtoken"},
		DeviceJWTs: map[string]string{
			"device1": "token1",
		},
	}, nil
}

func (m *MockRemoteVerifier) AttestSwitch(ctx context.Context, request *nras.AttestationRequest) (*nras.AttestationResponse, error) {
	if m.attestSwitchFunc != nil {
		return m.attestSwitchFunc(ctx, request)
	}

	return &nras.AttestationResponse{
		JWTData: []string{"header", "validJWTtoken"},
		DeviceJWTs: map[string]string{
			"switch1": "token1",
		},
	}, nil
}

func (m *MockRemoteVerifier) VerifyJWT(ctx context.Context, signedToken string) (*jwt.Token, error) {
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

func TestNewRemoteAttester(t *testing.T) {
	t.Parallel()

	t.Run("Success", func(t *testing.T) {
		mockAdmin := &MockDeviceAdmin{}
		mockVerifier := &MockRemoteVerifier{}

		attester := gonvtrust.NewRemoteAttester(mockAdmin, mockVerifier)

		require.NotNil(t, attester)
	})

	t.Run("WithNilVerifier", func(t *testing.T) {
		mockAdmin := &MockDeviceAdmin{}

		attester := gonvtrust.NewRemoteAttester[*MockDeviceInfo](mockAdmin, nil)

		require.NotNil(t, attester)
	})
}

func TestAttest(t *testing.T) {
	t.Parallel()

	t.Run("Success_GPU_HOPPER", func(t *testing.T) {
		certChain := certs.NewCertChainFromData([]byte("mock-cert-data"))

		mockAdmin := &MockDeviceAdmin{
			collectEvidenceFunc: func(_ []byte) ([]*MockDeviceInfo, error) {
				return []*MockDeviceInfo{
					{
						arch:              "HOPPER",
						attestationReport: []byte("mock-report"),
						certificate:       certChain,
					},
				}, nil
			},
		}

		mockVerifier := &MockRemoteVerifier{
			attestGPUFunc: func(_ context.Context, request *nras.AttestationRequest) (*nras.AttestationResponse, error) {
				require.Equal(t, "HOPPER", request.Arch)
				require.Equal(t, 1, len(request.EvidenceList))
				return &nras.AttestationResponse{
					JWTData: []string{"header", "validJWTtoken"},
					DeviceJWTs: map[string]string{
						"gpu1": "token1",
					},
				}, nil
			},
		}

		attester := gonvtrust.NewRemoteAttester(mockAdmin, mockVerifier)
		nonce := []byte("test-nonce")

		result, err := attester.Attest(context.Background(), nonce)

		require.NoError(t, err)
		require.NotNil(t, result)
		require.True(t, result.Result)
		require.NotNil(t, result.JWTToken)
		require.Equal(t, 1, len(result.DevicesTokens))
		require.Equal(t, "token1", result.DevicesTokens["gpu1"])
	})

	t.Run("Success_GPU_BLACKWELL", func(t *testing.T) {
		certChain := certs.NewCertChainFromData([]byte("mock-cert-data"))

		mockAdmin := &MockDeviceAdmin{
			collectEvidenceFunc: func(_ []byte) ([]*MockDeviceInfo, error) {
				return []*MockDeviceInfo{
					{
						arch:              "BLACKWELL",
						attestationReport: []byte("mock-report"),
						certificate:       certChain,
					},
				}, nil
			},
		}

		mockVerifier := &MockRemoteVerifier{}

		attester := gonvtrust.NewRemoteAttester(mockAdmin, mockVerifier)
		nonce := []byte("test-nonce")

		result, err := attester.Attest(context.Background(), nonce)

		require.NoError(t, err)
		require.NotNil(t, result)
		require.True(t, result.Result)
	})

	t.Run("Success_Switch_LS10", func(t *testing.T) {
		certChain := certs.NewCertChainFromData([]byte("mock-cert-data"))

		mockAdmin := &MockDeviceAdmin{
			collectEvidenceFunc: func(_ []byte) ([]*MockDeviceInfo, error) {
				return []*MockDeviceInfo{
					{
						arch:              "LS10",
						attestationReport: []byte("mock-report"),
						certificate:       certChain,
					},
				}, nil
			},
		}

		mockVerifier := &MockRemoteVerifier{
			attestSwitchFunc: func(_ context.Context, request *nras.AttestationRequest) (*nras.AttestationResponse, error) {
				require.Equal(t, "LS10", request.Arch)
				return &nras.AttestationResponse{
					JWTData: []string{"header", "validJWTtoken"},
					DeviceJWTs: map[string]string{
						"switch1": "token1",
					},
				}, nil
			},
		}

		attester := gonvtrust.NewRemoteAttester(mockAdmin, mockVerifier)
		nonce := []byte("test-nonce")

		result, err := attester.Attest(context.Background(), nonce)

		require.NoError(t, err)
		require.NotNil(t, result)
		require.True(t, result.Result)
		require.Equal(t, 1, len(result.DevicesTokens))
		require.Equal(t, "token1", result.DevicesTokens["switch1"])
	})

	t.Run("CollectEvidenceFailure", func(t *testing.T) {
		mockAdmin := &MockDeviceAdmin{
			collectEvidenceFunc: func(_ []byte) ([]*MockDeviceInfo, error) {
				return nil, errors.New("failed to collect evidence")
			},
		}

		mockVerifier := &MockRemoteVerifier{}
		attester := gonvtrust.NewRemoteAttester(mockAdmin, mockVerifier)

		result, err := attester.Attest(context.Background(), []byte("nonce"))

		require.Error(t, err)
		require.Nil(t, result)
		require.Contains(t, err.Error(), "failed to collect evidence")
	})

	t.Run("NoDevicesFound", func(t *testing.T) {
		mockAdmin := &MockDeviceAdmin{
			collectEvidenceFunc: func(_ []byte) ([]*MockDeviceInfo, error) {
				return []*MockDeviceInfo{}, nil
			},
		}

		mockVerifier := &MockRemoteVerifier{}
		attester := gonvtrust.NewRemoteAttester(mockAdmin, mockVerifier)

		result, err := attester.Attest(context.Background(), []byte("nonce"))

		require.Error(t, err)
		require.Nil(t, result)
		require.Contains(t, err.Error(), "no devices found")
	})

	t.Run("UnsupportedArchitecture", func(t *testing.T) {
		certChain := certs.NewCertChainFromData([]byte("mock-cert-data"))

		mockAdmin := &MockDeviceAdmin{
			collectEvidenceFunc: func(_ []byte) ([]*MockDeviceInfo, error) {
				return []*MockDeviceInfo{
					{
						arch:              "AMPERE",
						attestationReport: []byte("mock-report"),
						certificate:       certChain,
					},
				}, nil
			},
		}

		mockVerifier := &MockRemoteVerifier{}
		attester := gonvtrust.NewRemoteAttester(mockAdmin, mockVerifier)

		result, err := attester.Attest(context.Background(), []byte("nonce"))

		require.Error(t, err)
		require.Nil(t, result)
		require.Contains(t, err.Error(), "unsupported architecture: AMPERE")
	})

	t.Run("CertificateEncodingFailure", func(t *testing.T) {
		certChain := certs.NewCertChainFromData([]byte{})

		mockAdmin := &MockDeviceAdmin{
			collectEvidenceFunc: func(_ []byte) ([]*MockDeviceInfo, error) {
				return []*MockDeviceInfo{
					{
						arch:              "HOPPER",
						attestationReport: []byte("mock-report"),
						certificate:       certChain,
					},
				}, nil
			},
		}

		mockVerifier := &MockRemoteVerifier{}
		attester := gonvtrust.NewRemoteAttester(mockAdmin, mockVerifier)

		result, err := attester.Attest(context.Background(), []byte("nonce"))

		require.NoError(t, err)
		require.NotNil(t, result)
	})

	t.Run("AttestGPUFailure", func(t *testing.T) {
		certChain := certs.NewCertChainFromData([]byte("mock-cert-data"))

		mockAdmin := &MockDeviceAdmin{
			collectEvidenceFunc: func(_ []byte) ([]*MockDeviceInfo, error) {
				return []*MockDeviceInfo{
					{
						arch:              "HOPPER",
						attestationReport: []byte("mock-report"),
						certificate:       certChain,
					},
				}, nil
			},
		}

		mockVerifier := &MockRemoteVerifier{
			attestGPUFunc: func(_ context.Context, _ *nras.AttestationRequest) (*nras.AttestationResponse, error) {
				return nil, errors.New("attestation service unavailable")
			},
		}

		attester := gonvtrust.NewRemoteAttester(mockAdmin, mockVerifier)

		result, err := attester.Attest(context.Background(), []byte("nonce"))

		require.Error(t, err)
		require.Nil(t, result)
		require.Contains(t, err.Error(), "failed to attest GPU")
	})

	t.Run("AttestSwitchFailure", func(t *testing.T) {
		certChain := certs.NewCertChainFromData([]byte("mock-cert-data"))

		mockAdmin := &MockDeviceAdmin{
			collectEvidenceFunc: func(_ []byte) ([]*MockDeviceInfo, error) {
				return []*MockDeviceInfo{
					{
						arch:              "LS10",
						attestationReport: []byte("mock-report"),
						certificate:       certChain,
					},
				}, nil
			},
		}

		mockVerifier := &MockRemoteVerifier{
			attestSwitchFunc: func(_ context.Context, _ *nras.AttestationRequest) (*nras.AttestationResponse, error) {
				return nil, errors.New("switch attestation failed")
			},
		}

		attester := gonvtrust.NewRemoteAttester(mockAdmin, mockVerifier)

		result, err := attester.Attest(context.Background(), []byte("nonce"))

		require.Error(t, err)
		require.Nil(t, result)
		require.Contains(t, err.Error(), "failed to attest switch")
	})

	t.Run("InvalidJWTData", func(t *testing.T) {
		certChain := certs.NewCertChainFromData([]byte("mock-cert-data"))

		mockAdmin := &MockDeviceAdmin{
			collectEvidenceFunc: func(_ []byte) ([]*MockDeviceInfo, error) {
				return []*MockDeviceInfo{
					{
						arch:              "HOPPER",
						attestationReport: []byte("mock-report"),
						certificate:       certChain,
					},
				}, nil
			},
		}

		mockVerifier := &MockRemoteVerifier{
			attestGPUFunc: func(_ context.Context, _ *nras.AttestationRequest) (*nras.AttestationResponse, error) {
				return &nras.AttestationResponse{
					DeviceJWTs: map[string]string{},
				}, nil
			},
		}

		attester := gonvtrust.NewRemoteAttester(mockAdmin, mockVerifier)

		result, err := attester.Attest(context.Background(), []byte("nonce"))

		require.Error(t, err)
		require.Nil(t, result)
		require.Contains(t, err.Error(), "invalid JWT data")
	})

	t.Run("JWTVerificationFailure", func(t *testing.T) {
		certChain := certs.NewCertChainFromData([]byte("mock-cert-data"))

		mockAdmin := &MockDeviceAdmin{
			collectEvidenceFunc: func(_ []byte) ([]*MockDeviceInfo, error) {
				return []*MockDeviceInfo{
					{
						arch:              "HOPPER",
						attestationReport: []byte("mock-report"),
						certificate:       certChain,
					},
				}, nil
			},
		}

		mockVerifier := &MockRemoteVerifier{
			verifyJWTFunc: func(_ context.Context, _ string) (*jwt.Token, error) {
				return nil, errors.New("JWT verification failed")
			},
		}

		attester := gonvtrust.NewRemoteAttester(mockAdmin, mockVerifier)

		result, err := attester.Attest(context.Background(), []byte("nonce"))

		require.Error(t, err)
		require.Nil(t, result)
		require.Contains(t, err.Error(), "failed to verify JWT")
	})

	t.Run("InvalidClaimsType", func(t *testing.T) {
		certChain := certs.NewCertChainFromData([]byte("mock-cert-data"))

		mockAdmin := &MockDeviceAdmin{
			collectEvidenceFunc: func(_ []byte) ([]*MockDeviceInfo, error) {
				return []*MockDeviceInfo{
					{
						arch:              "HOPPER",
						attestationReport: []byte("mock-report"),
						certificate:       certChain,
					},
				}, nil
			},
		}

		mockVerifier := &MockRemoteVerifier{
			verifyJWTFunc: func(_ context.Context, _ string) (*jwt.Token, error) {
				return &jwt.Token{
					Claims: jwt.RegisteredClaims{},
				}, nil
			},
		}

		attester := gonvtrust.NewRemoteAttester(mockAdmin, mockVerifier)

		result, err := attester.Attest(context.Background(), []byte("nonce"))

		require.Error(t, err)
		require.Nil(t, result)
		require.Contains(t, err.Error(), "failed to parse claims")
	})

	t.Run("MissingAttestationResultClaim", func(t *testing.T) {
		certChain := certs.NewCertChainFromData([]byte("mock-cert-data"))

		mockAdmin := &MockDeviceAdmin{
			collectEvidenceFunc: func(_ []byte) ([]*MockDeviceInfo, error) {
				return []*MockDeviceInfo{
					{
						arch:              "HOPPER",
						attestationReport: []byte("mock-report"),
						certificate:       certChain,
					},
				}, nil
			},
		}

		mockVerifier := &MockRemoteVerifier{
			verifyJWTFunc: func(_ context.Context, _ string) (*jwt.Token, error) {
				mockToken := &jwt.Token{}
				mockClaims := jwt.MapClaims{}
				mockToken.Claims = mockClaims
				return mockToken, nil
			},
		}

		attester := gonvtrust.NewRemoteAttester(mockAdmin, mockVerifier)

		result, err := attester.Attest(context.Background(), []byte("nonce"))

		require.Error(t, err)
		require.Nil(t, result)
		require.Contains(t, err.Error(), "failed to parse overall attestation result")
	})

	t.Run("NonceEncoding", func(t *testing.T) {
		certChain := certs.NewCertChainFromData([]byte("mock-cert-data"))

		expectedNonce := []byte("Hello, world!")
		nonceCaptured := false

		mockAdmin := &MockDeviceAdmin{
			collectEvidenceFunc: func(nonce []byte) ([]*MockDeviceInfo, error) {
				require.Equal(t, expectedNonce, nonce)
				return []*MockDeviceInfo{
					{
						arch:              "HOPPER",
						attestationReport: []byte("mock-report"),
						certificate:       certChain,
					},
				}, nil
			},
		}

		mockVerifier := &MockRemoteVerifier{
			attestGPUFunc: func(_ context.Context, request *nras.AttestationRequest) (*nras.AttestationResponse, error) {
				// nonce is hex encoded version of "Hello, world!"
				require.Equal(t, "48656c6c6f2c20776f726c6421", request.Nonce)
				nonceCaptured = true
				return &nras.AttestationResponse{
					JWTData: []string{"header", "validJWTtoken"},
					DeviceJWTs: map[string]string{
						"gpu1": "token1",
					},
				}, nil
			},
		}

		attester := gonvtrust.NewRemoteAttester(mockAdmin, mockVerifier)

		result, err := attester.Attest(context.Background(), expectedNonce)

		require.NoError(t, err)
		require.NotNil(t, result)
		require.True(t, nonceCaptured)
	})

	t.Run("MultipleDevices", func(t *testing.T) {
		certChain := certs.NewCertChainFromData([]byte("mock-cert-data"))

		mockAdmin := &MockDeviceAdmin{
			collectEvidenceFunc: func(_ []byte) ([]*MockDeviceInfo, error) {
				return []*MockDeviceInfo{
					{
						arch:              "HOPPER",
						attestationReport: []byte("report-1"),
						certificate:       certChain,
					},
					{
						arch:              "HOPPER",
						attestationReport: []byte("report-2"),
						certificate:       certChain,
					},
					{
						arch:              "HOPPER",
						attestationReport: []byte("report-3"),
						certificate:       certChain,
					},
				}, nil
			},
		}

		mockVerifier := &MockRemoteVerifier{
			attestGPUFunc: func(_ context.Context, request *nras.AttestationRequest) (*nras.AttestationResponse, error) {
				require.Equal(t, 3, len(request.EvidenceList))
				return &nras.AttestationResponse{
					JWTData: []string{"header", "validJWTtoken"},
					DeviceJWTs: map[string]string{
						"gpu1": "token1",
						"gpu2": "token2",
						"gpu3": "token3",
					},
				}, nil
			},
		}

		attester := gonvtrust.NewRemoteAttester(mockAdmin, mockVerifier)

		result, err := attester.Attest(context.Background(), []byte("nonce"))

		require.NoError(t, err)
		require.NotNil(t, result)
		require.Equal(t, 3, len(result.DevicesTokens))
	})
}
