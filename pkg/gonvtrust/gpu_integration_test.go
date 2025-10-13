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

//go:build gpu_integration

package gonvtrust_test

import (
	"context"
	"crypto/rand"
	"testing"

	"github.com/confidentsecurity/go-nvtrust/pkg/gonscq"
	"github.com/confidentsecurity/go-nvtrust/pkg/gonvtrust"
	"github.com/confidentsecurity/go-nvtrust/pkg/gonvtrust/gpu"
	"github.com/confidentsecurity/go-nvtrust/pkg/gonvtrust/nras"
	"github.com/confidentsecurity/go-nvtrust/pkg/gonvtrust/nvswitch"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
)

type MockNRASClient struct{}

func (m *MockNRASClient) AttestGPU(ctx context.Context, request *nras.AttestationRequest) (*nras.AttestationResponse, error) {
	return &nras.AttestationResponse{
		JWTData: []string{"header", "mock.jwt.token"},
		DeviceJWTs: map[string]string{
			"gpu-0": "mock-device-token-0",
		},
	}, nil
}

func (m *MockNRASClient) AttestSwitch(ctx context.Context, request *nras.AttestationRequest) (*nras.AttestationResponse, error) {
	return &nras.AttestationResponse{
		JWTData: []string{"header", "mock.jwt.token"},
		DeviceJWTs: map[string]string{
			"switch-0": "mock-device-token-0",
		},
	}, nil
}

func (m *MockNRASClient) VerifyJWT(ctx context.Context, signedToken string) (*jwt.Token, error) {
	token := &jwt.Token{
		Raw: signedToken,
		Claims: jwt.MapClaims{
			"x-nvidia-overall-att-result": true,
		},
	}
	return token, nil
}

func TestGPUAttestation_HappyPath(t *testing.T) {
	// Test end-to-end GPU attestation with mocked NRAS
	// This test requires a GPU with confidential computing enabled.
	// To run this test, use the following command:
	// go test -tags=gpu_integration -v -run TestGPUAttestation_HappyPath

	gpuAdmin, err := gpu.NewNvmlGPUAdmin(nil)
	require.NoError(t, err, "failed to create GPU admin")
	defer gpuAdmin.Shutdown()

	nonce := make([]byte, 32)
	_, err = rand.Read(nonce)
	require.NoError(t, err, "failed to generate nonce")

	mockNRAS := &MockNRASClient{}

	attester := gonvtrust.NewRemoteAttester(gpuAdmin, mockNRAS)

	result, err := attester.Attest(context.Background(), nonce)
	require.NoError(t, err, "attestation failed")
	require.NotNil(t, result, "attestation result should not be nil")

	require.True(t, result.Result, "attestation should succeed")
	require.NotNil(t, result.JWTToken, "JWT token should not be nil")
	require.NotEmpty(t, result.DevicesTokens, "device tokens should not be empty")

	t.Logf("✓ GPU attestation completed successfully")
	t.Logf("  Attestation Result: %v", result.Result)
	t.Logf("  Device Tokens: %d", len(result.DevicesTokens))
}

func TestNVSwitchAttestation_HappyPath(t *testing.T) {
	// Test end-to-end NVSwitch attestation with mocked NRAS
	// This test requires an NVSwitch with TNVL mode enabled.
	// To run this test, use the following command:
	// go test -tags=gpu_integration -v -run TestNVSwitchAttestation_HappyPath

	handler, err := gonscq.NewHandler()
	require.NoError(t, err, "failed to create NSCQ handler")

	switchAdmin, err := nvswitch.NewNscqSwitchAdmin(handler)
	require.NoError(t, err, "failed to create switch admin")
	defer switchAdmin.Shutdown()

	nonce := make([]byte, 32)
	_, err = rand.Read(nonce)
	require.NoError(t, err, "failed to generate nonce")

	mockNRAS := &MockNRASClient{}

	attester := gonvtrust.NewRemoteAttester(switchAdmin, mockNRAS)

	result, err := attester.Attest(context.Background(), nonce)
	require.NoError(t, err, "attestation failed")
	require.NotNil(t, result, "attestation result should not be nil")

	require.True(t, result.Result, "attestation should succeed")
	require.NotNil(t, result.JWTToken, "JWT token should not be nil")
	require.NotEmpty(t, result.DevicesTokens, "device tokens should not be empty")

	t.Logf("✓ NVSwitch attestation completed successfully")
	t.Logf("  Attestation Result: %v", result.Result)
	t.Logf("  Device Tokens: %d", len(result.DevicesTokens))
}
