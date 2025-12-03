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

package gonvtrust

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/confidentsecurity/go-nvtrust/pkg/gonvtrust/certs"
	"github.com/confidentsecurity/go-nvtrust/pkg/gonvtrust/nras"
	"github.com/golang-jwt/jwt/v5"
)

type RemoteAttester[T DeviceInfo] struct {
	admin    DeviceAdmin[T]
	verifier RemoteVerifier
}

// Device-agnostic interfaces
type DeviceInfo interface {
	Arch() string
	AttestationReport() []byte
	Certificate() *certs.CertChain
}

type DeviceAdmin[T DeviceInfo] interface {
	CollectEvidence(nonce []byte) ([]T, error)
}

type RemoteVerifier interface {
	AttestGPU(ctx context.Context, request *nras.AttestationRequest) (*nras.AttestationResponse, error)
	AttestSwitch(ctx context.Context, request *nras.AttestationRequest) (*nras.AttestationResponse, error)
	VerifyJWT(ctx context.Context, signedToken string) (*jwt.Token, error)
}

func NewRemoteAttester[T DeviceInfo](admin DeviceAdmin[T], verifier RemoteVerifier) *RemoteAttester[T] {
	return &RemoteAttester[T]{
		admin:    admin,
		verifier: verifier,
	}
}

func (a *RemoteAttester[T]) Attest(ctx context.Context, nonce []byte) (*AttestationResult, error) {
	deviceInfos, err := a.admin.CollectEvidence(nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to collect evidence: %w", err)
	}
	if len(deviceInfos) == 0 {
		return nil, errors.New("no devices found")
	}
	arch := deviceInfos[0].Arch()

	attestationRequest, err := a.buildAttestationRequest(nonce, arch, deviceInfos)
	if err != nil {
		return nil, fmt.Errorf("failed to build attestation request: %w", err)
	}

	var attestationResponse *nras.AttestationResponse
	switch arch {
	case "HOPPER", "BLACKWELL":
		attestationResponse, err = a.verifier.AttestGPU(ctx, attestationRequest)
		if err != nil {
			return nil, fmt.Errorf("failed to attest GPU: %w", err)
		}
	case "LS10":
		attestationResponse, err = a.verifier.AttestSwitch(ctx, attestationRequest)
		if err != nil {
			return nil, fmt.Errorf("failed to attest switch: %w", err)
		}
	default:
		return nil, fmt.Errorf("unsupported architecture: %s", arch)
	}

	return a.parseAttestationResponse(ctx, attestationResponse)
}

func (*RemoteAttester[T]) buildAttestationRequest(nonce []byte, arch string, deviceInfos []T) (*nras.AttestationRequest, error) {
	evidenceList := make([]nras.RemoteEvidence, len(deviceInfos))

	for i, deviceInfo := range deviceInfos {
		encodedAttestationReport := base64.StdEncoding.EncodeToString(deviceInfo.AttestationReport())
		encodedCertChain, err := deviceInfo.Certificate().EncodeBase64()
		if err != nil {
			return nil, fmt.Errorf("failed to encode certificate: %w", err)
		}

		evidenceList[i] = nras.RemoteEvidence{Evidence: encodedAttestationReport, Certificate: encodedCertChain}
	}

	return &nras.AttestationRequest{
		Nonce:        fmt.Sprintf("%x", nonce),
		EvidenceList: evidenceList,
		Arch:         arch,
	}, nil
}

func (a *RemoteAttester[T]) parseAttestationResponse(ctx context.Context, response *nras.AttestationResponse) (*AttestationResult, error) {
	if len(response.JWTData) < ExpectJWTArrayItems {
		return nil, errors.New("invalid JWT data")
	}

	jwtToken, err := a.verifier.VerifyJWT(ctx, response.JWTData[1])
	if err != nil {
		return &AttestationResult{JWTToken: jwtToken}, fmt.Errorf("failed to verify JWT: %w", err)
	}

	claims, ok := jwtToken.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("failed to parse claims")
	}
	result, ok := claims["x-nvidia-overall-att-result"].(bool)
	if !ok {
		return nil, errors.New("failed to parse overall attestation result")
	}
	return &AttestationResult{
		Result:        result,
		JWTToken:      jwtToken,
		DevicesTokens: response.DeviceJWTs,
	}, nil
}

type AttestationResult struct {
	Result        bool
	JWTToken      *jwt.Token
	DevicesTokens map[string]string
}

const ExpectJWTArrayItems = 2
