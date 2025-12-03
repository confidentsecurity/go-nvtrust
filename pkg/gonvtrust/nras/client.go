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

package nras

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/golang-jwt/jwt/v5"
)

// jwtLeeway is the clock skew tolerance for JWT validation.
// This allows tokens to be valid slightly before their "not before" (nbf) time
// and slightly after their expiration (exp) time to account for clock drift
// between systems (including the NRAS server and the downstream client).
const jwtLeeway = 10 * time.Second

type Client struct {
	remoteGpuVerifierURL string
	httpClient           *http.Client
}

func NewNRASClient(httpClient *http.Client) *Client {
	return &Client{
		remoteGpuVerifierURL: "https://nras.attestation.nvidia.com",
		httpClient:           httpClient,
	}
}

func (v *Client) AttestGPU(ctx context.Context, request *AttestationRequest) (*AttestationResponse, error) {
	return v.attest(ctx, request, "/v3/attest/gpu")
}

func (v *Client) AttestSwitch(ctx context.Context, request *AttestationRequest) (*AttestationResponse, error) {
	return v.attest(ctx, request, "/v3/attest/switch")
}

func (v *Client) attest(ctx context.Context, request *AttestationRequest, url string) (*AttestationResponse, error) {
	// override claims version
	request.ClaimsVersion = "3.0"

	jsonRequest, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", v.remoteGpuVerifierURL+url, bytes.NewBuffer(jsonRequest))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	response, err := v.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}

	defer response.Body.Close()

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to attest: %s", response.Status)
	}

	var arrayResponse []json.RawMessage
	err = json.Unmarshal(body, &arrayResponse)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	if len(arrayResponse) != ExpectedTopLevelItems {
		return nil, fmt.Errorf("expected 2 elements in top-level array, but got %d", len(arrayResponse))
	}

	attestResult := &AttestationResponse{
		DeviceJWTs: make(map[string]string),
	}

	var jwtArray []string
	err = json.Unmarshal(arrayResponse[0], &jwtArray)
	if err != nil {
		return nil, fmt.Errorf("expected first element to be an array of strings, but got error: %w", err)
	}
	attestResult.JWTData = jwtArray

	var gpuTokens map[string]string
	err = json.Unmarshal(arrayResponse[1], &gpuTokens)
	if err != nil {
		return nil, fmt.Errorf("expected second element to be a map of strings, but got error: %w", err)
	}
	attestResult.DeviceJWTs = gpuTokens

	return attestResult, nil
}

func (v *Client) VerifyJWT(ctx context.Context, signedToken string) (*jwt.Token, error) {
	k, err := keyfunc.NewDefaultCtx(ctx, []string{v.remoteGpuVerifierURL + "/.well-known/jwks.json"})
	if err != nil {
		return nil, fmt.Errorf("failed to create a keyfunc.Keyfunc from the server's URL.\nError: %s", err)
	}
	parsed, err := jwt.Parse(signedToken, k.Keyfunc, jwt.WithLeeway(jwtLeeway))
	if err != nil {
		// jwt.Parse may return a non-nil token even if it fails validation.
		// Bubble up the (busted) token for later inspection.
		return parsed, fmt.Errorf("failed to parse the JWT.\nError: %w", err)
	}

	return parsed, nil
}

type AttestationRequest struct {
	Nonce         string           `json:"nonce"`
	Arch          string           `json:"arch"`
	EvidenceList  []RemoteEvidence `json:"evidence_list"`
	ClaimsVersion string           `json:"claims_version"`
}

type AttestationResponse struct {
	JWTData    []string
	DeviceJWTs map[string]string
}

type RemoteEvidence struct {
	Certificate string `json:"certificate"`
	Evidence    string `json:"evidence"`
}

const ExpectedTopLevelItems = 2
