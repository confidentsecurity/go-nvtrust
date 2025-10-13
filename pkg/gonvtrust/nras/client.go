package nras

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/golang-jwt/jwt/v5"
)

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

	var rawResponse []any
	err = json.Unmarshal(body, &rawResponse)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	if len(rawResponse) != EXPECTED_TOP_LEVEL_ITEMS {
		return nil, fmt.Errorf("expected 2 elements in top-level array, but got %d", len(rawResponse))
	}

	attestResult := &AttestationResponse{
		DeviceJWTs: make(map[string]string),
	}

	jwtArray, ok := rawResponse[0].([]string)
	if !ok {
		return nil, fmt.Errorf("expected first element to be an array, but got %v", rawResponse[0])
	}
	attestResult.JWTData = jwtArray

	gpuTokens, ok := rawResponse[1].(map[string]string)
	if !ok {
		return nil, fmt.Errorf("expected second element to be a map, but got %v", rawResponse[1])
	}
	attestResult.DeviceJWTs = gpuTokens

	return attestResult, nil
}

func (v *Client) VerifyJWT(ctx context.Context, signedToken string) (*jwt.Token, error) {
	k, err := keyfunc.NewDefaultCtx(ctx, []string{v.remoteGpuVerifierURL + "/.well-known/jwks.json"})
	if err != nil {
		return nil, fmt.Errorf("failed to create a keyfunc.Keyfunc from the server's URL.\nError: %s", err)
	}
	parsed, err := jwt.Parse(signedToken, k.Keyfunc)
	if err != nil {
		return nil, fmt.Errorf("failed to parse the JWT.\nError: %w", err)
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

const EXPECTED_TOP_LEVEL_ITEMS = 2
