package gonvtrust

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/NVIDIA/go-nvml/pkg/nvml"
	"github.com/golang-jwt/jwt/v5"
)

type AttestationVerifier interface {
	RequestRemoteAttestation(ctx context.Context, request *GPUAttestationRequest) (*GPUAttestationResponse, error)
	VerifyJWT(ctx context.Context, signedToken string) (*jwt.Token, error)
}

type NRASVerifier struct {
	remoteGpuVerifierURL string
}

func NewNRASVerifier() *NRASVerifier {
	return &NRASVerifier{
		remoteGpuVerifierURL: "https://nras.attestation.nvidia.com",
	}
}

func (v *NRASVerifier) RequestRemoteAttestation(ctx context.Context, request *GPUAttestationRequest) (*GPUAttestationResponse, error) {
	jsonRequest, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	fmt.Printf("jsonRequest: %s\n", string(jsonRequest))

	req, err := http.NewRequestWithContext(ctx, "POST", v.remoteGpuVerifierURL+"/v3/attest/gpu", bytes.NewBuffer(jsonRequest))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	response, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}

	defer response.Body.Close()

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to attest: %w", response.Status)
	}

	var rawResponse []any
	err = json.Unmarshal(body, &rawResponse)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	if len(rawResponse) != 2 {
		return nil, errors.New("unexpected response format")
	}

	attestResult := &GPUAttestationResponse{
		DeviceJWTs: make(map[string]string),
	}

	jwtArray, ok := rawResponse[0].([]any)
	if ok && len(jwtArray) >= 2 {
		for _, item := range jwtArray {
			if str, ok := item.(string); ok {
				attestResult.JWTData = append(attestResult.JWTData, str)
			}
		}
	}

	gpuTokens, ok := rawResponse[1].(map[string]any)
	if ok {
		for key, value := range gpuTokens {
			if str, ok := value.(string); ok {
				attestResult.DeviceJWTs[key] = str
			}
		}
	}

	return attestResult, nil
}

func (v *NRASVerifier) VerifyJWT(ctx context.Context, signedToken string) (*jwt.Token, error) {
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

type RemoteEvidence struct {
	Certificate string `json:"certificate"`
	Evidence    string `json:"evidence"`
}

type GpuAttester struct {
	nvmlHandler         NvmlHandler
	attestationVerifier AttestationVerifier
}

func NewGpuAttester(h NvmlHandler) *GpuAttester {
	if h == nil {
		h = &DefaultNVMLHandler{}
	}

	return &GpuAttester{
		nvmlHandler:         h,
		attestationVerifier: NewNRASVerifier(),
	}
}

func NewGpuAttesterWithVerifier(h NvmlHandler, v AttestationVerifier) *GpuAttester {
	if h == nil {
		h = &DefaultNVMLHandler{}
	}

	if v == nil {
		v = NewNRASVerifier()
	}

	return &GpuAttester{
		nvmlHandler:         h,
		attestationVerifier: v,
	}
}

func (g *GpuAttester) GetRemoteEvidence(nonce []byte) ([]RemoteEvidence, error) {
	ret := g.nvmlHandler.Init()

	if ret != nvml.SUCCESS {
		return nil, fmt.Errorf("unable to initialize NVML: %v", nvml.ErrorString(ret))
	}

	computeState, ret := g.nvmlHandler.SystemGetConfComputeState()
	if ret != nvml.SUCCESS {
		return nil, fmt.Errorf("unable to get compute state: %v", nvml.ErrorString(ret))
	}
	if computeState.CcFeature != nvml.CC_SYSTEM_FEATURE_ENABLED {
		return nil, errors.New("confidential computing is not enabled")
	}

	count, ret := g.nvmlHandler.DeviceGetCount()
	if ret != nvml.SUCCESS {
		return nil, fmt.Errorf("unable to get device count: %v", nvml.ErrorString(ret))
	}

	var remoteEvidence []RemoteEvidence

	for i := 0; i < count; i++ {
		device, ret := g.nvmlHandler.DeviceGetHandleByIndex(i)

		if ret != nvml.SUCCESS {
			return nil, fmt.Errorf("unable to get device at index %d: %v", i, nvml.ErrorString(ret))
		}

		deviceArchitecture, ret := device.GetArchitecture()

		if ret != nvml.SUCCESS {
			return nil, fmt.Errorf("unable to get architecture of device at index %d: %v", i, nvml.ErrorString(ret))
		}

		if deviceArchitecture != nvml.DEVICE_ARCH_HOPPER {
			return nil, fmt.Errorf("device at index %d is not supported", i)
		}

		report, ret := device.GetConfComputeGpuAttestationReport(nonce)

		if ret != nvml.SUCCESS {
			return nil, fmt.Errorf("unable to get attestation report of device at index %d: %v", i, nvml.ErrorString(ret))
		}

		attestationReportData := report.AttestationReport[:report.AttestationReportSize]
		encodedAttestationReport := base64.StdEncoding.EncodeToString(attestationReportData)

		certificate, ret := device.GetConfComputeGpuCertificate()

		if ret != nvml.SUCCESS {
			return nil, fmt.Errorf("unable to get certificate of device at index %d: %v", i, nvml.ErrorString(ret))
		}

		attestationCertChainData := certificate.AttestationCertChain[:certificate.AttestationCertChainSize]
		certChain := NewCertChainFromData(attestationCertChainData)
		err := certChain.verify()
		if err != nil {
			return nil, fmt.Errorf("failed to verify certificate chain: %v", err)
		}

		encodedCertChain, err := certChain.encodeBase64()
		if err != nil {
			return nil, fmt.Errorf("failed to encode certificate chain: %v", err)
		}

		remoteEvidence = append(remoteEvidence, RemoteEvidence{Evidence: encodedAttestationReport, Certificate: encodedCertChain})
	}

	return remoteEvidence, nil
}

func (g *GpuAttester) AttestRemoteEvidence(ctx context.Context, nonce []byte, evidenceList []RemoteEvidence) (*AttestationResult, error) {
	hexString := fmt.Sprintf("%x", nonce)
	request := GPUAttestationRequest{
		Nonce:         hexString,
		EvidenceList:  evidenceList,
		Arch:          "HOPPER",
		ClaimsVersion: "3.0",
	}

	attestationResponse, err := g.attestationVerifier.RequestRemoteAttestation(ctx, &request)
	if err != nil {
		return nil, fmt.Errorf("failed to request remote attestation: %w", err)
	}

	jwtToken, err := g.attestationVerifier.VerifyJWT(ctx, attestationResponse.JWTData[1])
	if err != nil {
		return nil, fmt.Errorf("failed to verify JWT: %w", err)
	}

	claims, ok := jwtToken.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("failed to parse claims")
	}

	result, ok := claims["x-nvidia-overall-att-result"].(bool)
	if !ok {
		return nil, errors.New("failed to get overall attestation result")
	}

	attestationResult := &AttestationResult{
		Result:     result,
		JWTToken:   jwtToken,
		GPUsTokens: attestationResponse.DeviceJWTs,
	}

	return attestationResult, nil
}

type AttestationResult struct {
	Result     bool
	JWTToken   *jwt.Token
	GPUsTokens map[string]string
}

type GPUAttestationRequest struct {
	Nonce         string           `json:"nonce"`
	EvidenceList  []RemoteEvidence `json:"evidence_list"`
	Arch          string           `json:"arch"`
	ClaimsVersion string           `json:"claims_version"`
}

type GPUAttestationResponse struct {
	JWTData    []string
	DeviceJWTs map[string]string
}
