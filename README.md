# go-nvtrust

A Go library for NVIDIA GPU and NVSwitch confidential computing attestation, providing a Go implementation inspired by [nvidia/nvtrust](https://github.com/nvidia/nvtrust). This library enables secure attestation of NVIDIA GPUs (Hopper, Blackwell) and NVSwitch devices with Confidential Computing capabilities.

## Overview

`go-nvtrust` provides a comprehensive solution for:

- Collecting attestation evidence from NVIDIA GPUs and NVSwitch devices
- Verifying attestation reports through NVIDIA Remote Attestation Service (NRAS)
- Enabling confidential computing workflows
- Go bindings for libnvidia-nscq (NVSwitch attestation library)

The library leverages:

- NVIDIA's NVML (NVIDIA Management Library) through [go-nvml](https://github.com/NVIDIA/go-nvml) for GPU attestation
- NVIDIA's libnvidia-nscq for NVSwitch attestation

## Supported Hardware

- **GPUs**: NVIDIA Hopper (H100), Blackwell architectures
- **NVSwitch**: LS10 architecture

## Installation

```bash
go get github.com/confidentsecurity/go-nvtrust
```

## Quick Start

### Attestation

```go
    ctx := context.Background()
    nonce := make([]byte, 32)
    if _, err := rand.Read(nonce); err != nil {
        log.Fatalf("Failed to generate nonce: %v", err)
    }

    nrasClient := nras.NewNRASClient(http.DefaultClient)

    // Create GPU admin and attester
    gpuAdmin, err := gpu.NewNvmlGPUAdmin(nil)
    if err != nil {
        log.Fatalf("Failed to create GPU admin: %v", err)
    }
    defer gpuAdmin.Shutdown()

    // Attest GPUs
    attester := gonvtrust.NewRemoteAttester(gpuAdmin, nrasClient)
    result, err := attester.Attest(ctx, nonce)
    if err != nil {
        log.Fatalf("Failed to attest: %v", err)
    }
    if result.Result {
        fmt.Println("GPU attestation successful - GPUs are trusted")
        fmt.Printf("Verified %d GPU(s)\n", len(result.DevicesTokens))
    } else {
        fmt.Println("GPU attestation failed")
    }

    // Attest NVSwitches
    attester = gonvtrust.NewRemoteAttester(switchAdmin, nrasClient)
    result, err = attester.Attest(ctx, nonce)
    if err != nil {
        log.Fatalf("Failed to attest: %v", err)
    }

    if result.Result {
        fmt.Println("NVSwitch attestation successful - switches are trusted")
        fmt.Printf("Verified %d NVSwitch(es)\n", len(result.DevicesTokens))
    } else {
        fmt.Println("NVSwitch attestation failed")
    }

```

## API Reference

### Core Attestation API

#### RemoteAttester[T DeviceInfo]

Generic attester for both GPU and NVSwitch devices.

- `NewRemoteAttester[T DeviceInfo](admin DeviceAdmin[T], verifier RemoteVerifier) *RemoteAttester[T]` - Creates a new remote attester
- `Attest(ctx context.Context, nonce []byte) (*AttestationResult, error)` - Collects evidence and verifies it remotely

#### AttestationResult

```go
type AttestationResult struct {
    Result        bool              // Overall attestation result
    JWTToken      *jwt.Token        // JWT token from NRAS
    DevicesTokens map[string]string // Individual device tokens
}
```

### GPU Administration

#### NvmlGPUAdmin

Manages NVIDIA GPU attestation through NVML.

- `NewNvmlGPUAdmin(handler NvmlHandler) (*NvmlGPUAdmin, error)` - Creates a new GPU admin
- `CollectEvidence(nonce []byte) ([]GPUDevice, error)` - Collects attestation evidence from all GPUs
- `IsConfidentialComputeEnabled() (bool, error)` - Checks if confidential compute is enabled
- `IsGPUReadyStateEnabled() (bool, error)` - Checks if GPU ready state is enabled
- `EnableGPUReadyState() error` - Enables GPU ready state
- `AllGPUInPersistenceMode() (bool, error)` - Checks if all GPUs are in persistence mode
- `Shutdown() error` - Shuts down the NVML library

### NVSwitch Administration

#### NscqSwitchAdmin

Manages NVSwitch attestation through libnvidia-nscq.

- `NewNscqSwitchAdmin(handler NvSwitchHandler) (*NscqSwitchAdmin, error)` - Creates a new switch admin
- `CollectEvidence(nonce []byte) ([]SwitchDevice, error)` - Collects attestation evidence from all switches
- `Shutdown() error` - Shuts down the NSCQ library

### NRAS Client

#### NRASClient

Client for communicating with NVIDIA Remote Attestation Service.

- `NewNRASClient(httpClient *http.Client) *NRASClient` - Creates a new NRAS client
- `AttestGPU(ctx context.Context, request *AttestationRequest) (*AttestationResponse, error)` - Attests GPU evidence
- `AttestSwitch(ctx context.Context, request *AttestationRequest) (*AttestationResponse, error)` - Attests switch evidence
- `VerifyJWT(ctx context.Context, signedToken string) (*jwt.Token, error)` - Verifies JWT token from NRAS

## Testing

### Unit Tests

Run the standard test suite:

```bash
go test -v ./pkg/...
```

### Integration Tests

Run integration tests (requires compatible GPU hardware):

```bash
go test -tags=gpu_integration -v ./pkg/...
```
