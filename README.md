# go-nvtrust

A Go library for NVIDIA GPU confidential computing attestation, providing a Go implementation inspired by [nvidia/nvtrust](https://github.com/nvidia/nvtrust). This library enables secure attestation of NVIDIA GPU(H100) with Confidential Computing capabilities.

## Overview

`go-nvtrust` provides a comprehensive solution for:

- Collecting attestation evidence from NVIDIA GPUs
- Verifying GPU attestation reports through NVIDIA Remote Attestation Service (NRAS)
- Enabling confidential computing

The library leverages NVIDIA's NVML (NVIDIA Management Library) through [go-nvml](https://github.com/NVIDIA/go-nvml) to interact with GPU hardware and retrieve cryptographic attestation data.

## Installation

```bash
go get github.com/confidentsecurity/go-nvtrust
```

## Quick Start

### Complete Attestation with Verification

```go
package main

import (
    "context"
    "crypto/sha256"
    "fmt"
    "log"

    "github.com/confidentsecurity/go-nvtrust/pkg/gonvtrust"
)

func main() {
    nonce := []byte("attestation-nonce")
    hash := sha256.Sum256(nonce)

    // Create attester
    attester := gonvtrust.NewRemoteGPUAttester(nil)

    // Step 1: Collect evidence from local GPUs
    evidenceList, err := attester.GetRemoteEvidence(hash[:])
    if err != nil {
        log.Fatalf("Failed to collect evidence: %v", err)
    }

    // Step 2: Verify evidence remotely via NVIDIA's service
    ctx := context.Background()
    result, err := attester.AttestRemoteEvidence(ctx, hash[:], evidenceList)
    if err != nil {
        log.Fatalf("Failed to verify evidence: %v", err)
    }

    if result.Result {
        fmt.Println("GPU attestation successful - GPUs are trusted")
        fmt.Printf("Verified %d GPU(s)\n", len(result.GPUsTokens))
    } else {
        fmt.Println("GPU attestation failed - GPUs are not trusted")
    }
}
```

## Tests

### Key Methods

#### RemoteGPUAttester

Allows to retrieve the attestation evidence from the GPUs and verify it remotely via NVIDIA's service.

- `NewRemoteGPUAttester(gpuAdmin GPUAdmin) *RemoteGPUAttester`
- `GetRemoteEvidence(nonce []byte) ([]RemoteEvidence, error)`
- `AttestRemoteEvidence(ctx context.Context, nonce []byte, evidenceList []RemoteEvidence) (*AttestationResult, error)`

#### NvmlGPUAdmin

Allows to manage the GPU.

- `NewNvmlGPUAdmin(handler NvmlHandler) *NvmlGPUAdmin`
- `CollectEvidence(nonce []byte) ([]GPUInfo, error)`
- `IsConfidentialComputeEnabled() (bool, error)`
- `IsGPUReadyStateEnabled() (bool, error)`
- `EnableGPUReadyState() error`
- `AllGPUInPersistenceMode() (bool, error)`

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
