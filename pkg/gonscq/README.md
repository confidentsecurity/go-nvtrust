# gonscq - Go Bindings for libnvidia-nscq

Go bindings for NVIDIA's libnvidia-nscq library, providing attestation capabilities for NVIDIA NVSwitch devices.

## Overview

`gonscq` provides both low-level CGo bindings and high-level Go APIs for interacting with NVSwitch devices through NVIDIA's NSCQ (NVSwitch Confidential Query) library.

## Installation

```bash
go get github.com/confidentsecurity/go-nvtrust/pkg/gonscq
```

## Quick Start

```go
package main

import (
    "crypto/rand"
    "fmt"
    "log"

    "github.com/confidentsecurity/go-nvtrust/pkg/gonscq"
)

func main() {
    // Create and open handler
    handler, err := gonscq.NewHandler()
    if err != nil {
        log.Fatalf("Failed to create handler: %v", err)
    }
    if err := handler.Open(); err != nil {
        log.Fatalf("Failed to open handler: %v", err)
    }
    defer handler.Close()

    // Get all switch UUIDs
    uuids, err := handler.GetAllSwitchUUIDs()
    if err != nil {
        log.Fatalf("Failed to get UUIDs: %v", err)
    }
    fmt.Printf("Found %d NVSwitch device(s)\n", len(uuids))

    deviceUUID := uuids[0]

    // Check TNVL and lock mode
    isTnvl, _ := handler.IsSwitchTnvlMode(deviceUUID)
    isLocked, _ := handler.IsSwitchLockMode(deviceUUID)
    fmt.Printf("TNVL: %v, Locked: %v\n", isTnvl, isLocked)

    // Generate nonce and get attestation report
    nonce := make([]byte, 32)
    rand.Read(nonce)

    report, err := handler.GetSwitchAttestationReport(deviceUUID, nonce)
    if err != nil {
        log.Fatalf("Failed to get report: %v", err)
    }
    fmt.Printf("Report size: %d bytes\n", len(report))

    // Get certificate chain
    certChain, err := handler.GetSwitchAttestationCertificateChain(deviceUUID)
    if err != nil {
        log.Fatalf("Failed to get cert chain: %v", err)
    }
    fmt.Printf("Cert chain size: %d bytes\n", len(certChain))
}
```

## API Reference

### High-Level Handler

#### Management
- `NewHandler() (*Handler, error)` - Create handler with default library path
- `Open() error` - Load library and create session
- `Close()` - Destroy session and unload library

#### Device Discovery
- `GetAllSwitchUUIDs() ([]string, error)` - Get all NVSwitch device UUIDs
- `GetSwitchArchitecture() (Arch, error)` - Get switch architecture

#### Status Checking
- `IsSwitchTnvlMode(device string) (bool, error)` - Check if TNVL mode enabled
- `IsSwitchLockMode(device string) (bool, error)` - Check if lock mode enabled

#### Attestation
- `GetSwitchAttestationReport(device string, nonce []byte) ([]byte, error)` - Get attestation report (nonce must be 32 bytes)
- `GetSwitchAttestationCertificateChain(device string) ([]byte, error)` - Get certificate chain

### Low-Level Session API

- `SessionCreate(flags uint32) (*Session, error)` - Create NSCQ session
- `(s *Session) Destroy()` - Destroy session
- `(s *Session) SetInput(data []byte, flags uint32) error` - Set input (e.g., nonce)
- `(s *Session) ObserveWithCallback(path string, callback any) error` - Observe path with callback

### Constants

- `SessionCreateMountDevices` - Mount devices during session creation
- `AttestationReportNonceSize = 32` - Required nonce size

## Examples

See `cmd/nscq-sample` and `cmd/switch-evidence-sample` for complete examples.

## License

Apache License 2.0

Copyright 2025 Nonvolatile Inc. d/b/a Confident Security
