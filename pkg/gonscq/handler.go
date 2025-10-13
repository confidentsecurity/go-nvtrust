// Copyright 2025 Nonvolatile Inc. d/b/a Confident Security

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//     https://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package gonscq

import (
	"errors"
	"fmt"

	"github.com/google/uuid"
)

// Handler constants
const (
	ExpectedNonceLength = 32
)

// Handler provides a high-level API for NSCQ operations
type Handler struct {
	library *Library
	session *Session
}

// NewHandler creates a new NSCQ handler with default library path
func NewHandler() (*Handler, error) {
	return NewHandlerWithLibrary("")
}

// NewHandlerWithLibrary creates a new NSCQ handler with a specific library path
func NewHandlerWithLibrary(libPath string) (*Handler, error) {
	// Load the NSCQ library
	var lib *Library
	if libPath == "" {
		lib = NewWithDefault()
	} else {
		lib = New(libPath)
	}

	return &Handler{
		library: lib,
	}, nil
}

func (h *Handler) Open() error {
	if err := h.library.Load(); err != nil {
		return fmt.Errorf("failed to load NSCQ library: %w", err)
	}

	// Create session
	session, err := SessionCreate(SessionCreateMountDevices)
	if err != nil {
		_ = h.library.Unload()
		return fmt.Errorf("failed to create session: %w", err)
	}
	h.session = session
	return nil
}

func (h *Handler) Close() {
	if h.session != nil {
		h.session.Destroy()
		h.session = nil
	}
	if h.library != nil {
		_ = h.library.Unload()
		h.library = nil
	}
}

func buildPath(basePath string, device string) string {
	if device == "" {
		return basePath
	}
	return "/" + device + basePath[len("/{nvswitch}"):]
}

func (h *Handler) GetAllSwitchUUIDs() ([]string, error) {
	uuids := make([]string, 0)
	var observeErr error

	callback := UUIDCallback(func(_ *uuid.UUID, rc Rc, deviceUUID *uuid.UUID, _ any) {
		if rc.IsError() {
			observeErr = rc
			return
		}

		if deviceUUID != nil {
			label, err := UUIDToLabel(deviceUUID, 0)
			if err != nil {
				observeErr = err
				return
			}
			uuids = append(uuids, label.String())
		}
	})

	if err := h.session.ObserveWithCallback(NVSwitchDeviceUUIDPath, callback); err != nil {
		return nil, fmt.Errorf("failed to observe UUID path: %w", err)
	}

	return uuids, observeErr
}

func (h *Handler) GetSwitchArchitecture() (Arch, error) {
	var observeErr error
	var deviceArch Arch

	callback := ArchCallback(func(_ *uuid.UUID, rc Rc, arch Arch, _ any) {
		if rc.IsError() {
			observeErr = rc
			return
		}

		deviceArch = arch
	})

	if err := h.session.ObserveWithCallback(NVSwitchArch, callback); err != nil {
		return 0, fmt.Errorf("failed to observe architecture path: %w", err)
	}

	return deviceArch, observeErr
}

func (h *Handler) GetSwitchTnvlStatus(device string) (TnvlStatus, error) {
	if device == "" {
		return 0, errors.New("device UUID cannot be empty")
	}

	var observeErr error
	var status TnvlStatus

	callback := TnvlStatusCallback(func(_ *uuid.UUID, rc Rc, tnvlStatus TnvlStatus, _ any) {
		if rc.IsError() {
			observeErr = rc
			return
		}

		status = tnvlStatus
	})

	path := buildPath(NVSwitchPCIeMode, device)
	if err := h.session.ObserveWithCallback(path, callback); err != nil {
		return 0, fmt.Errorf("failed to observe TNVL status path: %w", err)
	}

	return status, observeErr
}

func (h *Handler) GetAllSwitchTnvlStatus() (map[string]TnvlStatus, error) {
	tnvlStatus := make(map[string]TnvlStatus)
	var observeErr error

	callback := TnvlStatusCallback(func(device *uuid.UUID, rc Rc, status TnvlStatus, _ any) {
		if rc.IsError() {
			observeErr = rc
			return
		}

		if device != nil {
			label, err := UUIDToLabel(device, 0)
			if err != nil {
				observeErr = err
				return
			}
			tnvlStatus[label.String()] = status
		}
	})

	if err := h.session.ObserveWithCallback(NVSwitchPCIeMode, callback); err != nil {
		return nil, fmt.Errorf("failed to observe TNVL status path: %w", err)
	}

	return tnvlStatus, observeErr
}

func (h *Handler) IsSwitchTnvlMode(device string) (bool, error) {
	status, err := h.GetSwitchTnvlStatus(device)
	if err != nil {
		return false, err
	}
	return status.IsTnvlEnabled(), nil
}

func (h *Handler) IsSwitchLockMode(device string) (bool, error) {
	status, err := h.GetSwitchTnvlStatus(device)
	if err != nil {
		return false, err
	}
	return status.IsLocked(), nil
}

func (h *Handler) GetSwitchAttestationCertificateChain(device string) ([]byte, error) {
	if device == "" {
		return nil, errors.New("device UUID cannot be empty")
	}

	var observeErr error
	var certChain []byte

	callback := AttestationCertificateCallback(func(_ *uuid.UUID, rc Rc, cert AttestationCertificate, _ any) {
		if rc.IsError() {
			observeErr = rc
			return
		}

		certChain = cert.GetCertChain()
	})

	path := buildPath(NVSwitchCertificate, device)
	if err := h.session.ObserveWithCallback(path, callback); err != nil {
		return nil, fmt.Errorf("failed to observe certificate chain path: %w", err)
	}

	return certChain, observeErr
}

func (h *Handler) GetAllSwitchAttestationCertificateChain() (map[string][]byte, error) {
	certificateChains := make(map[string][]byte)
	var observeErr error

	callback := AttestationCertificateCallback(func(device *uuid.UUID, rc Rc, cert AttestationCertificate, _ any) {
		if rc.IsError() {
			observeErr = rc
			return
		}

		if device != nil {
			label, err := UUIDToLabel(device, 0)
			if err != nil {
				observeErr = err
				return
			}
			certificateChains[label.String()] = cert.GetCertChain()
		}
	})

	if err := h.session.ObserveWithCallback(NVSwitchCertificate, callback); err != nil {
		return nil, fmt.Errorf("failed to observe certificate chain path: %w", err)
	}

	return certificateChains, observeErr
}

func (h *Handler) GetSwitchAttestationReport(device string, nonce []byte) ([]byte, error) {
	if device == "" {
		return nil, errors.New("device UUID cannot be empty")
	}
	if len(nonce) != ExpectedNonceLength {
		return nil, fmt.Errorf("nonce must be %d bytes, got %d", ExpectedNonceLength, len(nonce))
	}

	// Set nonce as input
	if err := h.session.SetInput(nonce, 0); err != nil {
		return nil, fmt.Errorf("failed to set nonce: %w", err)
	}

	var observeErr error
	var report []byte

	callback := AttestationReportCallback(func(_ *uuid.UUID, rc Rc, attestationReport AttestationReport, _ any) {
		if rc.IsError() {
			observeErr = rc
			return
		}

		report = attestationReport.GetReport()
	})

	path := buildPath(NVSwitchAttestationReport, device)
	if err := h.session.ObserveWithCallback(path, callback); err != nil {
		return nil, fmt.Errorf("failed to observe attestation report path: %w", err)
	}

	return report, observeErr
}

func (h *Handler) GetAllSwitchAttestationReport(nonce []byte) (map[string][]byte, error) {
	if len(nonce) != ExpectedNonceLength {
		return nil, fmt.Errorf("nonce must be %d bytes, got %d", ExpectedNonceLength, len(nonce))
	}

	// Set nonce as input
	if err := h.session.SetInput(nonce, 0); err != nil {
		return nil, fmt.Errorf("failed to set nonce: %w", err)
	}

	attestationReports := make(map[string][]byte)
	var observeErr error

	callback := AttestationReportCallback(func(device *uuid.UUID, rc Rc, report AttestationReport, _ any) {
		if rc.IsError() {
			observeErr = rc
			return
		}

		if device != nil {
			label, err := UUIDToLabel(device, 0)
			if err != nil {
				observeErr = err
				return
			}

			attestationReports[label.String()] = report.GetReport()
		}
	})

	if err := h.session.ObserveWithCallback(NVSwitchAttestationReport, callback); err != nil {
		return nil, fmt.Errorf("failed to observe attestation report path: %w", err)
	}

	return attestationReports, observeErr
}
