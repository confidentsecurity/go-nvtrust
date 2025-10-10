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

/*
#cgo linux LDFLAGS: -Wl,--export-dynamic -Wl,--unresolved-symbols=ignore-in-object-files
#cgo darwin LDFLAGS: -Wl,-undefined,dynamic_lookup
#include "nscq_attestation.h"
#include "nscq_attestation_path.h"
#include <stdlib.h>
*/
import "C"
import (
	"fmt"
	"unsafe"
)

// API Version constants
const (
	APIVersionMajor = 2
	APIVersionMinor = 0
	APIVersionPatch = 0
)

// Return code constants
const (
	RcSuccess                   = C.NSCQ_RC_SUCCESS
	RcWarningRdtInitFailure     = C.NSCQ_RC_WARNING_RDT_INIT_FAILURE
	RcErrorNotImplemented       = C.NSCQ_RC_ERROR_NOT_IMPLEMENTED
	RcErrorInvalidUUID          = C.NSCQ_RC_ERROR_INVALID_UUID
	RcErrorResourceNotMountable = C.NSCQ_RC_ERROR_RESOURCE_NOT_MOUNTABLE
	RcErrorOverflow             = C.NSCQ_RC_ERROR_OVERFLOW
	RcErrorUnexpectedValue      = C.NSCQ_RC_ERROR_UNEXPECTED_VALUE
	RcErrorUnsupportedDrv       = C.NSCQ_RC_ERROR_UNSUPPORTED_DRV
	RcErrorDrv                  = C.NSCQ_RC_ERROR_DRV
	RcErrorTimeout              = C.NSCQ_RC_ERROR_TIMEOUT
	RcErrorExt                  = C.NSCQ_RC_ERROR_EXT
	RcErrorUnspecified          = C.NSCQ_RC_ERROR_UNSPECIFIED
)

// Architecture constants
const (
	ArchSV10 = C.NSCQ_ARCH_SV10
	ArchLR10 = C.NSCQ_ARCH_LR10
	ArchLS10 = C.NSCQ_ARCH_LS10
)

// TNVL Mode constants
const (
	DeviceTnvlModeUnknown  = C.NSCQ_DEVICE_TNVL_MODE_UNKNOWN
	DeviceTnvlModeDisabled = C.NSCQ_DEVICE_TNVL_MODE_DISABLED
	DeviceTnvlModeEnabled  = C.NSCQ_DEVICE_TNVL_MODE_ENABLED
	DeviceTnvlModeFailure  = C.NSCQ_DEVICE_TNVL_MODE_FAILURE
	DeviceTnvlModeLocked   = C.NSCQ_DEVICE_TNVL_MODE_LOCKED
)

// Session flags
const (
	SessionCreateMountDevices = C.NSCQ_SESSION_CREATE_MOUNT_DEVICES
)

// Attestation constants
const (
	AttestationReportNonceSize  = C.NSCQ_ATTESTATION_REPORT_NONCE_SIZE
	AttestationReportSize       = C.NSCQ_ATTESTATION_REPORT_SIZE
	CertificateCertChainMaxSize = C.NSCQ_CERTIFICATE_CERT_CHAIN_MAX_SIZE
)

// Bit positions for TNVL status parsing
const (
	TnvlBitPosition = 0
	LockBitPosition = 1
)

// Rc represents an NSCQ return code
type Rc int8

// IsSuccess returns true if the return code indicates success
func (r Rc) IsSuccess() bool {
	return r == RcSuccess
}

// IsWarning returns true if the return code indicates a warning
func (r Rc) IsWarning() bool {
	return r > RcSuccess
}

// IsError returns true if the return code indicates an error
func (r Rc) IsError() bool {
	return r < RcSuccess
}

// Error implements the error interface
func (r Rc) Error() string {
	switch r {
	case RcSuccess:
		return "success"
	case RcWarningRdtInitFailure:
		return "warning: RDT initialization failure"
	case RcErrorNotImplemented:
		return "error: not implemented"
	case RcErrorInvalidUUID:
		return "error: invalid UUID"
	case RcErrorResourceNotMountable:
		return "error: resource not mountable"
	case RcErrorOverflow:
		return "error: overflow"
	case RcErrorUnexpectedValue:
		return "error: unexpected value"
	case RcErrorUnsupportedDrv:
		return "error: unsupported driver"
	case RcErrorDrv:
		return "error: driver error"
	case RcErrorTimeout:
		return "error: timeout"
	case RcErrorExt:
		return "error: external error"
	case RcErrorUnspecified:
		return "error: unspecified"
	default:
		return fmt.Sprintf("error: unknown return code %d", r)
	}
}

// UUID represents an NSCQ device UUID
type UUID struct {
	Bytes [16]byte
}

// String returns a string representation of the UUID
func (u UUID) String() string {
	return fmt.Sprintf("%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		u.Bytes[0], u.Bytes[1], u.Bytes[2], u.Bytes[3],
		u.Bytes[4], u.Bytes[5],
		u.Bytes[6], u.Bytes[7],
		u.Bytes[8], u.Bytes[9],
		u.Bytes[10], u.Bytes[11], u.Bytes[12], u.Bytes[13], u.Bytes[14], u.Bytes[15])
}

// Label represents an NSCQ device label
type Label struct {
	Data [64]byte
}

// String returns the label as a string
func (l Label) String() string {
	// Find null terminator
	for i, b := range l.Data {
		if b == 0 {
			return string(l.Data[:i])
		}
	}
	return string(l.Data[:])
}

// Arch represents device architecture
type Arch int8

// String returns architecture name
func (a Arch) String() string {
	switch a {
	case ArchSV10:
		return "SV10"
	case ArchLR10:
		return "LR10"
	case ArchLS10:
		return "LS10"
	default:
		return fmt.Sprintf("Unknown(%d)", a)
	}
}

// TnvlStatus represents TNVL mode status
type TnvlStatus int8

// IsTnvlEnabled checks if TNVL mode is enabled
func (t TnvlStatus) IsTnvlEnabled() bool {
	return (t>>TnvlBitPosition)&1 == 1
}

// IsLocked checks if lock mode is enabled
func (t TnvlStatus) IsLocked() bool {
	return (t>>LockBitPosition)&1 == 1
}

// String returns string representation
func (t TnvlStatus) String() string {
	switch t {
	case DeviceTnvlModeUnknown:
		return "Unknown"
	case DeviceTnvlModeDisabled:
		return "Disabled"
	case DeviceTnvlModeEnabled:
		return "Enabled"
	case DeviceTnvlModeFailure:
		return "Failure"
	case DeviceTnvlModeLocked:
		return "Locked"
	default:
		return fmt.Sprintf("Unknown(%d)", t)
	}
}

// AttestationReport represents an attestation report
type AttestationReport struct {
	ReportSize uint32
	Report     [AttestationReportSize]byte
}

// GetReport returns the actual report data (excluding padding)
func (a AttestationReport) GetReport() []byte {
	if a.ReportSize > AttestationReportSize {
		return a.Report[:]
	}
	return a.Report[:a.ReportSize]
}

// AttestationCertificate represents an attestation certificate chain
type AttestationCertificate struct {
	CertChain     [CertificateCertChainMaxSize]byte
	CertChainSize uint32
}

// GetCertChain returns the actual certificate chain data (excluding padding)
func (a AttestationCertificate) GetCertChain() []byte {
	if a.CertChainSize > CertificateCertChainMaxSize {
		return a.CertChain[:]
	}
	return a.CertChain[:a.CertChainSize]
}

// Session represents an NSCQ session handle
type Session struct {
	handle C.nscq_session_t
}

// sessionResult represents the result of session creation
type sessionResult struct {
	rc      Rc
	session Session
}

// Observer represents an NSCQ observer handle
type Observer struct {
	handle C.nscq_observer_t
}

// observerResult represents the result of observer registration
type observerResult struct {
	rc       Rc
	observer Observer
}

// Writer represents an NSCQ writer handle
type Writer struct {
	handle C.nscq_writer_t
}

// writerResult represents the result of writer creation
type writerResult struct {
	rc     Rc
	writer Writer
}

// Callback is a function type for path observation callbacks
type Callback func(device *UUID, rc Rc, data interface{}, userData interface{})

// UUIDCallback is invoked for UUID path observations
type UUIDCallback func(device *UUID, rc Rc, uuid *UUID, userData interface{})

// ArchCallback is invoked for architecture path observations
type ArchCallback func(device *UUID, rc Rc, arch Arch, userData interface{})

// TnvlStatusCallback is invoked for TNVL status path observations
type TnvlStatusCallback func(device *UUID, rc Rc, status TnvlStatus, userData interface{})

// AttestationReportCallback is invoked for attestation report path observations
type AttestationReportCallback func(device *UUID, rc Rc, report AttestationReport, userData interface{})

// AttestationCertificateCallback is invoked for certificate chain path observations
type AttestationCertificateCallback func(device *UUID, rc Rc, cert AttestationCertificate, userData interface{})

// convertCUUID converts a C UUID to Go UUID
func convertCUUID(cUUID *C.nscq_uuid_t) *UUID {
	if cUUID == nil {
		return nil
	}
	uuid := &UUID{}
	for i := 0; i < 16; i++ {
		uuid.Bytes[i] = byte(cUUID.bytes[i])
	}
	return uuid
}

// convertGoUUID converts a Go UUID to C UUID
func convertGoUUID(uuid *UUID) *C.nscq_uuid_t {
	if uuid == nil {
		return nil
	}
	cUUID := &C.nscq_uuid_t{}
	for i := 0; i < 16; i++ {
		cUUID.bytes[i] = C.uint8_t(uuid.Bytes[i])
	}
	return cUUID
}

// convertCLabel converts a C label to Go label
func convertCLabel(cLabel *C.nscq_label_t) *Label {
	if cLabel == nil {
		return nil
	}
	label := &Label{}
	for i := 0; i < 64; i++ {
		label.Data[i] = byte(cLabel.data[i])
	}
	return label
}

// convertCAttestationReport converts C attestation report to Go
func convertCAttestationReport(cReport *C.nscq_attestation_report_t) AttestationReport {
	if cReport == nil {
		return AttestationReport{}
	}
	report := AttestationReport{
		ReportSize: uint32(cReport.report_size),
	}
	for i := 0; i < AttestationReportSize; i++ {
		report.Report[i] = byte(cReport.report[i])
	}
	return report
}

// convertCAttestationCertificate converts C attestation certificate to Go
func convertCAttestationCertificate(cCert *C.nscq_attestation_certificate_t) AttestationCertificate {
	if cCert == nil {
		return AttestationCertificate{}
	}
	cert := AttestationCertificate{
		CertChainSize: uint32(cCert.cert_chain_size),
	}
	for i := 0; i < CertificateCertChainMaxSize; i++ {
		cert.CertChain[i] = byte(cCert.cert_chain[i])
	}
	return cert
}

// Helper function to convert Go string to C string (caller must free)
func cString(s string) *C.char {
	return C.CString(s)
}

// Helper function to free C string
func freeCString(s *C.char) {
	C.free(unsafe.Pointer(s))
}
