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
#include "callback_wrappers.h"
#include <stdlib.h>
*/
import "C"
import (
	"unsafe"
)

// Expose C callback wrapper functions as Go variables
var (
	UuidCallbackWrapper                   = C.uuidCallbackWrapper
	ArchCallbackWrapper                   = C.archCallbackWrapper
	TnvlStatusCallbackWrapper             = C.tnvlStatusCallbackWrapper
	AttestationReportCallbackWrapper      = C.attestationReportCallbackWrapper
	AttestationCertificateCallbackWrapper = C.attestationCertificateCallbackWrapper
)

//export goUUIDCallback
func goUUIDCallback(devicePtr unsafe.Pointer, rc int8, uuidPtr, userDataPtr unsafe.Pointer) {
	var device, uuid *UUID
	if devicePtr != nil {
		device = convertCUUID((*C.nscq_uuid_t)(devicePtr))
	}
	if uuidPtr != nil {
		uuid = convertCUUID((*C.nscq_uuid_t)(uuidPtr))
	}

	callbackID := uintptr(userDataPtr)
	if cb, ok := getCallback(callbackID); ok {
		if uuidCb, ok := cb.(UUIDCallback); ok {
			uuidCb(device, Rc(rc), uuid, nil)
		}
	}
}

//export goArchCallback
func goArchCallback(devicePtr unsafe.Pointer, rc int8, archVal int8, userDataPtr unsafe.Pointer) {
	var device *UUID
	if devicePtr != nil {
		device = convertCUUID((*C.nscq_uuid_t)(devicePtr))
	}
	arch := Arch(archVal)

	callbackID := uintptr(userDataPtr)
	if cb, ok := getCallback(callbackID); ok {
		if archCb, ok := cb.(ArchCallback); ok {
			archCb(device, Rc(rc), arch, nil)
		}
	}
}

//export goTnvlStatusCallback
func goTnvlStatusCallback(devicePtr unsafe.Pointer, rc int8, statusVal int8, userDataPtr unsafe.Pointer) {
	var device *UUID
	if devicePtr != nil {
		device = convertCUUID((*C.nscq_uuid_t)(devicePtr))
	}
	status := TnvlStatus(statusVal)

	callbackID := uintptr(userDataPtr)
	if cb, ok := getCallback(callbackID); ok {
		if statusCb, ok := cb.(TnvlStatusCallback); ok {
			statusCb(device, Rc(rc), status, nil)
		}
	}
}

//export goAttestationReportCallback
func goAttestationReportCallback(devicePtr unsafe.Pointer, rc int8, cReport C.nscq_attestation_report_t, userDataPtr unsafe.Pointer) {
	report := convertCAttestationReport(&cReport)
	device := convertCUUID((*C.nscq_uuid_t)(devicePtr))

	callbackID := uintptr(userDataPtr)
	if cb, ok := getCallback(callbackID); ok {
		if reportCb, ok := cb.(AttestationReportCallback); ok {
			reportCb(device, Rc(rc), report, nil)
		}
	}
}

//export goAttestationCertificateCallback
func goAttestationCertificateCallback(devicePtr unsafe.Pointer, rc int8, cCert C.nscq_attestation_certificate_t, userDataPtr unsafe.Pointer) {
	device := convertCUUID((*C.nscq_uuid_t)(devicePtr))
	cert := convertCAttestationCertificate(&cCert)

	callbackID := uintptr(userDataPtr)
	if cb, ok := getCallback(callbackID); ok {
		if certCb, ok := cb.(AttestationCertificateCallback); ok {
			certCb(device, Rc(rc), cert, nil)
		}
	}
}
