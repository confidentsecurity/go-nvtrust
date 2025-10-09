// Copyright (c) 2025, Confident Security. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "callback_wrappers.h"

// C wrapper functions that will be passed to nscq_session_path_observe
// C code can call exported Go functions with their explicit name. But if a C-program wants a function pointer, 
// a gateway function has to be written. This is because we can’t take the address of a Go function and 
// give that to C-code since the cgo tool will generate a stub in C that should be called. The following 
// example shows how to integrate with C code wanting a function pointer of a give type.
// source: https://go.dev/wiki/cgo#function-pointer-callbacks
void uuidCallbackWrapper(const nscq_uuid_t* device, nscq_rc_t rc, const nscq_uuid_t* uuid, void* userData) {
    goUUIDCallback((void*)device, rc, (void*)uuid, userData);
}

void archCallbackWrapper(const nscq_uuid_t* device, nscq_rc_t rc, nscq_arch_t arch, void* userData) {
    goArchCallback((void*)device, rc, arch, userData);
}

void tnvlStatusCallbackWrapper(const nscq_uuid_t* device, nscq_rc_t rc, nscq_tnvl_status_t status, void* userData) {
    goTnvlStatusCallback((void*)device, rc, status, userData);
}

void attestationReportCallbackWrapper(const nscq_uuid_t* device, nscq_rc_t rc, const nscq_attestation_report_t report, void* userData) {
    goAttestationReportCallback((void*)device, rc, report, userData);
}

void attestationCertificateCallbackWrapper(const nscq_uuid_t* device, nscq_rc_t rc, const nscq_attestation_certificate_t cert, void* userData) {
    goAttestationCertificateCallback((void*)device, rc, cert, userData);
}
