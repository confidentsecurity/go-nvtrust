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

#ifndef NSCQ_CALLBACK_WRAPPERS_H
#define NSCQ_CALLBACK_WRAPPERS_H

#include "nscq_attestation.h"
#include <stdint.h>

// Forward declarations for Go callback exports
extern void goUUIDCallback(void* device, int8_t rc, void* uuid, void* userData);
extern void goArchCallback(void* device, int8_t rc, int8_t arch, void* userData);
extern void goTnvlStatusCallback(void* device, int8_t rc, int8_t status, void* userData);
extern void goAttestationReportCallback(void* device, int8_t rc, nscq_attestation_report_t report, void* userData);
extern void goAttestationCertificateCallback(void* device, int8_t rc, nscq_attestation_certificate_t cert, void* userData);

// C wrapper functions that will be passed to nscq_session_path_observe
void uuidCallbackWrapper(const nscq_uuid_t* device, nscq_rc_t rc, const nscq_uuid_t* uuid, void* userData);
void archCallbackWrapper(const nscq_uuid_t* device, nscq_rc_t rc, nscq_arch_t arch, void* userData);
void tnvlStatusCallbackWrapper(const nscq_uuid_t* device, nscq_rc_t rc, nscq_tnvl_status_t status, void* userData);
void attestationReportCallbackWrapper(const nscq_uuid_t* device, nscq_rc_t rc, const nscq_attestation_report_t report, void* userData);
void attestationCertificateCallbackWrapper(const nscq_uuid_t* device, nscq_rc_t rc, const nscq_attestation_certificate_t cert, void* userData);

#endif // NSCQ_CALLBACK_WRAPPERS_H
