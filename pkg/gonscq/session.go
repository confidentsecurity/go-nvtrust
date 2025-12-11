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
	"errors"
	"fmt"
	"runtime"
	"sync"
	"unsafe"

	"github.com/google/uuid"
)

// SessionConfig holds configuration for creating a session
type SessionConfig struct {
	// Flags for session creation (e.g., SessionCreateMountDevices)
	Flags uint32
}

// DefaultSessionConfig returns a session config with default values
func DefaultSessionConfig() *SessionConfig {
	return &SessionConfig{
		Flags: SessionCreateMountDevices,
	}
}

// callbackRegistry manages callbacks registered for path observations
var callbackRegistry = struct {
	sync.RWMutex
	callbacks map[uint]any
	nextID    uint
}{
	callbacks: make(map[uint]any),
	nextID:    1,
}

// registerCallback stores a callback and returns its ID
func registerCallback(cb any) uint {
	callbackRegistry.Lock()
	defer callbackRegistry.Unlock()
	id := callbackRegistry.nextID
	callbackRegistry.callbacks[id] = cb
	callbackRegistry.nextID++
	return id
}

// getCallback retrieves a callback by ID
func getCallback(id uint) (any, bool) {
	callbackRegistry.RLock()
	defer callbackRegistry.RUnlock()
	cb, ok := callbackRegistry.callbacks[id]
	return cb, ok
}

// unregisterCallback removes a callback
func unregisterCallback(id uint) {
	callbackRegistry.Lock()
	defer callbackRegistry.Unlock()
	delete(callbackRegistry.callbacks, id)
}

// getWrapperForCallback returns the appropriate C wrapper function based on callback type
func getWrapperForCallback(callback any) (unsafe.Pointer, error) {
	switch callback.(type) {
	case UUIDCallback:
		return UUIDCallbackWrapper, nil
	case ArchCallback:
		return ArchCallbackWrapper, nil
	case TnvlStatusCallback:
		return TnvlStatusCallbackWrapper, nil
	case AttestationReportCallback:
		return AttestationReportCallbackWrapper, nil
	case AttestationCertificateCallback:
		return AttestationCertificateCallbackWrapper, nil
	default:
		return nil, fmt.Errorf("unknown callback type: %T", callback)
	}
}

// ObserveWithCallback is a helper that handles callback registration, path observation, and cleanup
func (s *Session) ObserveWithCallback(path string, callback any) error {
	wrapper, err := getWrapperForCallback(callback)
	if err != nil {
		return err
	}

	callbackID := registerCallback(callback)
	defer unregisterCallback(callbackID)

	return s.PathObserve(path, wrapper, unsafe.Pointer(&callbackID), 0)
}

// SessionCreate creates a new NSCQ session
func SessionCreate(flags uint32) (*Session, error) {
	result := C.nscq_session_create(C.uint32_t(flags))

	rc := Rc(result.rc)
	if rc.IsError() {
		return nil, fmt.Errorf("failed to create session: %w", rc)
	}

	session := &Session{handle: result.session}

	// Set finalizer to ensure cleanup
	runtime.SetFinalizer(session, func(s *Session) {
		if s.handle.handle != nil {
			s.Destroy()
		}
	})

	if rc.IsWarning() {
		// Log warning but continue
		fmt.Printf("Warning during session creation: %v\n", rc)
	}

	return session, nil
}

// Destroy destroys the NSCQ session
func (s *Session) Destroy() {
	if s.handle.handle != nil {
		C.nscq_session_destroy(s.handle)
		s.handle.handle = nil
	}
}

// SetInput sets input data for the session (e.g., nonce for attestation reports)
func (s *Session) SetInput(data []byte, flags uint32) error {
	if len(data) == 0 {
		return errors.New("input data cannot be empty")
	}

	rc := Rc(C.nscq_session_set_input(
		s.handle,
		C.uint32_t(flags),
		unsafe.Pointer(&data[0]),
		C.uint32_t(len(data)),
	))

	if rc.IsError() {
		return fmt.Errorf("failed to set input: %w", rc)
	}

	return nil
}

// UUIDToLabel converts a UUID to a label
func UUIDToLabel(deviceUUID *uuid.UUID, flags uint32) (*Label, error) {
	if deviceUUID == nil {
		return nil, errors.New("uuid cannot be nil")
	}

	cUUID := convertGoUUID(deviceUUID)
	var cLabel C.nscq_label_t

	rc := Rc(C.nscq_uuid_to_label(cUUID, &cLabel, C.uint32_t(flags)))

	if rc.IsError() {
		return nil, fmt.Errorf("failed to convert UUID to label: %w", rc)
	}

	return convertCLabel(&cLabel), nil
}

// PathObserve observes a path and invokes the callback with results
// Note: This is a simplified version. Full callback support requires C wrapper functions
func (s *Session) PathObserve(path string, callback unsafe.Pointer, userData unsafe.Pointer, flags uint32) error {
	// Convert path to C string
	cPath := cString(path)
	defer freeCString(cPath)

	rc := Rc(C.nscq_session_path_observe(
		s.handle,
		cPath,
		C.nscq_fn_t(callback),
		userData,
		C.uint32_t(flags),
	))

	if rc.IsError() {
		return fmt.Errorf("failed to observe path: %w", rc)
	}

	return nil
}
