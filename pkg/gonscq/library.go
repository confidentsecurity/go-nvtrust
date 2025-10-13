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
#cgo linux LDFLAGS: -ldl
#include <dlfcn.h>
#include <stdlib.h>
#include "nscq_attestation_path.h"

*/
import "C"
import (
	"fmt"
	"runtime"
	"sync"
	"unsafe"
)

type Library struct {
	mutex  sync.Mutex
	path   string
	handle unsafe.Pointer
}

func New(path string) *Library {
	return &Library{
		path: path,
	}
}

// NewWithDefault creates a library loader with the default NSCQ library path
func NewWithDefault() *Library {
	return New("libnvidia-nscq.so.2")
}

func (l *Library) Load() error {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	// Locking the thread is critical here as the dlerror() is thread local so
	// go should not reschedule this onto another thread.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	cPath := C.CString(l.path)
	defer C.free(unsafe.Pointer(cPath))
	h := C.dlopen(cPath, C.RTLD_LAZY|C.RTLD_GLOBAL)
	if h == nil {
		errStr := C.GoString(C.dlerror())
		return &ErrLoadLibrary{errStr}
	}
	l.handle = h
	return nil
}

func (l *Library) Unload() error {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	// Locking the thread is critical here as the dlerror() is thread local so
	// go should not reschedule this onto another thread.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	if l.handle == nil {
		return nil
	}
	if C.dlclose(l.handle) != 0 {
		errStr := C.GoString(C.dlerror())
		return &ErrUnloadLibrary{errStr}
	}

	l.handle = nil
	return nil
}

type ErrLoadLibrary struct {
	message string
}

func (l *ErrLoadLibrary) Error() string {
	return fmt.Sprintf("failed to load library: %s", l.message)
}

type ErrUnloadLibrary struct {
	message string
}

func (l *ErrUnloadLibrary) Error() string {
	return fmt.Sprintf("failed to unload library: %s", l.message)
}
