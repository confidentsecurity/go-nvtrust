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

type library struct {
	mutex  sync.Mutex
	path   string
	handle unsafe.Pointer
}

func New(path string) *library {
	return &library{
		path: path,
	}
}

// NewWithDefault creates a library loader with the default NSCQ library path
func NewWithDefault() *library {
	return New("libnvidia-nscq.so.2")
}

func (l *library) Load() error {
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

func (l *library) Unload() error {
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
