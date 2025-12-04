package gonscq

import (
	"fmt"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/require"
)

func TestCallbackStorage(t *testing.T) {
	cb := func () {
		fmt.Println("CALLING BACK")
	}

	cb2 := func() {
		fmt.Println("Second Call Back")
		t.Log("Got back the wrong callback")
		t.Fail()
	}

	cbID := registerCallback(cb)
	defer unregisterCallback(cbID)
	cb2ID := registerCallback(cb2)
	defer unregisterCallback(cb2ID)


	gotCallback, ok := getCallback(cbID)
	if (!ok) {
		t.Fatal("Didn't find the first callback")
	}

	callable, ok :=gotCallback.(func ())
	if !ok {
		t.Fatal("wasn't callback shaped")
	}

	callable()
}

func TestPointerMath(t *testing.T) {
	cb := func () {
		fmt.Println("CALLING BACK")
	}

	cbID := registerCallback(cb)
	defer unregisterCallback(cbID)

	unSub := unsafe.Pointer(&cbID)

	reIDPtr := (*uint)(unSub)

	realID := *reIDPtr

	gotCallback, ok := getCallback(realID)
	if (!ok) {
		t.Fatal("Didn't find the first callback")
	}

	callable, ok :=gotCallback.(func ())
	if !ok {
		t.Fatal("wasn't callback shaped")
	}
	callable()

	require.Equal(t, cbID, realID)

}
