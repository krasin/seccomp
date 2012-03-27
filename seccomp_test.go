package seccomp

import (
	"testing"
	"unsafe"
)

const (
	PR_GET_NAME = 16
)

func TestPrctl(t *testing.T) {
	buf := make([]byte, 16)
	if err := Prctl(PR_GET_NAME, uint64(uintptr(unsafe.Pointer(&buf[0]))), 0, 0, 0); err != nil {
		t.Errorf("Prcl(PR_GET_NAME): %v", err)
	}
	t.Fatalf("buf: %v", string(buf))
}
