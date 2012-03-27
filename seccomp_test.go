package seccomp

import (
	"testing"
	"unsafe"
)

const (
	PR_GET_NAME         = 16
	PR_SET_SECCOMP      = 22
	PR_SET_NO_NEW_PRIVS = 36

	SECCOMP_MODE_FILTER = 2 /* uses user-supplied filter. */
	SECCOMP_RET_KILL    = 0 /* kill the task immediately */

	BPF_LD  = 0x00
	BPF_JMP = 0x05
	BPF_RET = 0x06

	BPF_W = 0x00

	BPF_ABS = 0x20
	BPF_JEQ = 0x10

	BPF_K = 0x00

	AUDIT_ARCH_X86_64 = 8
	ARCH_NR           = AUDIT_ARCH_X86_64
)

func TestPrctl(t *testing.T) {
	buf := make([]byte, 16)
	if err := Prctl(PR_GET_NAME, uint64(uintptr(unsafe.Pointer(&buf[0]))), 0, 0, 0); err != nil {
		t.Errorf("Prctl(PR_GET_NAME): %v", err)
	}
	t.Fatalf("buf: %v", string(buf))
}

type SockFilter struct {
	Code uint16
	Jt   uint8
	Jf   uint8
	K    uint32
}

type SockFilterSlice []SockFilter

func BPF_STMT(code uint16, k uint32) SockFilter {
	return SockFilter{code, 0, 0, k}
}

func BPF_JUMP(code uint16, k uint32, jt uint8, jf uint8) SockFilter {
	return SockFilter{code, jt, jf, k}
}

func ValidateArchitecture() []SockFilter {
	return []SockFilter{
		BPF_STMT(BPF_LD+BPF_W+BPF_ABS, 8), // HACK: 8 = sizeof(int) for the arch.
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ARCH_NR, 1, 0),
		BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL),
	}
}

type SockFprog struct {
	Len    uint16
	Filter *SockFilter
}

func TestSeccomp(t *testing.T) {
	if err := Prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		t.Fatalf("Prctl(PR_SET_NO_NEW_PRIVS): %v", err)
	}
	var filter []SockFilter
	filter = append(filter, ValidateArchitecture()...)

	prog := &SockFprog{
		Len:    uint16(len(filter) * int(unsafe.Sizeof(SockFilter{}))),
		Filter: (*SockFilter)(unsafe.Pointer(&(filter)[0])),
	}
	//	t.Fatalf("prog: %v", prog)
	//	t.Fatalf("filter: %v", filter)
	if err := Prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, uint64(uintptr(unsafe.Pointer(prog))), 1<<64-1, 0); err != nil {
		t.Fatalf("prctl(SECCOMP): %v", err)
	}
}
