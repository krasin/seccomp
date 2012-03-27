package main

import (
	"github.com/krasin/seccomp"
	"log"
	"syscall"
	"unsafe"
)

const (
	PR_GET_NAME         = 16
	PR_SET_SECCOMP      = 22
	PR_SET_NO_NEW_PRIVS = 36

	SECCOMP_MODE_FILTER = 2 /* uses user-supplied filter. */
	SECCOMP_RET_KILL    = 0 /* kill the task immediately */
	SECCOMP_RET_ALLOW   = 0x7fff0000

	BPF_LD  = 0x00
	BPF_JMP = 0x05
	BPF_RET = 0x06

	BPF_W = 0x00

	BPF_ABS = 0x20
	BPF_JEQ = 0x10

	BPF_K = 0x00

	AUDIT_ARCH_X86_64 = 8
	ARCH_NR           = AUDIT_ARCH_X86_64

	syscall_nr = 0
)

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

func ExamineSyscall() []SockFilter {
	return []SockFilter{
		BPF_STMT(BPF_LD+BPF_W+BPF_ABS, syscall_nr),
	}
}

func AllowSyscall(syscallNum uint32) []SockFilter {
	return []SockFilter{
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, syscallNum, 0, 1),
		BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW),
	}
}

func KillProcess() []SockFilter {
	return []SockFilter{
		BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL),
	}
}

type SockFprog struct {
	Len    uint16
	Filter *SockFilter
}

func main() {
	var filter []SockFilter
	filter = append(filter, ValidateArchitecture()...)

	// Grab the system call number.
	filter = append(filter, ExamineSyscall()...)

	// List allowed syscalls.
	filter = append(filter, AllowSyscall(syscall.SYS_RT_SIGRETURN)...)

	filter = append(filter, KillProcess()...)

	prog := &SockFprog{
		Len:    uint16(len(filter)),
		Filter: (*SockFilter)(unsafe.Pointer(&(filter)[0])),
	}

	pp := uint64(uintptr(unsafe.Pointer(prog)))
	log.Printf("pp: 0x%x\n", pp)
	if err := seccomp.Prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		log.Fatalf("Prctl(PR_SET_NO_NEW_PRIVS): %v", err)
	}
	if err := seccomp.Prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, pp, 1<<64-1, 0); err != nil {
		log.Fatalf("prctl(SECCOMP): %v", err)
	}
}
