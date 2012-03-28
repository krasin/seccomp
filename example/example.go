package main

// This is an example of using 'mode 2 seccomp' based on
// the following tutorial: http://outflux.net/teach-seccomp/
//
// 'mode 2 seccomp' is the security mechanism that allows to restrict
// the list of syscalls allowed to be called from the current thread.
// In case of the policy violation, the thread is killed.
//
// As of now, 'mode 2 seccomp is supported in Ubuntu 12.04 and
// may become available in the mainline kernel 'soon'.
// You may follow the progress on lkml.org, for instance,
// https://lkml.org/lkml/2012/3/14/573

import (
	"fmt"
	"log"
	"os"
	"runtime"
	"syscall"
	"unsafe"
)

func Prctl(option int, arg2, arg3, arg4, arg5 uint64) (err error) {
	_, _, e1 := syscall.Syscall6(syscall.SYS_PRCTL, uintptr(option),
		uintptr(arg2), uintptr(arg3), uintptr(arg4), uintptr(arg5), 0)
	if e1 != 0 {
		err = e1
	}
	return
}

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

	AUDIT_ARCH_X86_64 = 3221225534 // HACK: I don't understand this value
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
		BPF_STMT(BPF_LD+BPF_W+BPF_ABS, 4), // HACK: I don't understand this 4.
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
	filter = append(filter, AllowSyscall(syscall.SYS_EXIT_GROUP)...)
	filter = append(filter, AllowSyscall(syscall.SYS_EXIT)...)
	filter = append(filter, AllowSyscall(syscall.SYS_MMAP)...)
	filter = append(filter, AllowSyscall(syscall.SYS_READ)...)
	filter = append(filter, AllowSyscall(syscall.SYS_WRITE)...)
	filter = append(filter, AllowSyscall(syscall.SYS_GETTIMEOFDAY)...)
	filter = append(filter, AllowSyscall(syscall.SYS_FUTEX)...)
	filter = append(filter, AllowSyscall(syscall.SYS_SIGALTSTACK)...)
	filter = append(filter, AllowSyscall(syscall.SYS_RT_SIGPROCMASK)...)

	filter = append(filter, KillProcess()...)

	prog := &SockFprog{
		Len:    uint16(len(filter)),
		Filter: (*SockFilter)(unsafe.Pointer(&(filter)[0])),
	}

	fmt.Printf("Applying syscall policy...\n")
	runtime.LockOSThread()

	if err := Prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		log.Fatalf("Prctl(PR_SET_NO_NEW_PRIVS): %v", err)
	}

	if err := Prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER,
		uint64(uintptr(unsafe.Pointer(prog))), 1<<64-1, 0); err != nil {
		log.Fatalf("prctl(SECCOMP): %v", err)
	}

	fmt.Printf("And now, let's make a 'bad' syscall\n")
	fmt.Printf("Note: due to lack of seccomp support from the Go runtime," +
		"the example will stuck instead of crashing. Use Ctrl+C to exit.\n")
	_, _ = os.Open("nonexistent_file")

	// Actually, the line below will never be printed.
	// The quirk is that instead of crashing the whole process,
	// the system kills just the thread that has violated the policy.
	// Currently, it means that the Go runtime thread gets stuck and
	// you will have to Ctrl+C to exit from this example.
	fmt.Printf("How come, I'm alive?\n")
}
