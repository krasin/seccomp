package seccomp

import (
	"syscall"
)

func Prctl(option int, arg2, arg3, arg4, arg5 uint64) (err error) {
	//	func Fchownat(dirfd int, path string, uid int, gid int, flags int) (err error) {
	_, _, e1 := syscall.Syscall6(syscall.SYS_PRCTL, uintptr(option), uintptr(arg2), uintptr(arg3), uintptr(arg4), uintptr(arg5), 0)
	if e1 != 0 {
		err = e1
	}
	return
}
