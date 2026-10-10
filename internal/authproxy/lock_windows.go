//go:build windows

package authproxy

import (
	"errors"
	"os"
	"syscall"
	"unsafe"
)

var lockFileEx = syscall.NewLazyDLL("kernel32.dll").NewProc("LockFileEx")

func ownedByUser(_ os.FileInfo) bool { return true }
func openNoFollow(path string, flags int, mode os.FileMode) (*os.File, error) {
	return os.OpenFile(path, flags, mode)
}
func tryLock(f *os.File) error {
	var overlapped syscall.Overlapped
	r, _, e := lockFileEx.Call(f.Fd(), 3, 0, 1, 0, uintptr(unsafe.Pointer(&overlapped)))
	if r == 0 {
		return e
	}
	return nil
}
func lockBusy(e error) bool { return errors.Is(e, syscall.Errno(33)) }
