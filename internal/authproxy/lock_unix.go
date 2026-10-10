//go:build unix

package authproxy

import (
	"errors"
	"os"
	"syscall"
)

func ownedByUser(info os.FileInfo) bool {
	s, ok := info.Sys().(*syscall.Stat_t)
	return ok && s.Uid == uint32(os.Geteuid())
}
func openNoFollow(path string, flags int, mode os.FileMode) (*os.File, error) {
	fd, e := syscall.Open(path, flags|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, uint32(mode))
	if e != nil {
		return nil, e
	}
	return os.NewFile(uintptr(fd), path), nil
}
func tryLock(f *os.File) error { return syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) }
func lockBusy(e error) bool    { return errors.Is(e, syscall.EWOULDBLOCK) || errors.Is(e, syscall.EAGAIN) }
