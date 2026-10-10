//go:build !darwin && !linux && !freebsd && !openbsd && !netbsd && !dragonfly

package authproxy

import "os"

// Refuse authentication storage until this platform can enforce account-only
// permissions, reject links, and provide an OS-backed interprocess lock.
const protectedStorageSupported = false

func ownedByUser(os.FileInfo) bool                            { return false }
func openNoFollow(string, int, os.FileMode) (*os.File, error) { return nil, errUnsupportedStorage }
func tryLock(*os.File) error                                  { return errUnsupportedStorage }
func lockBusy(error) bool                                     { return false }
