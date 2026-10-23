package authproxy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

var errUnsupportedStorage = errors.New("otgo authentication storage is unsupported on this platform; account-only protection is required")

func privateDir(path string) error {
	if !protectedStorageSupported {
		return errUnsupportedStorage
	}
	// #nosec G703 -- Operator-selected storage path; directory ownership and type checked below.
	if err := os.MkdirAll(path, 0700); err != nil {
		return errors.New("cannot create protected storage directory")
	}
	// #nosec G703 -- Metadata check of an operator-selected storage path.
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("unsafe storage directory")
	}
	if info.Mode().Perm() != 0700 || !ownedByUser(info) {
		return errors.New("storage directory must be owned by this account with mode 0700")
	}
	return nil
}
func checkPrivateFile(path string) (os.FileInfo, error) {
	if !protectedStorageSupported {
		return nil, errUnsupportedStorage
	}
	// #nosec G703 -- Metadata check of an operator-selected storage path.
	info, e := os.Lstat(path)
	if e != nil {
		return nil, e
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0600 || !ownedByUser(info) {
		return nil, errors.New("unsafe credential file; require account ownership and mode 0600")
	}
	return info, nil
}
func readPrivate(path string) ([]byte, error) {
	return readPrivateWithOpen(path, openNoFollow)
}

func readPrivateWithOpen(path string, open func(string, int, os.FileMode) (*os.File, error)) ([]byte, error) {
	if !protectedStorageSupported {
		return nil, errUnsupportedStorage
	}
	// #nosec G703 -- Validate parent of an operator-selected credential file.
	info, e := os.Lstat(filepath.Dir(path))
	if e != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0700 || !ownedByUser(info) {
		return nil, errors.New("unsafe or missing credential directory")
	}
	f, e := open(path, os.O_RDONLY, 0600)
	if e != nil {
		return nil, errors.New("cannot open credential file")
	}
	defer func() { _ = f.Close() }()
	after, e := f.Stat()
	if e != nil || !after.Mode().IsRegular() || after.Mode().Perm() != 0600 || !ownedByUser(after) {
		return nil, errors.New("unsafe credential file; require account ownership and mode 0600")
	}
	if after.Size() > maxFileBytes {
		return nil, errors.New("credential file exceeds size limit")
	}
	b, e := io.ReadAll(io.LimitReader(f, maxFileBytes+1))
	if e != nil || len(b) > maxFileBytes {
		return nil, errors.New("cannot read bounded credential file")
	}
	return b, nil
}
func decodeStrict(b []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if e := d.Decode(v); e != nil {
		return e
	}
	var extra any
	if e := d.Decode(&extra); e != io.EOF {
		return errors.New("trailing JSON content")
	}
	return nil
}
func writePrivate(path string, b []byte) error {
	if len(b) > maxFileBytes {
		return errors.New("credential file exceeds size limit")
	}
	if e := privateDir(filepath.Dir(path)); e != nil {
		return e
	}
	if _, e := checkPrivateFile(path); e != nil && !os.IsNotExist(e) {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(path), ".otgo-*")
	if e != nil {
		return errors.New("cannot create credential temporary file")
	}
	tmp := f.Name()
	// #nosec G703 -- Remove only the temporary file returned by CreateTemp.
	defer func() { _ = f.Close(); _ = os.Remove(tmp) }()
	if _, e = f.Write(b); e != nil {
		return errors.New("cannot write credential file")
	}
	if e = f.Sync(); e != nil {
		return errors.New("cannot sync credential file")
	}
	if e = f.Close(); e != nil {
		return errors.New("cannot close credential file")
	}
	// #nosec G703 -- Both paths are in the validated private directory.
	if e = os.Rename(tmp, path); e != nil {
		return errors.New("cannot replace credential file")
	}
	return nil
}
func withFileLock(path string, fn func() error) error {
	if e := privateDir(filepath.Dir(path)); e != nil {
		return fmt.Errorf("cannot prepare storage lock for %q: %w", path, e)
	}
	lockPath := path + ".lock"
	if _, e := checkPrivateFile(lockPath); e != nil && !os.IsNotExist(e) {
		// Quote the path once, including when Lstat returned a PathError.
		var pathErr *os.PathError
		if errors.As(e, &pathErr) {
			e = pathErr.Err
		}
		return fmt.Errorf("cannot use storage lock %q: %w", lockPath, e)
	}
	f, e := openNoFollow(lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return fmt.Errorf("cannot open storage lock %q: %w", lockPath, e)
	}
	defer func() { _ = f.Close() }()
	const timeout = 2 * time.Second
	deadline := time.Now().Add(timeout)
	for {
		e = tryLock(f)
		if e == nil {
			break
		}
		if !lockBusy(e) {
			return fmt.Errorf("cannot acquire storage lock %q: %w", lockPath, e)
		}
		if !time.Now().Before(deadline) {
			return fmt.Errorf("cannot acquire storage lock %q after %s: %w; another otgo process might already be running; wait for it to finish or stop it before retrying (do not delete the lock file)", lockPath, timeout, e)
		}
		time.Sleep(10 * time.Millisecond)
	}
	return fn()
}

// WithProfileLock prevents simultaneous proxies or setup for one tunnel profile.
// The lock file is retained: unlinking an active OS lock would permit a second owner.
func WithProfileLock(path string, fn func() error) error  { return withFileLock(path, fn) }
func WithMutationLock(path string, fn func() error) error { return withFileLock(path+".mutation", fn) }

// Reset removes only the known credential files; lock files stay in place.
func Reset(paths Paths) error {
	return WithMutationLock(paths.AuthConfig, func() error {
		for _, path := range []string{paths.AuthConfig, paths.TokenFile, IdentityKeyPath(paths)} {
			if e := withFileLock(path, func() error {
				if _, e := checkPrivateFile(path); os.IsNotExist(e) {
					return nil
				} else if e != nil {
					return e
				}
				return os.Remove(path)
			}); e != nil {
				return e
			}
		}
		return nil
	})
}

// ResetTokens is used during explicit setup to invalidate credentials for a previous backend.
func ResetTokens(path string) error {
	return withFileLock(path, func() error {
		if _, e := checkPrivateFile(path); os.IsNotExist(e) {
			return nil
		} else if e != nil {
			return e
		}
		return os.Remove(path)
	})
}
