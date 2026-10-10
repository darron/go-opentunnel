package authproxy

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

func privateDir(path string) error {
	// #nosec G703 -- Operator-selected storage path; directory ownership and type checked below.
	if err := os.MkdirAll(path, 0700); err != nil {
		return errors.New("cannot create protected storage directory")
	}
	// #nosec G703 -- Metadata check of an operator-selected storage path.
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("unsafe storage directory")
	}
	if runtime.GOOS != "windows" && (info.Mode().Perm() != 0700 || !ownedByUser(info)) {
		return errors.New("storage directory must be owned by this account with mode 0700")
	}
	return nil
}
func checkPrivateFile(path string) (os.FileInfo, error) {
	// #nosec G703 -- Metadata check of an operator-selected storage path.
	info, e := os.Lstat(path)
	if e != nil {
		return nil, e
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || (runtime.GOOS != "windows" && (info.Mode().Perm() != 0600 || !ownedByUser(info))) {
		return nil, errors.New("unsafe credential file; require account ownership and mode 0600")
	}
	return info, nil
}
func readPrivate(path string) ([]byte, error) {
	info, e := os.Lstat(filepath.Dir(path))
	if e != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || (runtime.GOOS != "windows" && (info.Mode().Perm() != 0700 || !ownedByUser(info))) {
		return nil, errors.New("unsafe or missing credential directory")
	}
	before, e := checkPrivateFile(path)
	if e != nil {
		return nil, errors.New("credential file is missing or unsafe")
	}
	if before.Size() > maxFileBytes {
		return nil, errors.New("credential file exceeds size limit")
	}
	f, e := openNoFollow(path, os.O_RDONLY, 0600)
	if e != nil {
		return nil, errors.New("cannot open credential file")
	}
	defer func() { _ = f.Close() }()
	after, e := f.Stat()
	if e != nil || !os.SameFile(before, after) {
		return nil, errors.New("credential file changed while opening")
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
	if e = os.Rename(tmp, path); e != nil {
		return errors.New("cannot replace credential file")
	}
	return nil
}
func withFileLock(path string, fn func() error) error {
	if e := privateDir(filepath.Dir(path)); e != nil {
		return e
	}
	lockPath := path + ".lock"
	if _, e := checkPrivateFile(lockPath); e != nil && !os.IsNotExist(e) {
		return e
	}
	f, e := openNoFollow(lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return errors.New("cannot open storage lock")
	}
	defer func() { _ = f.Close() }()
	deadline := time.Now().Add(2 * time.Second)
	for {
		e = tryLock(f)
		if e == nil {
			break
		}
		if !lockBusy(e) || !time.Now().Before(deadline) {
			return errors.New("cannot acquire storage lock")
		}
		time.Sleep(10 * time.Millisecond)
	}
	return fn()
}
