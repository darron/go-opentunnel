//go:build darwin || linux || freebsd || openbsd || netbsd || dragonfly

package authproxy

import (
	"bytes"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestPrivateReadFollowsOneCoherentAtomicReplacement(t *testing.T) {
	path := filepath.Join(secureTempDir(t), "tokens.json")
	if err := writePrivate(path, []byte("previous registry")); err != nil {
		t.Fatal(err)
	}
	want := []byte("replacement registry")
	got, err := readPrivateWithOpen(path, func(path string, flags int, mode os.FileMode) (*os.File, error) {
		if err := writePrivate(path, want); err != nil {
			return nil, err
		}
		return openNoFollow(path, flags, mode)
	})
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("atomic replacement disrupted read: %v", err)
	}
}

func TestPrivateReadRejectsFIFOWithoutWaitingForWriter(t *testing.T) {
	path := filepath.Join(secureTempDir(t), "fifo")
	if err := syscall.Mkfifo(path, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readPrivate(path); err == nil {
		t.Fatal("credential FIFO accepted")
	}
}
