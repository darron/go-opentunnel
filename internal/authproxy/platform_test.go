package authproxy

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestUnsupportedStorageFailsBeforeCreatingFiles(t *testing.T) {
	if protectedStorageSupported {
		t.Skip("protected storage is supported on this platform")
	}
	path := filepath.Join(t.TempDir(), "credentials", "auth.json")
	if err := SaveConfig(path, fixtureConfig()); !errors.Is(err, errUnsupportedStorage) {
		t.Fatalf("storage was not refused: %v", err)
	}
	if _, err := os.Stat(filepath.Dir(path)); !os.IsNotExist(err) {
		t.Fatal("unsupported setup created credential files")
	}
	if _, err := readPrivate(path); !errors.Is(err, errUnsupportedStorage) {
		t.Fatalf("read was not refused: %v", err)
	}
}
