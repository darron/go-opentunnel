package opentunnel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

// NewMemoryStorage returns a concurrent store that lasts for this process only.
func NewMemoryStorage() Storage {
	return &memoryStorage{identities: make(map[string]Identity), pending: make(map[string]PendingIdentity)}
}

type memoryStorage struct {
	mu         sync.RWMutex
	identities map[string]Identity
	pending    map[string]PendingIdentity
}

func (s *memoryStorage) Profiles(ctx context.Context) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	seen := make(map[string]struct{}, len(s.identities)+len(s.pending))
	for p := range s.identities {
		seen[p] = struct{}{}
	}
	for p := range s.pending {
		seen[p] = struct{}{}
	}
	profiles := make([]string, 0, len(seen))
	for p := range seen {
		profiles = append(profiles, p)
	}
	sort.Strings(profiles)
	return profiles, nil
}

//nolint:nilnil // Missing identities intentionally return nil,nil per Storage contract.
func (s *memoryStorage) Load(ctx context.Context, profile string) (*Identity, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !validProfile(profile) {
		return nil, invalidProfile(profile)
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.identities[profile]
	if !ok {
		return nil, nil
	}
	v.CertificateExpiry = v.CertificateExpiry.UTC()
	return &v, nil
}

func (s *memoryStorage) Save(ctx context.Context, profile string, identity Identity) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !validProfile(profile) {
		return invalidProfile(profile)
	}
	identity.CertificateExpiry = identity.CertificateExpiry.UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.identities[profile] = identity
	delete(s.pending, profile)
	return nil
}

//nolint:nilnil // Missing identities intentionally return nil,nil per Storage contract.
func (s *memoryStorage) LoadPending(ctx context.Context, profile string) (*PendingIdentity, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !validProfile(profile) {
		return nil, invalidProfile(profile)
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.pending[profile]
	if !ok {
		return nil, nil
	}
	return &v, nil
}

func (s *memoryStorage) SavePending(ctx context.Context, profile string, pending PendingIdentity) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !validProfile(profile) {
		return invalidProfile(profile)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if completed, ok := s.identities[profile]; ok && !matchesPending(completed, pending) {
		return ErrExists
	}
	s.pending[profile] = pending
	return nil
}

func (s *memoryStorage) Remove(ctx context.Context, profile string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !validProfile(profile) {
		return invalidProfile(profile)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.identities, profile)
	delete(s.pending, profile)
	return nil
}

func (s *memoryStorage) List(ctx context.Context) ([]StoredTunnel, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	profiles := make([]string, 0, len(s.identities))
	for p := range s.identities {
		profiles = append(profiles, p)
	}
	sort.Strings(profiles)
	result := make([]StoredTunnel, 0, len(profiles))
	for _, p := range profiles {
		v := s.identities[p]
		v.CertificateExpiry = v.CertificateExpiry.UTC()
		result = append(result, StoredTunnel{Profile: p, Tunnel: v})
	}
	return result, nil
}

// NewFileStorage stores profiles directly below root.
func NewFileStorage(root string) Storage { return &fileStorage{root: root} }

// NewXDGStorage uses $XDG_DATA_HOME/opentunnel, falling back to
// ~/.local/share/opentunnel for upstream compatibility.
func NewXDGStorage() (Storage, error) {
	dataHome := os.Getenv("XDG_DATA_HOME")
	if dataHome == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("opentunnel: find home directory: %w", err)
		}
		dataHome = filepath.Join(home, ".local", "share")
	}
	return NewFileStorage(filepath.Join(dataHome, "opentunnel")), nil
}

type fileStorage struct {
	root string
	mu   sync.Mutex
}

type tunnelMetadata struct {
	ID                string    `json:"id"`
	Hostname          string    `json:"hostname"`
	CertificateExpiry time.Time `json:"certificateExpiry"`
}
type pendingMetadata struct {
	ID       string `json:"id"`
	Hostname string `json:"hostname"`
	CSR      string `json:"csr"`
}

func (s *fileStorage) Profiles(ctx context.Context) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	entries, err := os.ReadDir(s.root)
	if errors.Is(err, fs.ErrNotExist) {
		return []string{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("opentunnel: list profiles: %w", err)
	}
	profiles := make([]string, 0, len(entries))
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if !validProfile(entry.Name()) {
			continue
		}
		info, err := os.Lstat(filepath.Join(s.root, entry.Name()))
		if err != nil {
			return nil, fmt.Errorf("opentunnel: inspect profile %q: %w", entry.Name(), err)
		}
		if info.Mode()&os.ModeSymlink == 0 && info.IsDir() {
			profiles = append(profiles, entry.Name())
		}
	}
	sort.Strings(profiles)
	return profiles, nil
}

func (s *fileStorage) Load(ctx context.Context, profile string) (*Identity, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !validProfile(profile) {
		return nil, invalidProfile(profile)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	dir, exists, err := s.profileDir(profile)
	if err != nil || !exists {
		return nil, err
	}
	metadataBytes, exists, err := readRegular(filepath.Join(dir, "tunnel.json"))
	if err != nil || !exists {
		return nil, err
	}
	var metadata tunnelMetadata
	if err := json.Unmarshal(metadataBytes, &metadata); err != nil {
		return nil, fmt.Errorf("opentunnel: corrupt tunnel identity for %q: %w", profile, err)
	}
	if metadata.ID == "" || metadata.Hostname == "" || metadata.CertificateExpiry.IsZero() {
		return nil, fmt.Errorf("opentunnel: corrupt tunnel identity for %q", profile)
	}
	token, tokenOK, err := readRegular(filepath.Join(dir, "token"))
	if err != nil {
		return nil, err
	}
	key, keyOK, err := readRegular(filepath.Join(dir, "private-key.pem"))
	if err != nil {
		return nil, err
	}
	cert, certOK, err := readRegular(filepath.Join(dir, "certificate.pem"))
	if err != nil {
		return nil, err
	}
	chain, chainOK, err := readRegular(filepath.Join(dir, "chain.pem"))
	if err != nil {
		return nil, err
	}
	if !tokenOK || !keyOK || !certOK || !chainOK || strings.TrimSpace(string(token)) == "" || strings.TrimSpace(string(key)) == "" || strings.TrimSpace(string(cert)) == "" || strings.TrimSpace(string(chain)) == "" {
		return nil, incomplete(profile)
	}
	return &Identity{ID: metadata.ID, Hostname: metadata.Hostname, Token: strings.TrimSpace(string(token)), PrivateKey: string(key), Certificate: string(cert), Chain: string(chain), CertificateExpiry: metadata.CertificateExpiry.UTC()}, nil
}

func (s *fileStorage) Save(ctx context.Context, profile string, identity Identity) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !validProfile(profile) {
		return invalidProfile(profile)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	dir, err := s.ensureProfileDir(profile)
	if err != nil {
		return err
	}
	if err := s.write(ctx, dir, "token", []byte(identity.Token+"\n")); err != nil {
		return err
	}
	if err := s.write(ctx, dir, "private-key.pem", []byte(identity.PrivateKey)); err != nil {
		return err
	}
	if err := s.write(ctx, dir, "certificate.pem", []byte(identity.Certificate)); err != nil {
		return err
	}
	if err := s.write(ctx, dir, "chain.pem", []byte(identity.Chain)); err != nil {
		return err
	}
	metadata, err := json.MarshalIndent(tunnelMetadata{ID: identity.ID, Hostname: identity.Hostname, CertificateExpiry: identity.CertificateExpiry.UTC()}, "", "  ")
	if err != nil {
		return fmt.Errorf("opentunnel: encode tunnel identity: %w", err)
	}
	if err := s.write(ctx, dir, "tunnel.json", append(metadata, '\n')); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	// Remove pending metadata only after writing the completed identity marker.
	if err := removeRegular(filepath.Join(dir, "pending.json")); err != nil {
		return err
	}
	return nil
}

func (s *fileStorage) LoadPending(ctx context.Context, profile string) (*PendingIdentity, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !validProfile(profile) {
		return nil, invalidProfile(profile)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	dir, exists, err := s.profileDir(profile)
	if err != nil || !exists {
		return nil, err
	}
	metadataBytes, exists, err := readRegular(filepath.Join(dir, "pending.json"))
	if err != nil || !exists {
		return nil, err
	}
	var metadata pendingMetadata
	if err := json.Unmarshal(metadataBytes, &metadata); err != nil {
		return nil, fmt.Errorf("opentunnel: corrupt pending identity for %q: %w", profile, err)
	}
	if metadata.ID == "" || metadata.Hostname == "" || metadata.CSR == "" {
		return nil, fmt.Errorf("opentunnel: corrupt pending identity for %q", profile)
	}
	token, tokenOK, err := readRegular(filepath.Join(dir, "token"))
	if err != nil {
		return nil, err
	}
	key, keyOK, err := readRegular(filepath.Join(dir, "private-key.pem"))
	if err != nil {
		return nil, err
	}
	if !tokenOK || !keyOK || strings.TrimSpace(string(token)) == "" || strings.TrimSpace(string(key)) == "" {
		return nil, fmt.Errorf("opentunnel: incomplete pending tunnel identity for %q", profile)
	}
	return &PendingIdentity{ID: metadata.ID, Hostname: metadata.Hostname, Token: strings.TrimSpace(string(token)), PrivateKey: string(key), CSR: metadata.CSR}, nil
}

func (s *fileStorage) SavePending(ctx context.Context, profile string, pending PendingIdentity) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !validProfile(profile) {
		return invalidProfile(profile)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	dir, err := s.ensureProfileDir(profile)
	if err != nil {
		return err
	}
	completedMetadata, completed, err := readRegular(filepath.Join(dir, "tunnel.json"))
	if err != nil {
		return err
	}
	if completed {
		var metadata tunnelMetadata
		if err := json.Unmarshal(completedMetadata, &metadata); err != nil {
			return fmt.Errorf("opentunnel: corrupt tunnel identity for %q: %w", profile, err)
		}
		token, tokenOK, err := readRegular(filepath.Join(dir, "token"))
		if err != nil {
			return err
		}
		key, keyOK, err := readRegular(filepath.Join(dir, "private-key.pem"))
		if err != nil {
			return err
		}
		if metadata.ID == "" || metadata.Hostname == "" || metadata.CertificateExpiry.IsZero() || !tokenOK || !keyOK || strings.TrimSpace(string(token)) == "" || strings.TrimSpace(string(key)) == "" {
			return incomplete(profile)
		}
		if !matchesPending(Identity{ID: metadata.ID, Hostname: metadata.Hostname, Token: strings.TrimSpace(string(token)), PrivateKey: string(key)}, pending) {
			return ErrExists
		}
	}
	// Keep completed credentials when saving recovery metadata.
	if completed {
		metadata, err := json.MarshalIndent(pendingMetadata{ID: pending.ID, Hostname: pending.Hostname, CSR: pending.CSR}, "", "  ")
		if err != nil {
			return fmt.Errorf("opentunnel: encode pending identity: %w", err)
		}
		return s.write(ctx, dir, "pending.json", append(metadata, '\n'))
	}
	if err := s.write(ctx, dir, "token", []byte(pending.Token+"\n")); err != nil {
		return err
	}
	if err := s.write(ctx, dir, "private-key.pem", []byte(pending.PrivateKey)); err != nil {
		return err
	}
	metadata, err := json.MarshalIndent(pendingMetadata{ID: pending.ID, Hostname: pending.Hostname, CSR: pending.CSR}, "", "  ")
	if err != nil {
		return fmt.Errorf("opentunnel: encode pending identity: %w", err)
	}
	return s.write(ctx, dir, "pending.json", append(metadata, '\n'))
}

func (s *fileStorage) Remove(ctx context.Context, profile string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !validProfile(profile) {
		return invalidProfile(profile)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	dir, exists, err := s.profileDir(profile)
	if err != nil || !exists {
		return err
	}
	markerExists := false
	for _, name := range []string{"tunnel.json", "pending.json"} {
		exists, err := regularFileExists(filepath.Join(dir, name))
		if err != nil {
			return err
		}
		markerExists = markerExists || exists
	}
	if !markerExists {
		return nil
	}
	ownedFiles := []string{"token", "private-key.pem", "certificate.pem", "chain.pem", "tunnel.json", "pending.json"}
	for _, name := range ownedFiles {
		if _, err := regularFileExists(filepath.Join(dir, name)); err != nil {
			return err
		}
	}
	for _, name := range ownedFiles {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := removeRegular(filepath.Join(dir, name)); err != nil {
			return err
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("opentunnel: inspect profile %q after removal: %w", profile, err)
	}
	if len(entries) != 0 {
		return nil
	}
	if err := os.Remove(dir); err != nil {
		return fmt.Errorf("opentunnel: remove profile %q: %w", profile, err)
	}
	return nil
}

func (s *fileStorage) List(ctx context.Context) ([]StoredTunnel, error) {
	profiles, err := s.Profiles(ctx)
	if err != nil {
		return nil, err
	}
	result := make([]StoredTunnel, 0, len(profiles))
	for _, profile := range profiles {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		identity, err := s.Load(ctx, profile)
		if err != nil {
			return nil, err
		}
		if identity != nil {
			result = append(result, StoredTunnel{Profile: profile, Tunnel: *identity})
		}
	}
	return result, nil
}

func (s *fileStorage) profileDir(profile string) (string, bool, error) {
	dir := filepath.Join(s.root, profile)
	info, err := os.Lstat(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return dir, false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("opentunnel: inspect profile %q: %w", profile, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return "", false, fmt.Errorf("opentunnel: unsafe profile directory %q", profile)
	}
	return dir, true, nil
}

func (s *fileStorage) ensureProfileDir(profile string) (string, error) {
	rootCreated := false
	if info, err := os.Lstat(s.root); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return "", fmt.Errorf("opentunnel: unsafe storage root")
		}
		if runtime.GOOS != "windows" && info.Mode().Perm()&0o022 != 0 {
			return "", fmt.Errorf("opentunnel: storage root permissions %04o are writable by group or others", info.Mode().Perm())
		}
	} else if errors.Is(err, fs.ErrNotExist) {
		rootCreated = true
	} else {
		return "", fmt.Errorf("opentunnel: inspect storage root: %w", err)
	}
	if err := os.MkdirAll(s.root, 0o700); err != nil {
		return "", fmt.Errorf("opentunnel: create storage root: %w", err)
	}
	if info, err := os.Lstat(s.root); err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		if err != nil {
			return "", fmt.Errorf("opentunnel: inspect storage root: %w", err)
		}
		return "", fmt.Errorf("opentunnel: unsafe storage root")
	}
	if rootCreated {
		// #nosec G302 -- Directory requires owner execute; no access for group/others.
		if err := os.Chmod(s.root, 0o700); err != nil {
			return "", fmt.Errorf("opentunnel: secure storage root: %w", err)
		}
	}
	dir, exists, err := s.profileDir(profile)
	if err != nil {
		return "", err
	}
	if !exists {
		if err := os.Mkdir(dir, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
			return "", fmt.Errorf("opentunnel: create profile %q: %w", profile, err)
		}
		if _, exists, err = s.profileDir(profile); err != nil || !exists {
			if err != nil {
				return "", err
			}
			return "", fmt.Errorf("opentunnel: create profile %q", profile)
		}
	}
	// #nosec G302 -- Directory requires owner execute; no access for group/others.
	if err := os.Chmod(dir, 0o700); err != nil {
		return "", fmt.Errorf("opentunnel: secure profile %q: %w", profile, err)
	}
	return dir, nil
}

func regularFileExists(path string) (bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("opentunnel: inspect %s: %w", filepath.Base(path), err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return false, fmt.Errorf("opentunnel: unsafe file %s", filepath.Base(path))
	}
	return true, nil
}

func (s *fileStorage) write(ctx context.Context, dir, name string, content []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	path := filepath.Join(dir, name)
	if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("opentunnel: refusing symlinked file %q", name)
	} else if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("opentunnel: inspect %q: %w", name, err)
	}
	temporary, err := os.CreateTemp(dir, "."+name+".tmp-")
	if err != nil {
		return fmt.Errorf("opentunnel: create temporary %q: %w", name, err)
	}
	tmp := temporary.Name()
	defer func() { _ = os.Remove(tmp) }() //nolint:errcheck // Best-effort temporary cleanup.
	if err := temporary.Chmod(0o600); err != nil {
		if closeErr := temporary.Close(); closeErr != nil {
			return fmt.Errorf("opentunnel: secure temporary %q: %w", name, errors.Join(err, closeErr))
		}
		return fmt.Errorf("opentunnel: secure temporary %q: %w", name, err)
	}
	if _, err := temporary.Write(content); err != nil {
		if closeErr := temporary.Close(); closeErr != nil {
			return fmt.Errorf("opentunnel: write %q: %w", name, errors.Join(err, closeErr))
		}
		return fmt.Errorf("opentunnel: write %q: %w", name, err)
	}
	if err := temporary.Sync(); err != nil {
		if closeErr := temporary.Close(); closeErr != nil {
			return fmt.Errorf("opentunnel: sync %q: %w", name, errors.Join(err, closeErr))
		}
		return fmt.Errorf("opentunnel: sync %q: %w", name, err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("opentunnel: close %q: %w", name, err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("opentunnel: replace %q: %w", name, err)
	}
	return nil
}

func readRegular(path string) ([]byte, bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("opentunnel: inspect %s: %w", filepath.Base(path), err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, false, fmt.Errorf("opentunnel: unsafe file %s", filepath.Base(path))
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, false, fmt.Errorf("opentunnel: read %s: %w", filepath.Base(path), err)
	}
	return content, true, nil
}

func removeRegular(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("opentunnel: inspect %s: %w", filepath.Base(path), err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("opentunnel: unsafe file %s", filepath.Base(path))
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("opentunnel: remove %s: %w", filepath.Base(path), err)
	}
	return nil
}

func invalidProfile(profile string) error {
	return fmt.Errorf("%w: invalid profile %q", ErrInvalid, profile)
}
func incomplete(profile string) error {
	return fmt.Errorf("opentunnel: incomplete tunnel identity for %q", profile)
}

func matchesPending(identity Identity, pending PendingIdentity) bool {
	return identity.ID == pending.ID && identity.Hostname == pending.Hostname && identity.Token == pending.Token && identity.PrivateKey == pending.PrivateKey
}
