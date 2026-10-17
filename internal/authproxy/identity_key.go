package authproxy

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
)

// IdentityKeyPath keeps each signing key beside its profile's protected config.
func IdentityKeyPath(paths Paths) string { return paths.AuthConfig + ".identity.json" }

type identityKeyFile struct {
	Version  int     `json:"version"`
	Binding  Binding `json:"binding"`
	Upstream string  `json:"upstream"`
	Seed     []byte  `json:"seed"`
}

// EnsureIdentityKey creates the profile key once, then requires the same key on
// every start. A config fingerprint detects key loss or substitution. Callers
// must not already hold the auth config mutation lock.
func EnsureIdentityKey(paths Paths, expected Config) (ed25519.PrivateKey, error) {
	return loadIdentityKey(paths, expected, true)
}

// LoadIdentityPublicKey reads the existing pinned profile key without creating,
// replacing or pinning one. It uses the same storage and binding checks as startup.
func LoadIdentityPublicKey(paths Paths, expected Config) (ed25519.PublicKey, error) {
	key, err := loadIdentityKey(paths, expected, false)
	if err != nil {
		return nil, err
	}
	return append(ed25519.PublicKey(nil), key[ed25519.SeedSize:]...), nil
}

func loadIdentityKey(paths Paths, expected Config, create bool) (ed25519.PrivateKey, error) {
	var key ed25519.PrivateKey
	err := WithMutationLock(paths.AuthConfig, func() error {
		current, err := LoadConfig(paths.AuthConfig)
		if err != nil {
			return err
		}
		if err := ValidateBinding(current, expected.Binding); err != nil {
			return err
		}
		if current.Upstream != expected.Upstream {
			return errors.New("auth backend changed during identity key operation")
		}
		if !create && (current.IdentityKeyID == "" || current.IdentityKeyID != expected.IdentityKeyID) {
			return errors.New("identity key is not pinned or changed; start the GitHub proxy or export its public key first")
		}
		path := IdentityKeyPath(paths)
		_, err = checkPrivateFile(path)
		var stored identityKeyFile
		switch {
		case os.IsNotExist(err):
			if current.IdentityKeyID != "" {
				return errors.New("pinned identity signing key is missing; restore it or explicitly reset auth and re-pin the public key")
			}
			_, generated, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				return errors.New("cannot generate identity signing key")
			}
			stored = identityKeyFile{Version: 1, Binding: current.Binding, Upstream: current.Upstream, Seed: generated.Seed()}
			b, err := json.Marshal(stored)
			if err != nil {
				return errors.New("cannot encode identity signing key")
			}
			if err := writePrivate(path, b); err != nil {
				return err
			}
		case err != nil:
			return err
		default:
			b, err := readPrivate(path)
			if err != nil {
				return err
			}
			if err := decodeStrict(b, &stored); err != nil {
				return errors.New("invalid identity signing key file")
			}
		}
		if stored.Version != 1 || stored.Binding != current.Binding || stored.Upstream != current.Upstream || len(stored.Seed) != ed25519.SeedSize {
			return errors.New("identity signing key does not match this profile")
		}
		key = ed25519.NewKeyFromSeed(stored.Seed)
		fingerprint := IdentityKeyID(key)
		if current.IdentityKeyID != "" && current.IdentityKeyID != fingerprint {
			return errors.New("identity signing key fingerprint mismatch")
		}
		if current.IdentityKeyID == "" {
			current.IdentityKeyID = fingerprint
			return SaveConfig(paths.AuthConfig, current)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return key, nil
}

func IdentityKeyID(key ed25519.PrivateKey) string {
	sum := sha256.Sum256(key[ed25519.SeedSize:])
	return hex.EncodeToString(sum[:])
}
func IdentityPublicKeyPEM(key ed25519.PrivateKey) ([]byte, error) {
	if len(key) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid identity signing key")
	}
	b, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		return nil, errors.New("cannot encode identity public key")
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: b}), nil
}

// ResetIdentityKey requires the caller to hold the config mutation lock.
func ResetIdentityKey(paths Paths) error {
	path := IdentityKeyPath(paths)
	if _, err := checkPrivateFile(path); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return err
	}
	// #nosec G703 -- Only the known key file in protected profile storage is removed.
	return os.Remove(path)
}
