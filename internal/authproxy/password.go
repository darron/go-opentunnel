package authproxy

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
)

const passwordIterations = 600000

func randomSecret() string              { return base64.RawURLEncoding.EncodeToString(randomBytes(32)) }
func randomBytes(n int) []byte          { b := make([]byte, n); _, _ = rand.Read(b); return b }
func GeneratePassword() (string, error) { return randomSecret(), nil }
func NewPasswordVerifier(password []byte) (PasswordVerifier, error) {
	if len(password) == 0 || len(password) > 1024 {
		return PasswordVerifier{}, errors.New("password must contain 1 to 1024 bytes")
	}
	salt := randomBytes(32)
	key, err := pbkdf2.Key(sha256.New, string(password), salt, passwordIterations, 32)
	if err != nil {
		return PasswordVerifier{}, errors.New("cannot derive password verifier")
	}
	return PasswordVerifier{Version: 1, Salt: base64.RawURLEncoding.EncodeToString(salt), Iterations: passwordIterations, Digest: base64.RawURLEncoding.EncodeToString(key)}, nil
}
func validVerifier(v PasswordVerifier) bool {
	salt, e := base64.RawURLEncoding.DecodeString(v.Salt)
	digest, f := base64.RawURLEncoding.DecodeString(v.Digest)
	return v.Version == 1 && v.Iterations >= passwordIterations && v.Iterations <= 2000000 && e == nil && f == nil && len(salt) == 32 && len(digest) == 32
}
func VerifyPassword(v PasswordVerifier, password []byte) bool {
	if !validVerifier(v) || len(password) == 0 || len(password) > 1024 {
		return false
	}
	salt, _ := base64.RawURLEncoding.DecodeString(v.Salt)
	want, _ := base64.RawURLEncoding.DecodeString(v.Digest)
	got, e := pbkdf2.Key(sha256.New, string(password), salt, v.Iterations, 32)
	return e == nil && subtle.ConstantTimeCompare(got, want) == 1
}
