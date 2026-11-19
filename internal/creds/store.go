// Package creds stores deploy-key private keys encrypted at rest and hands
// them to in-memory SSH agents at session time.
//
// Private keys are never written to disk in plaintext: the on-disk artifact is
// a NaCl secretbox (XSalsa20-Poly1305) blob sealed with a 32-byte master key
// provided through the GIT_MCP_MASTER_KEY environment variable. The plaintext
// exists only inside the gateway process for the shortest possible time.
package creds

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"

	"golang.org/x/crypto/nacl/secretbox"
)

const magic = "gitmcp1" // blob header, guards against decrypting foreign files

// MasterKey reads and validates GIT_MCP_MASTER_KEY (base64, 32 bytes).
func MasterKey() ([]byte, error) {
	raw := strings.TrimSpace(os.Getenv("GIT_MCP_MASTER_KEY"))
	if raw == "" {
		return nil, errors.New("GIT_MCP_MASTER_KEY is not set")
	}
	key, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("GIT_MCP_MASTER_KEY is not valid base64: %w", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("GIT_MCP_MASTER_KEY must decode to 32 bytes, got %d", len(key))
	}
	return key, nil
}

// Encrypt seals plaintext with the master key. Output: "gitmcp1." + base64(nonce||box).
func Encrypt(key, plaintext []byte) (string, error) {
	if len(key) != 32 {
		return "", errors.New("master key must be 32 bytes")
	}
	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", err
	}
	var k [32]byte
	copy(k[:], key)
	box := secretbox.Seal(nil, plaintext, &nonce, &k)
	out := magic + "." + base64.StdEncoding.EncodeToString(append(nonce[:], box...))
	return out, nil
}

// Decrypt opens a blob produced by Encrypt.
func Decrypt(key []byte, blob string) ([]byte, error) {
	blob = strings.TrimSpace(blob)
	if !strings.HasPrefix(blob, magic+".") {
		return nil, errors.New("not a git-mcp key blob")
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(blob, magic+"."))
	if err != nil || len(raw) < 24 {
		return nil, errors.New("corrupt key blob")
	}
	var nonce [24]byte
	copy(nonce[:], raw[:24])
	boxed := raw[24:]
	var k [32]byte
	copy(k[:], key)
	plain, ok := secretbox.Open(nil, boxed, &nonce, &k)
	if !ok {
		return nil, errors.New("decrypt failed (wrong master key?)")
	}
	return plain, nil
}

// LoadPlaintext reads an encrypted key file and returns the private key bytes.
func LoadPlaintext(key []byte, path string) ([]byte, error) {
	blob, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read key file: %w", err)
	}
	plain, err := Decrypt(key, string(blob))
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	return plain, nil
}

// Zero wipes a plaintext buffer after use.
func Zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

var (
	mkOnce sync.Once
	mkKey  []byte
	mkErr  error
)

// GlobalMasterKey caches the process-wide master key (read once from env).
func GlobalMasterKey() ([]byte, error) {
	mkOnce.Do(func() { mkKey, mkErr = MasterKey() })
	return mkKey, mkErr
}
