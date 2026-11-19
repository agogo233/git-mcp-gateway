// Package auth validates Bearer tokens against bcrypt hashes from users.yaml.
package auth

import (
	"crypto/subtle"
	"errors"
	"net/http"
	"strings"

	"github.com/local/git-mcp-gateway/internal/config"
	"golang.org/x/crypto/bcrypt"
)

// ErrUnauthorized is returned for missing/invalid credentials.
var ErrUnauthorized = errors.New("unauthorized")

// Authenticator checks Bearer tokens for MCP users and the admin console.
type Authenticator struct {
	store *config.Store
}

// New builds an Authenticator bound to the config store (hot reload aware).
func New(store *config.Store) *Authenticator {
	return &Authenticator{store: store}
}

// User authenticates an MCP caller and returns its configured identity.
func (a *Authenticator) User(r *http.Request) (string, config.User, error) {
	token := bearer(r)
	if token == "" {
		return "", config.User{}, ErrUnauthorized
	}
	cfg := a.store.Get()
	for name, u := range cfg.Users {
		if u.Disabled {
			continue
		}
		if bcrypt.CompareHashAndPassword([]byte(u.TokenHash), []byte(token)) == nil {
			return name, u, nil
		}
	}
	return "", config.User{}, ErrUnauthorized
}

// Admin authenticates the management console token.
func (a *Authenticator) Admin(r *http.Request) error {
	token := bearer(r)
	if token == "" {
		return ErrUnauthorized
	}
	hash := a.store.Get().AdminToken
	// bcrypt hashes cannot be constant-time compared directly; compare the
	// derived key instead to avoid trivially timing-parallel guessing.
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(token)) != nil {
		return ErrUnauthorized
	}
	return nil
}

// HashToken produces a bcrypt hash for a plaintext token (admin console / CLI).
func HashToken(token string) (string, error) {
	h, err := bcrypt.GenerateFromPassword([]byte(token), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(h), nil
}

// EqualHashes is a helper for tests and tooling.
func EqualHashes(hash, token string) bool {
	return subtle.ConstantTimeCompare([]byte(hash), []byte(hash)) == 1 &&
		bcrypt.CompareHashAndPassword([]byte(hash), []byte(token)) == nil
}

func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if h == "" {
		return ""
	}
	const prefix = "Bearer "
	if len(h) <= len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return ""
	}
	return strings.TrimSpace(h[len(prefix):])
}
