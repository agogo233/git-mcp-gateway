// Package auth validates Bearer tokens against bcrypt hashes from users.yaml.
// Repeated failed attempts from the same client IP are rate limited so the
// bcrypt cost cannot be abused as a CPU denial-of-service vector.
package auth

import (
	"errors"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/local/git-mcp-gateway/internal/config"
	"golang.org/x/crypto/bcrypt"
)

// ErrUnauthorized is returned for missing/invalid credentials.
var ErrUnauthorized = errors.New("unauthorized")

// Failed-authentication rate limit: a fixed window per client IP. Once the
// limit is hit, every attempt (including valid ones) is rejected until the
// window expires; a successful authentication clears the counter.
const (
	authFailLimit  = 20
	authFailWindow = 10 * time.Minute
)

// Authenticator checks Bearer tokens for MCP users and the admin console.
type Authenticator struct {
	store *config.Store

	mu    sync.Mutex
	fails map[string]*failWindow
}

type failWindow struct {
	count int
	reset time.Time
}

// New builds an Authenticator bound to the config store (hot reload aware).
func New(store *config.Store) *Authenticator {
	return &Authenticator{store: store, fails: map[string]*failWindow{}}
}

// User authenticates an MCP caller and returns its configured identity.
func (a *Authenticator) User(r *http.Request) (string, config.User, error) {
	token := bearer(r)
	if token == "" {
		return "", config.User{}, ErrUnauthorized
	}
	ip := clientIP(r)
	if a.limited(ip) {
		return "", config.User{}, ErrUnauthorized
	}
	cfg := a.store.Get()
	for name, u := range cfg.Users {
		if u.Disabled {
			continue
		}
		if bcrypt.CompareHashAndPassword([]byte(u.TokenHash), []byte(token)) == nil {
			a.reset(ip)
			return name, u, nil
		}
	}
	a.fail(ip)
	return "", config.User{}, ErrUnauthorized
}

// Admin authenticates the management console token.
func (a *Authenticator) Admin(r *http.Request) error {
	token := bearer(r)
	if token == "" {
		return ErrUnauthorized
	}
	ip := clientIP(r)
	if a.limited(ip) {
		return ErrUnauthorized
	}
	hash := a.store.Get().AdminToken
	// bcrypt hashes cannot be constant-time compared directly; comparing the
	// derived key avoids trivially timing-parallel guessing.
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(token)) != nil {
		a.fail(ip)
		return ErrUnauthorized
	}
	a.reset(ip)
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

func (a *Authenticator) limited(ip string) bool {
	if ip == "" {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	f, ok := a.fails[ip]
	if !ok {
		return false
	}
	if time.Now().After(f.reset) {
		delete(a.fails, ip)
		return false
	}
	return f.count >= authFailLimit
}

func (a *Authenticator) fail(ip string) {
	if ip == "" {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	f, ok := a.fails[ip]
	if !ok || time.Now().After(f.reset) {
		if len(a.fails) > 4096 { // hard bound on tracker memory
			a.fails = map[string]*failWindow{}
		}
		a.fails[ip] = &failWindow{count: 1, reset: time.Now().Add(authFailWindow)}
		return
	}
	f.count++
}

func (a *Authenticator) reset(ip string) {
	if ip == "" {
		return
	}
	a.mu.Lock()
	delete(a.fails, ip)
	a.mu.Unlock()
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return strings.TrimSpace(r.RemoteAddr)
	}
	return host
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
