// Package auth validates Bearer tokens against bcrypt hashes from users.yaml.
// Repeated failed attempts are rate limited per presented token, with a
// higher per-IP backstop, so the bcrypt cost cannot be abused as a CPU
// denial-of-service vector — while a shared egress IP cannot be locked out by
// one misbehaving caller. Successful authentications are cached briefly.
package auth

import (
	"crypto/sha256"
	"encoding/hex"
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

// Failed-authentication rate limits: failures are counted per presented token
// (authFailLimit) and, as a backstop against token-rotation flooding, per
// client IP (authIPFailLimit). A successful authentication clears both.
const (
	authFailLimit   = 20
	authIPFailLimit = 200
	authFailWindow  = 10 * time.Minute
	authCacheTTL    = 5 * time.Minute
)

// Authenticator checks Bearer tokens for MCP users and the admin console.
type Authenticator struct {
	store *config.Store

	mu    sync.Mutex
	fails map[string]*failWindow
	cache map[string]cacheEntry
}

type failWindow struct {
	count int
	reset time.Time
}

// cacheEntry remembers a verified token until the configuration generation
// changes (e.g. a rotation) or the entry expires.
type cacheEntry struct {
	cfg  *config.Config
	name string
	user config.User
	exp  time.Time
}

// New builds an Authenticator bound to the config store (hot reload aware).
func New(store *config.Store) *Authenticator {
	return &Authenticator{
		store: store,
		fails: map[string]*failWindow{},
		cache: map[string]cacheEntry{},
	}
}

// tokenKey maps a presented token to a stable hash for the failure window
// and the cache; the plaintext token is never stored.
func tokenKey(token string) string {
	sum := sha256.Sum256([]byte(token))
	return "t:" + hex.EncodeToString(sum[:])
}

func ipKey(ip string) string {
	if ip == "" {
		return ""
	}
	return "ip:" + ip
}

// User authenticates an MCP caller and returns its configured identity.
func (a *Authenticator) User(r *http.Request) (string, config.User, error) {
	token := bearer(r)
	if token == "" {
		return "", config.User{}, ErrUnauthorized
	}
	ip := clientIP(r)
	cfg := a.store.Get()
	tk := tokenKey(token)
	if e, ok := a.cached(tk, cfg); ok {
		a.resetKeys(tk, ipKey(ip))
		return e.name, e.user, nil
	}
	if a.limited(tk, ipKey(ip)) {
		return "", config.User{}, ErrUnauthorized
	}
	for name, u := range cfg.Users {
		if u.Disabled {
			continue
		}
		if bcrypt.CompareHashAndPassword([]byte(u.TokenHash), []byte(token)) == nil {
			a.storeCache(tk, cfg, name, u)
			a.resetKeys(tk, ipKey(ip))
			return name, u, nil
		}
	}
	a.failKeys(tk, ipKey(ip))
	return "", config.User{}, ErrUnauthorized
}

// Admin authenticates the management console token.
func (a *Authenticator) Admin(r *http.Request) error {
	token := bearer(r)
	if token == "" {
		return ErrUnauthorized
	}
	ip := clientIP(r)
	cfg := a.store.Get()
	tk := "a:" + tokenKey(token)
	if _, ok := a.cached(tk, cfg); ok {
		a.resetKeys(tk, ipKey(ip))
		return nil
	}
	if a.limited(tk, ipKey(ip)) {
		return ErrUnauthorized
	}
	// bcrypt hashes cannot be constant-time compared directly; comparing the
	// derived key avoids trivially timing-parallel guessing.
	if bcrypt.CompareHashAndPassword([]byte(cfg.AdminToken), []byte(token)) != nil {
		a.failKeys(tk, ipKey(ip))
		return ErrUnauthorized
	}
	a.storeCache(tk, cfg, "admin", config.User{})
	a.resetKeys(tk, ipKey(ip))
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

func (a *Authenticator) cached(key string, cfg *config.Config) (cacheEntry, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	e, ok := a.cache[key]
	if !ok {
		return cacheEntry{}, false
	}
	if e.cfg != cfg || time.Now().After(e.exp) {
		delete(a.cache, key)
		return cacheEntry{}, false
	}
	return e, true
}

func (a *Authenticator) storeCache(key string, cfg *config.Config, name string, u config.User) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.cache) > 4096 {
		a.cache = map[string]cacheEntry{}
	}
	a.cache[key] = cacheEntry{cfg: cfg, name: name, user: u, exp: time.Now().Add(authCacheTTL)}
}

func (a *Authenticator) limited(keys ...string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, k := range keys {
		if k == "" {
			continue
		}
		f, ok := a.fails[k]
		if !ok {
			continue
		}
		if time.Now().After(f.reset) {
			delete(a.fails, k)
			continue
		}
		limit := authFailLimit
		if strings.HasPrefix(k, "ip:") {
			limit = authIPFailLimit
		}
		if f.count >= limit {
			return true
		}
	}
	return false
}

func (a *Authenticator) failKeys(keys ...string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, k := range keys {
		if k == "" {
			continue
		}
		f, ok := a.fails[k]
		if !ok || time.Now().After(f.reset) {
			if len(a.fails) > 4096 { // hard bound on tracker memory
				a.fails = map[string]*failWindow{}
			}
			a.fails[k] = &failWindow{count: 1, reset: time.Now().Add(authFailWindow)}
			continue
		}
		f.count++
	}
}

func (a *Authenticator) resetKeys(keys ...string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, k := range keys {
		if k != "" {
			delete(a.fails, k)
		}
	}
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
