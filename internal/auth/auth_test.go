package auth

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/local/git-mcp-gateway/internal/config"
	"golang.org/x/crypto/bcrypt"
)

// testAuth builds an Authenticator backed by a real hot-reload store with one
// enabled user (alice / goodTok) and an admin token.
func testAuth(t *testing.T) (*Authenticator, *config.Store) {
	t.Helper()
	dir := t.TempDir()
	userHash, err := bcrypt.GenerateFromPassword([]byte("goodTok"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	adminHash, err := bcrypt.GenerateFromPassword([]byte("adminTok"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"server.yaml": "server:\n  addr: \":8443\"\n  session_image: git-mcp-session:local\n  socket_dir: " +
			filepath.Join(t.TempDir(), "agents") + "\n  audit_file: " + filepath.Join(t.TempDir(), "audit.jsonl") + "\n",
		"users.yaml":  "users:\n  alice:\n    token_hash: \"" + string(userHash) + "\"\n    name: Alice\n    email: alice@corp.com\nadmin_token_hash: \"" + string(adminHash) + "\"\n",
		"grants.yaml": "credentials:\n  key-alice:\n    repo: org/proj1\n    readonly: false\n    key_file: /keys/k.age\ngrants:\n  - user: alice\n    repo: org/proj1\n    actions: [read, clone, push]\n    credential: key-alice\n",
		"repos.yaml":  "workspace_root: " + filepath.Join(t.TempDir(), "ws") + "\nrepos:\n  org/proj1:\n    github: org/proj1\n",
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	store, err := config.NewStore(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	return New(store), store
}

func TestAuthSuccess(t *testing.T) {
	a, _ := testAuth(t)
	r := httptest.NewRequest("POST", "/mcp", strings.NewReader("{}"))
	r.Header.Set("Authorization", "Bearer goodTok")
	user, _, err := a.User(r)
	if err != nil || user != "alice" {
		t.Fatalf("expected alice, got %q err=%v", user, err)
	}
	ar := httptest.NewRequest("POST", "/admin", strings.NewReader("{}"))
	ar.Header.Set("Authorization", "Bearer adminTok")
	if err := a.Admin(ar); err != nil {
		t.Fatalf("admin should authenticate, got %v", err)
	}
}

func TestAuthCacheHit(t *testing.T) {
	a, _ := testAuth(t)
	r := httptest.NewRequest("POST", "/mcp", strings.NewReader("{}"))
	r.Header.Set("Authorization", "Bearer goodTok")
	if _, _, err := a.User(r); err != nil {
		t.Fatalf("first auth should succeed, got %v", err)
	}
	// the second call is served from the cache
	if _, _, err := a.User(r); err != nil {
		t.Fatalf("cached auth should succeed, got %v", err)
	}
}

func TestAuthCacheInvalidatedOnTokenRotation(t *testing.T) {
	a, store := testAuth(t)
	r := httptest.NewRequest("POST", "/mcp", strings.NewReader("{}"))
	r.Header.Set("Authorization", "Bearer goodTok")
	if _, _, err := a.User(r); err != nil {
		t.Fatalf("first auth should succeed, got %v", err)
	}
	newHash, err := bcrypt.GenerateFromPassword([]byte("rotated"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Update(func(c *config.Config) error {
		u := c.Users["alice"]
		u.TokenHash = string(newHash)
		c.Users["alice"] = u
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// the rotation changes the configuration generation, so the stale cache
	// entry must not keep the old token authenticating
	if _, _, err := a.User(r); err == nil {
		t.Fatal("rotated token must not authenticate via a stale cache entry")
	}
}

func TestAuthRateLimitPerToken(t *testing.T) {
	a, _ := testAuth(t)
	// exhaust the failure budget for one presented token
	for i := 0; i < authFailLimit; i++ {
		r := httptest.NewRequest("POST", "/mcp", strings.NewReader("{}"))
		r.RemoteAddr = "192.0.2.1:1234"
		r.Header.Set("Authorization", "Bearer wrong")
		if _, _, err := a.User(r); err == nil {
			t.Fatal("bad token must fail")
		}
	}
	// that token is now rate limited
	r := httptest.NewRequest("POST", "/mcp", strings.NewReader("{}"))
	r.RemoteAddr = "192.0.2.1:1234"
	r.Header.Set("Authorization", "Bearer wrong")
	if _, _, err := a.User(r); err == nil {
		t.Fatal("expected rate-limited rejection for the exhausted token")
	}
	// a different token from the same IP is unaffected
	r2 := httptest.NewRequest("POST", "/mcp", strings.NewReader("{}"))
	r2.RemoteAddr = "192.0.2.1:1234"
	r2.Header.Set("Authorization", "Bearer goodTok")
	if _, _, err := a.User(r2); err != nil {
		t.Fatalf("valid token from the same IP must not be blocked, got %v", err)
	}
}

func TestAuthRateLimitIPBackstop(t *testing.T) {
	a, _ := testAuth(t)
	// distinct bad tokens exhaust the per-IP backstop
	for i := 0; i < authIPFailLimit; i++ {
		r := httptest.NewRequest("POST", "/mcp", strings.NewReader("{}"))
		r.RemoteAddr = "192.0.2.1:1234"
		r.Header.Set("Authorization", "Bearer wrong-tok-"+strconv.Itoa(i))
		if _, _, err := a.User(r); err == nil {
			t.Fatal("bad token must fail")
		}
	}
	// the IP backstop now rejects even a valid token from that IP
	r := httptest.NewRequest("POST", "/mcp", strings.NewReader("{}"))
	r.RemoteAddr = "192.0.2.1:1234"
	r.Header.Set("Authorization", "Bearer goodTok")
	if _, _, err := a.User(r); err == nil {
		t.Fatal("expected per-IP backstop rejection after 200 failures")
	}
	// a different IP is unaffected
	r2 := httptest.NewRequest("POST", "/mcp", strings.NewReader("{}"))
	r2.RemoteAddr = "192.0.2.9:9999"
	r2.Header.Set("Authorization", "Bearer goodTok")
	if _, _, err := a.User(r2); err != nil {
		t.Fatalf("different IP must not be rate limited, got %v", err)
	}
}

func TestAuthRateLimitResetsOnSuccess(t *testing.T) {
	a, _ := testAuth(t)
	// a single failure, then a success from the same IP clears the counter
	r := httptest.NewRequest("POST", "/mcp", strings.NewReader("{}"))
	r.RemoteAddr = "192.0.2.5:1"
	r.Header.Set("Authorization", "Bearer wrong")
	_, _, _ = a.User(r)
	r2 := httptest.NewRequest("POST", "/mcp", strings.NewReader("{}"))
	r2.RemoteAddr = "192.0.2.5:1"
	r2.Header.Set("Authorization", "Bearer goodTok")
	if _, _, err := a.User(r2); err != nil {
		t.Fatalf("success should clear the failure counter, got %v", err)
	}
}
