package mcpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func initReq(sid string) *http.Request {
	body := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}`
	return postReq(sid, body)
}

func pingReq(sid string) *http.Request {
	return postReq(sid, `{"jsonrpc":"2.0","id":2,"method":"ping"}`)
}

func postReq(sid, body string) *http.Request {
	req := httptest.NewRequest("POST", "/mcp", strings.NewReader(body))
	if sid != "" {
		req.Header.Set("Mcp-Session-Id", sid)
	}
	return req
}

func TestSessionActorBinding(t *testing.T) {
	srv, tk := newTestServer(t)

	// alice initializes → gets a session id
	req := initReq("")
	req.Header.Set("Authorization", "Bearer "+tk.alice)
	rec := httptest.NewRecorder()
	srv.handleMCP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("initialize failed: %d %s", rec.Code, rec.Body.String())
	}
	sid := rec.Header().Get("Mcp-Session-Id")
	if sid == "" {
		t.Fatal("no session id returned")
	}

	// bob must not be able to reuse alice's session id
	req2 := initReq(sid)
	req2.Header.Set("Authorization", "Bearer "+tk.bob)
	rec2 := httptest.NewRecorder()
	srv.handleMCP(rec2, req2)
	if rec2.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for cross-user initialize, got %d", rec2.Code)
	}

	// bob must not be able to call tools on alice's session
	req3 := pingReq(sid)
	req3.Header.Set("Authorization", "Bearer "+tk.bob)
	rec3 := httptest.NewRecorder()
	srv.handleMCP(rec3, req3)
	if rec3.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for cross-user tools/call, got %d", rec3.Code)
	}

	// bob must not be able to delete alice's session
	req4 := httptest.NewRequest("DELETE", "/mcp", nil)
	req4.Header.Set("Authorization", "Bearer "+tk.bob)
	req4.Header.Set("Mcp-Session-Id", sid)
	rec4 := httptest.NewRecorder()
	srv.handleMCP(rec4, req4)
	if rec4.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for cross-user delete, got %d", rec4.Code)
	}

	// the rightful owner still works (ping succeeds on the same session)
	req5 := pingReq(sid)
	req5.Header.Set("Authorization", "Bearer "+tk.alice)
	rec5 := httptest.NewRecorder()
	srv.handleMCP(rec5, req5)
	if rec5.Code != http.StatusOK {
		t.Fatalf("owner ping failed: %d %s", rec5.Code, rec5.Body.String())
	}
}

func TestInitializeUnknownSessionCreatesNew(t *testing.T) {
	srv, tk := newTestServer(t)
	req := initReq("someone-elses-session")
	req.Header.Set("Authorization", "Bearer "+tk.alice)
	rec := httptest.NewRecorder()
	srv.handleMCP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("initialize with unknown sid should mint a new session, got %d", rec.Code)
	}
	if rec.Header().Get("Mcp-Session-Id") == "someone-elses-session" {
		t.Fatal("must not trust a client-supplied unknown session id")
	}
}

func TestInitializeSessionLimit(t *testing.T) {
	srv, tk := newTestServer(t)
	// the default limit is 4: the fifth initialize for one user is rejected
	for i := 0; i < 4; i++ {
		req := initReq("")
		req.Header.Set("Authorization", "Bearer "+tk.alice)
		rec := httptest.NewRecorder()
		srv.handleMCP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("initialize %d should succeed: %d %s", i+1, rec.Code, rec.Body.String())
		}
	}
	req := initReq("")
	req.Header.Set("Authorization", "Bearer "+tk.alice)
	rec := httptest.NewRecorder()
	srv.handleMCP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 on the fifth session, got %d %s", rec.Code, rec.Body.String())
	}
}
