package session

import "testing"

func TestGetMissingNoPanic(t *testing.T) {
	m := &Manager{live: map[string]*Active{}}
	if a, ok := m.Get("no-such-session", "org/proj1"); ok {
		t.Fatalf("expected missing, got %+v", a)
	}
}

func TestGetPresent(t *testing.T) {
	m := &Manager{live: map[string]*Active{
		key("s1", "org/proj1"): {SessionID: "s1", Repo: "org/proj1", Container: "c1"},
	}}
	a, ok := m.Get("s1", "org/proj1")
	if !ok || a.Container != "c1" {
		t.Fatalf("expected present container, got %+v ok=%v", a, ok)
	}
}
