// Package audit appends security-relevant events to a JSONL file and keeps a
// small in-memory ring for the admin console.
package audit

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Event is a single audit record.
type Event struct {
	TS         time.Time `json:"ts"`
	Actor      string    `json:"actor"`
	ActorType  string    `json:"actor_type"` // user | admin | system
	Event      string    `json:"event"`      // authn, authz, session, push, tool, agent, config...
	Repo       string    `json:"repo,omitempty"`
	Tool       string    `json:"tool,omitempty"`
	Credential string    `json:"credential,omitempty"`
	Session    string    `json:"session,omitempty"`
	Result     string    `json:"result"` // ok | denied | error
	Detail     string    `json:"detail,omitempty"`
}

// Logger writes events as JSON lines and keeps the most recent ones in memory.
type Logger struct {
	mu     sync.Mutex
	f      *os.File
	path   string
	size   int64
	rotate int64
	recent []Event
	limit  int
}

// auditRotateBytes bounds the live audit log; on overflow the file is
// renamed to <path>.1 and a fresh one is opened.
const auditRotateBytes = 16 << 20

// Open creates the audit log file (and its directory) if needed.
func Open(path string) (*Logger, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	size, _ := f.Seek(0, io.SeekEnd)
	return &Logger{f: f, path: path, size: size, rotate: auditRotateBytes, limit: 500}, nil
}

// Log records one event. It never panics on write errors; the file write is
// best-effort but the in-memory ring always records the event.
func (l *Logger) Log(e Event) {
	if e.TS.IsZero() {
		e.TS = time.Now()
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.recent = append(l.recent, e)
	if len(l.recent) > l.limit {
		l.recent = l.recent[len(l.recent)-l.limit:]
	}
	if l.f != nil {
		data, err := json.Marshal(e)
		if err == nil {
			n, _ := l.f.Write(append(data, '\n'))
			l.size += int64(n)
			if l.size > l.rotate {
				l.rotateLocked()
			}
		}
	}
}

// rotateLocked moves the current log aside and starts a fresh one.
func (l *Logger) rotateLocked() {
	if l.f != nil {
		_ = l.f.Close()
	}
	_ = os.Rename(l.path, l.path+".1")
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		l.f = nil
		l.size = 0
		return
	}
	l.f = f
	l.size = 0
}

// Recent returns up to n most recent events, newest first.
func (l *Logger) Recent(n int) []Event {
	l.mu.Lock()
	defer l.mu.Unlock()
	if n <= 0 || n > len(l.recent) {
		n = len(l.recent)
	}
	out := make([]Event, 0, n)
	for i := len(l.recent) - 1; i >= len(l.recent)-n; i-- {
		out = append(out, l.recent[i])
	}
	return out
}

// Close closes the underlying file.
func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f != nil {
		return l.f.Close()
	}
	return nil
}
