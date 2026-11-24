// Package sanitize scrubs credential material from anything that is about to
// leave the gateway and reach an LLM context: tool results, git output, error
// messages and admin API payloads.
package sanitize

import "regexp"

var patterns = []struct {
	re   *regexp.Regexp
	repl string
}{
	// OpenSSH / PEM private key blocks.
	{regexp.MustCompile(`(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----`), "[private key removed]"},
	// age secret keys.
	{regexp.MustCompile(`AGE-SECRET-KEY-[A-Z0-9]{20,}`), "[age key removed]"},
	// GitHub tokens (classic fine-grained and OAuth).
	{regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{16,}`), "[github token removed]"},
	{regexp.MustCompile(`github_pat_[A-Za-z0-9_]{20,}`), "[github token removed]"},
	// JWT-shaped blobs.
	{regexp.MustCompile(`eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.?[A-Za-z0-9_.-]*`), "[jwt removed]"},
	// URL embedded credentials: scheme://user:pass@host or scheme://token@host
	{regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.-]*://)[^/\s:@]+(:[^/\s@]+)?@`), "${1}[cred]@"},
	// keyword=value style leaks in git/ssh diagnostics.
	{regexp.MustCompile(`(?i)(token|password|passwd|secret|api[_-]?key|authorization)(["']?\s*[:=]\s*["']?)[A-Za-z0-9_\-./+=]{8,}`), "${1}${2}[redacted]"},
}

// Clean replaces every recognisable credential shape in s.
func Clean(s string) string {
	for _, p := range patterns {
		s = p.re.ReplaceAllString(s, p.repl)
	}
	return s
}
