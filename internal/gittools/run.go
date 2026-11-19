// Package gittools builds git command lines for the semantic tools and
// validates agent-supplied arguments for the run_git escape hatch.
package gittools

import (
	"fmt"
	"strconv"
	"strings"
)

// allowlisted git subcommands for run_git. Everything else is rejected.
var allowlist = map[string]bool{
	"status": true, "diff": true, "log": true, "show": true,
	"branch": true, "tag": true, "remote": true,
	"add": true, "commit": true, "push": true, "pull": true, "fetch": true,
	"checkout": true, "switch": true, "restore": true,
	"merge": true, "rebase": true, "cherry-pick": true, "revert": true,
	"stash": true, "ls-files": true, "rev-parse": true, "shortlog": true,
	"describe": true, "blame": true, "grep": true, "reflog": true,
}

// forbidden argument fragments (exact token matches), enforced across all
// run_git invocations regardless of subcommand.
var forbiddenArgs = map[string]bool{
	"--force": true, "-f": true, "--hard": true, "--amend": true,
	"-D": true, "--delete": true, "--prune-empty": true,
	"--exec": true, "--upload-pack": true, "--receive-pack": true,
	"-c": true, "--config": true,
}

// CheckRunArgs validates an agent-supplied git invocation. Only known
// subcommands are allowed, dangerous flags are rejected everywhere, and
// delete-style refspecs (push origin :branch) are refused.
func CheckRunArgs(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("args must not be empty")
	}
	if args[0] != "git" {
		return fmt.Errorf("only git commands are allowed")
	}
	if len(args) < 2 {
		return fmt.Errorf("missing git subcommand")
	}
	sub := args[1]
	if strings.HasPrefix(sub, "-") {
		return fmt.Errorf("invalid git subcommand %q", sub)
	}
	if !allowlist[sub] {
		return fmt.Errorf("git subcommand %q is not allowed", sub)
	}
	for _, a := range args[2:] {
		if forbiddenArgs[a] {
			return fmt.Errorf("argument %q is not allowed", a)
		}
		if sub == "push" && strings.HasPrefix(a, ":") {
			return fmt.Errorf("delete-style refspec %q is not allowed", a)
		}
		if sub == "push" && strings.HasPrefix(a, "refs/heads/") && strings.Contains(a, ":") &&
			strings.HasPrefix(strings.SplitN(a, ":", 2)[1], ":") {
			return fmt.Errorf("delete-style refspec %q is not allowed", a)
		}
	}
	return nil
}

// ValidateRefName guards branch/tag names supplied by agents.
func ValidateRefName(name string) error {
	if name == "" {
		return fmt.Errorf("name must not be empty")
	}
	if strings.HasPrefix(name, "-") || strings.ContainsAny(name, " \t\n\r~^:?*[\\") ||
		strings.Contains(name, "..") {
		return fmt.Errorf("invalid ref name %q", name)
	}
	return nil
}

// ValidateRelPath guards pathspec arguments: relative, no traversal.
func ValidateRelPath(p string) error {
	if p == "" {
		return fmt.Errorf("path must not be empty")
	}
	if strings.HasPrefix(p, "/") || strings.Contains(p, "..") {
		return fmt.Errorf("path %q must stay inside the repository", p)
	}
	return nil
}

// LogLimit normalises a requested log limit.
func LogLimit(n int) string {
	if n <= 0 {
		return "20"
	}
	if n > 100 {
		return "100"
	}
	return strconv.Itoa(n)
}
