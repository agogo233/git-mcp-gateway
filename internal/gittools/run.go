// Package gittools builds git command lines for the semantic tools and
// validates agent-supplied arguments for the run_git escape hatch.
package gittools

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/local/git-mcp-gateway/internal/config"
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

// remoteWriteSubcommands mutate the workspace's remote configuration and are
// never allowed through run_git (a prompt-injected agent must not be able to
// point origin at an attacker-controlled server).
var remoteWriteSubcommands = map[string]bool{
	"set-url": true, "add": true, "remove": true, "rm": true, "rename": true,
	"prune": true, "set-head": true, "set-branches": true,
}

// CheckRunArgs validates an agent-supplied git invocation. Only known
// subcommands are allowed, dangerous flags are rejected everywhere, and
// force/delete-style refspecs are refused.
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
		switch sub {
		case "push":
			// force-push via flag or "+" refspec, and delete-style refspecs,
			// are never allowed through the escape hatch. --force-with-lease
			// is matched by prefix so "ref:expect" variants cannot slip by.
			if strings.HasPrefix(a, "+") || strings.HasPrefix(a, ":") {
				return fmt.Errorf("force/delete refspec %q is not allowed", a)
			}
			if strings.HasPrefix(a, "--force-with-lease") || a == "--mirror" || a == "--prune" {
				return fmt.Errorf("argument %q is not allowed", a)
			}
		case "fetch":
			// force-fetching ("+" refspec) rewrites local remote-tracking
			// refs; the plain fetch tools already cover the safe cases.
			if strings.HasPrefix(a, "+") {
				return fmt.Errorf("force refspec %q is not allowed", a)
			}
		case "remote":
			// keep git remote read-only: the first non-flag argument selects
			// the remote subcommand.
			if !strings.HasPrefix(a, "-") && remoteWriteSubcommands[a] {
				return fmt.Errorf("git remote %s is not allowed", a)
			}
		}
	}
	return nil
}

// RequiredAction maps an allowlisted git invocation to the grant action it
// requires: write-style subcommands need push, network/workspace-mutating
// ones need clone, everything else is read. Used to re-check run_git against
// the caller's grant, since the tool itself is registered as read.
func RequiredAction(args []string) string {
	if len(args) < 2 {
		return config.ActionRead
	}
	switch args[1] {
	case "add", "commit", "push", "merge", "rebase", "cherry-pick", "revert", "stash":
		return config.ActionPush
	case "pull", "fetch", "checkout", "switch", "restore":
		return config.ActionClone
	default:
		return config.ActionRead
	}
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
