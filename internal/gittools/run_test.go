package gittools

import "testing"

func TestCheckRunArgs(t *testing.T) {
	allowed := [][]string{
		{"git", "log", "--oneline", "-n", "5"},
		{"git", "status"},
		{"git", "diff", "--staged"},
		{"git", "push", "origin", "feature/x"},
		{"git", "branch", "new-branch"},
	}
	for _, a := range allowed {
		if err := CheckRunArgs(a); err != nil {
			t.Fatalf("expected %v allowed, got %v", a, err)
		}
	}
	denied := [][]string{
		{"git", "push", "--force", "origin", "main"},
		{"git", "push", "origin", ":main"},
		{"git", "reset", "--hard", "HEAD~1"},
		{"git", "commit", "--amend"},
		{"git", "clean", "-fd"},
		{"git", "config", "user.name", "evil"},
		{"git", "submodule", "update", "--init"},
		{"ls", "-la"},
		{"git"},
	}
	for _, a := range denied {
		if err := CheckRunArgs(a); err == nil {
			t.Fatalf("expected %v denied", a)
		}
	}
}

func TestValidateRefName(t *testing.T) {
	if err := ValidateRefName("feature/x"); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"", "-x", "a b", "a..b", "a:b"} {
		if err := ValidateRefName(bad); err == nil {
			t.Fatalf("expected %q denied", bad)
		}
	}
}

func TestValidateRelPath(t *testing.T) {
	if err := ValidateRelPath("src/main.go"); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"", "/etc/passwd", "../secret"} {
		if err := ValidateRelPath(bad); err == nil {
			t.Fatalf("expected %q denied", bad)
		}
	}
}
