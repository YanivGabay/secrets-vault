package sync

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeTarget implements Target for testing.
type fakeTarget struct {
	name    string
	err     error
	synced  map[string]string
	project string
}

func (f *fakeTarget) Name() string { return f.name }
func (f *fakeTarget) Sync(project string, secrets map[string]string) error {
	f.project = project
	f.synced = secrets
	return f.err
}

func TestAll_SingleTarget(t *testing.T) {
	target := &fakeTarget{name: "test"}
	secrets := map[string]string{"A": "1", "B": "2"}

	results := All("myapp", secrets, target)

	if len(results) != 1 {
		t.Fatalf("result count = %d, want 1", len(results))
	}
	if results[0].Err != nil {
		t.Fatalf("unexpected error: %v", results[0].Err)
	}
	if results[0].Target != "test" {
		t.Fatalf("target = %q, want %q", results[0].Target, "test")
	}
	if len(results[0].Keys) != 2 {
		t.Fatalf("key count = %d, want 2", len(results[0].Keys))
	}
	if target.project != "myapp" {
		t.Fatalf("project = %q, want %q", target.project, "myapp")
	}
}

func TestAll_ParallelTargets(t *testing.T) {
	targets := []Target{
		&fakeTarget{name: "github"},
		&fakeTarget{name: "cloudflare"},
		&fakeTarget{name: "env"},
	}
	secrets := map[string]string{"KEY": "val"}

	results := All("app", secrets, targets...)

	if len(results) != 3 {
		t.Fatalf("result count = %d, want 3", len(results))
	}
	for _, r := range results {
		if r.Err != nil {
			t.Fatalf("target %s failed: %v", r.Target, r.Err)
		}
	}
}

func TestAll_PartialFailure(t *testing.T) {
	targets := []Target{
		&fakeTarget{name: "ok"},
		&fakeTarget{name: "fail", err: errors.New("connection refused")},
		&fakeTarget{name: "ok2"},
	}
	secrets := map[string]string{"KEY": "val"}

	results := All("app", secrets, targets...)

	failCount := 0
	for _, r := range results {
		if r.Err != nil {
			failCount++
			if r.Target != "fail" {
				t.Fatalf("wrong target failed: %s", r.Target)
			}
		}
	}
	if failCount != 1 {
		t.Fatalf("fail count = %d, want 1", failCount)
	}
}

func TestFormatResults(t *testing.T) {
	results := []Result{
		{Target: "github", Keys: []string{"A", "B"}, Err: nil},
		{Target: "cloudflare", Keys: []string{"A"}, Err: errors.New("timeout")},
	}

	out := FormatResults(results)

	if !strings.Contains(out, "OK   github: synced 2 keys") {
		t.Fatalf("missing success line in: %s", out)
	}
	if !strings.Contains(out, "FAIL cloudflare: timeout") {
		t.Fatalf("missing failure line in: %s", out)
	}
}

func TestDotEnv_Sync(t *testing.T) {
	dir := t.TempDir()
	de := &DotEnv{ProjectDir: dir}

	secrets := map[string]string{
		"ZEBRA":    "last",
		"ALPHA":    "first",
		"MIDDLE":   "mid",
		"HAS_QUOTE": `say "hello"`,
	}

	if err := de.Sync("app", secrets); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(filepath.Join(dir, ".env"))
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)

	// keys should be sorted
	alphaIdx := strings.Index(content, "ALPHA=")
	middleIdx := strings.Index(content, "MIDDLE=")
	zebraIdx := strings.Index(content, "ZEBRA=")

	if alphaIdx > middleIdx || middleIdx > zebraIdx {
		t.Fatalf("keys not sorted:\n%s", content)
	}

	// values should be quoted
	if !strings.Contains(content, `HAS_QUOTE="say \"hello\""`) {
		t.Fatalf("quote escaping wrong:\n%s", content)
	}

	// file permissions
	info, _ := os.Stat(filepath.Join(dir, ".env"))
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Fatalf("permissions = %o, want 0600", perm)
	}
}

func TestDotEnv_Overwrite(t *testing.T) {
	dir := t.TempDir()
	de := &DotEnv{ProjectDir: dir}

	de.Sync("app", map[string]string{"OLD": "old"})
	de.Sync("app", map[string]string{"NEW": "new"})

	data, _ := os.ReadFile(filepath.Join(dir, ".env"))
	content := string(data)

	if strings.Contains(content, "OLD") {
		t.Fatal(".env should be overwritten, not appended")
	}
	if !strings.Contains(content, "NEW") {
		t.Fatal("new key missing after overwrite")
	}
}
