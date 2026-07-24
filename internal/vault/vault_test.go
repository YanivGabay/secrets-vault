package vault

import (
	"os"
	"path/filepath"
	"testing"
)

func newTestVault(t *testing.T) *Vault {
	t.Helper()
	dir := t.TempDir()
	v := New(dir)
	if err := v.Init(); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestInit(t *testing.T) {
	dir := t.TempDir()
	v := New(dir)

	if err := v.Init(); err != nil {
		t.Fatal(err)
	}

	keyPath := filepath.Join(dir, "key")
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatal("key file not created")
	}
	if info.Size() != keySize {
		t.Fatalf("key size = %d, want %d", info.Size(), keySize)
	}

	vaultPath := filepath.Join(dir, "vault.enc")
	if _, err := os.Stat(vaultPath); err != nil {
		t.Fatal("vault file not created")
	}
}

func TestInit_AlreadyExists(t *testing.T) {
	v := newTestVault(t)
	if err := v.Init(); err == nil {
		t.Fatal("expected error on double init")
	}
}

func TestAdd_And_Get(t *testing.T) {
	v := newTestVault(t)

	if err := v.Add("myapp", "API_KEY", "secret123"); err != nil {
		t.Fatal(err)
	}

	val, err := v.Get("myapp", "API_KEY")
	if err != nil {
		t.Fatal(err)
	}
	if val != "secret123" {
		t.Fatalf("got %q, want %q", val, "secret123")
	}
}

func TestAdd_OverwritesExisting(t *testing.T) {
	v := newTestVault(t)

	v.Add("app", "KEY", "old")
	v.Add("app", "KEY", "new")

	val, _ := v.Get("app", "KEY")
	if val != "new" {
		t.Fatalf("got %q, want %q", val, "new")
	}
}

func TestAdd_MultipleProjects(t *testing.T) {
	v := newTestVault(t)

	v.Add("app1", "A", "1")
	v.Add("app2", "B", "2")
	v.Add("app1", "C", "3")

	projects, _ := v.ListProjects()
	if len(projects) != 2 {
		t.Fatalf("project count = %d, want 2", len(projects))
	}

	keys, _ := v.ListKeys("app1")
	if len(keys) != 2 {
		t.Fatalf("app1 key count = %d, want 2", len(keys))
	}
}

func TestAdd_SpecialCharacters(t *testing.T) {
	v := newTestVault(t)

	tests := []struct {
		name, key, value string
	}{
		{"multiline", "CERT", "line1\nline2\nline3"},
		{"unicode", "LABEL", "日本語テスト"},
		{"json-value", "CONFIG", `{"host":"localhost","port":5432}`},
		{"equals-sign", "DSN", "postgres://user:p@ss=word@host/db"},
		{"empty-value", "EMPTY", ""},
		{"spaces", "MSG", "  leading and trailing  "},
		{"quotes", "QUOTED", `"double" and 'single'`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := v.Add("special", tt.key, tt.value); err != nil {
				t.Fatal(err)
			}
			got, err := v.Get("special", tt.key)
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.value {
				t.Fatalf("got %q, want %q", got, tt.value)
			}
		})
	}
}

func TestRemove(t *testing.T) {
	v := newTestVault(t)
	v.Add("app", "A", "1")
	v.Add("app", "B", "2")

	if err := v.Remove("app", "A"); err != nil {
		t.Fatal(err)
	}

	keys, _ := v.ListKeys("app")
	if len(keys) != 1 || keys[0] != "B" {
		t.Fatalf("keys after remove = %v, want [B]", keys)
	}
}

func TestRemove_LastKey_RemovesProject(t *testing.T) {
	v := newTestVault(t)
	v.Add("app", "ONLY", "val")

	v.Remove("app", "ONLY")

	projects, _ := v.ListProjects()
	if len(projects) != 0 {
		t.Fatalf("projects = %v, want empty", projects)
	}
}

func TestRemove_NonexistentProject(t *testing.T) {
	v := newTestVault(t)
	if err := v.Remove("nope", "KEY"); err == nil {
		t.Fatal("expected error removing from nonexistent project")
	}
}

func TestRemove_NonexistentKey(t *testing.T) {
	v := newTestVault(t)
	v.Add("app", "EXISTS", "val")
	if err := v.Remove("app", "NOPE"); err == nil {
		t.Fatal("expected error removing nonexistent key")
	}
}

func TestGet_NonexistentProject(t *testing.T) {
	v := newTestVault(t)
	_, err := v.Get("nope", "KEY")
	if err == nil {
		t.Fatal("expected error for nonexistent project")
	}
}

func TestGet_NonexistentKey(t *testing.T) {
	v := newTestVault(t)
	v.Add("app", "EXISTS", "val")
	_, err := v.Get("app", "NOPE")
	if err == nil {
		t.Fatal("expected error for nonexistent key")
	}
}

func TestListProjects_Sorted(t *testing.T) {
	v := newTestVault(t)
	v.Add("zebra", "K", "v")
	v.Add("alpha", "K", "v")
	v.Add("middle", "K", "v")

	projects, _ := v.ListProjects()
	want := []string{"alpha", "middle", "zebra"}
	for i, p := range projects {
		if p != want[i] {
			t.Fatalf("projects[%d] = %q, want %q", i, p, want[i])
		}
	}
}

func TestListKeys_Sorted(t *testing.T) {
	v := newTestVault(t)
	v.Add("app", "ZEBRA_KEY", "v")
	v.Add("app", "ALPHA_KEY", "v")
	v.Add("app", "MID_KEY", "v")

	keys, _ := v.ListKeys("app")
	want := []string{"ALPHA_KEY", "MID_KEY", "ZEBRA_KEY"}
	for i, k := range keys {
		if k != want[i] {
			t.Fatalf("keys[%d] = %q, want %q", i, k, want[i])
		}
	}
}

func TestGetProject(t *testing.T) {
	v := newTestVault(t)
	v.Add("app", "A", "1")
	v.Add("app", "B", "2")

	secrets, err := v.GetProject("app")
	if err != nil {
		t.Fatal(err)
	}
	if len(secrets) != 2 {
		t.Fatalf("secret count = %d, want 2", len(secrets))
	}
	if secrets["A"] != "1" || secrets["B"] != "2" {
		t.Fatalf("secrets = %v", secrets)
	}
}

func TestProjects_Summary(t *testing.T) {
	v := newTestVault(t)
	v.Add("app1", "B", "v")
	v.Add("app1", "A", "v")
	v.Add("app2", "X", "v")

	summary, err := v.Projects()
	if err != nil {
		t.Fatal(err)
	}

	if len(summary) != 2 {
		t.Fatalf("project count = %d, want 2", len(summary))
	}

	app1Keys := summary["app1"]
	if len(app1Keys) != 2 || app1Keys[0] != "A" || app1Keys[1] != "B" {
		t.Fatalf("app1 keys = %v, want [A B]", app1Keys)
	}
}

func TestVault_Persistence(t *testing.T) {
	dir := t.TempDir()

	v1 := New(dir)
	v1.Init()
	v1.Add("app", "KEY", "persistent-value")

	v2 := New(dir)
	val, err := v2.Get("app", "KEY")
	if err != nil {
		t.Fatal(err)
	}
	if val != "persistent-value" {
		t.Fatalf("got %q after reopening vault", val)
	}
}

func TestVault_LargeDataset(t *testing.T) {
	v := newTestVault(t)

	for i := range 100 {
		project := "project-" + itoa(i/10)
		key := "KEY_" + itoa(i)
		if err := v.Add(project, key, "value-"+itoa(i)); err != nil {
			t.Fatal(err)
		}
	}

	projects, _ := v.ListProjects()
	if len(projects) != 10 {
		t.Fatalf("project count = %d, want 10", len(projects))
	}

	for i := range 10 {
		keys, _ := v.ListKeys("project-" + itoa(i))
		if len(keys) != 10 {
			t.Fatalf("project-%d key count = %d, want 10", i, len(keys))
		}
	}
}

func itoa(i int) string {
	return string(rune('0'+i/10)) + string(rune('0'+i%10))
}
