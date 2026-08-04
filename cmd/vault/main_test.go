package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func buildBinary(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "vault")
	cmd := exec.Command("go", "build", "-o", bin, ".")
	cmd.Dir = filepath.Join(findModRoot(t), "cmd", "vault")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %s\n%s", err, out)
	}
	return bin
}

func findModRoot(t *testing.T) string {
	t.Helper()
	dir, _ := os.Getwd()
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found")
		}
		dir = parent
	}
}

func runVault(t *testing.T, bin, vaultDir string, args ...string) (string, error) {
	t.Helper()
	return runVaultWithStdin(t, bin, vaultDir, "", args...)
}

func runVaultWithStdin(t *testing.T, bin, vaultDir, stdin string, args ...string) (string, error) {
	t.Helper()
	cmd := exec.Command(bin, args...)
	cmd.Env = append(os.Environ(), "VAULT_DIR="+vaultDir)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func TestCLI_InitAndList(t *testing.T) {
	bin := buildBinary(t)
	dir := t.TempDir()

	out, err := runVault(t, bin, dir, "init")
	if err != nil {
		t.Fatalf("init failed: %s: %v", out, err)
	}
	if !strings.Contains(out, "initialized") {
		t.Fatalf("unexpected init output: %s", out)
	}

	out, err = runVault(t, bin, dir, "list")
	if err != nil {
		t.Fatalf("list failed: %s: %v", out, err)
	}
	if !strings.Contains(out, "empty vault") {
		t.Fatalf("expected empty vault, got: %s", out)
	}
}

func TestCLI_DoubleInit(t *testing.T) {
	bin := buildBinary(t)
	dir := t.TempDir()

	runVault(t, bin, dir, "init")
	_, err := runVault(t, bin, dir, "init")
	if err == nil {
		t.Fatal("expected error on double init")
	}
}

func TestCLI_ImportAndList(t *testing.T) {
	bin := buildBinary(t)
	dir := t.TempDir()
	runVault(t, bin, dir, "init")

	envFile := filepath.Join(t.TempDir(), ".env")
	os.WriteFile(envFile, []byte("KEY_A=value_a\nKEY_B=value_b\n"), 0644)

	out, err := runVault(t, bin, dir, "import", "testproject", envFile)
	if err != nil {
		t.Fatalf("import failed: %s: %v", out, err)
	}
	if !strings.Contains(out, "Imported 2 keys") {
		t.Fatalf("unexpected import output: %s", out)
	}

	out, _ = runVault(t, bin, dir, "list")
	if !strings.Contains(out, "testproject") {
		t.Fatalf("project not in list: %s", out)
	}
	if !strings.Contains(out, "KEY_A") || !strings.Contains(out, "KEY_B") {
		t.Fatalf("keys not in list: %s", out)
	}
}

func TestCLI_RemoveAndVerify(t *testing.T) {
	bin := buildBinary(t)
	dir := t.TempDir()
	runVault(t, bin, dir, "init")

	envFile := filepath.Join(t.TempDir(), ".env")
	os.WriteFile(envFile, []byte("A=1\nB=2\nC=3\n"), 0644)
	runVault(t, bin, dir, "import", "app", envFile)

	out, err := runVault(t, bin, dir, "rm", "app", "B")
	if err != nil {
		t.Fatalf("rm failed: %s: %v", out, err)
	}

	out, _ = runVault(t, bin, dir, "list", "app")
	if strings.Contains(out, "B") {
		t.Fatalf("B still in list after remove: %s", out)
	}
	if !strings.Contains(out, "A") || !strings.Contains(out, "C") {
		t.Fatalf("other keys missing: %s", out)
	}
}

func TestCLI_SyncEnv(t *testing.T) {
	bin := buildBinary(t)
	dir := t.TempDir()
	runVault(t, bin, dir, "init")

	envFile := filepath.Join(t.TempDir(), ".env")
	os.WriteFile(envFile, []byte("SECRET=my-secret\n"), 0644)
	runVault(t, bin, dir, "import", "app", envFile)

	syncDir := t.TempDir()
	out, err := runVault(t, bin, dir, "sync", "app", "env", "--dir", syncDir)
	if err != nil {
		t.Fatalf("sync failed: %s: %v", out, err)
	}
	if !strings.Contains(out, "OK") {
		t.Fatalf("expected OK in sync output: %s", out)
	}

	data, err := os.ReadFile(filepath.Join(syncDir, ".env"))
	if err != nil {
		t.Fatal("synced .env not created")
	}
	if !strings.Contains(string(data), "SECRET=") {
		t.Fatalf("secret not in synced .env: %s", data)
	}
}

func TestCLI_UnknownCommand(t *testing.T) {
	bin := buildBinary(t)
	_, err := runVault(t, bin, t.TempDir(), "bogus")
	if err == nil {
		t.Fatal("expected error for unknown command")
	}
}

func TestCLI_NoArgs(t *testing.T) {
	bin := buildBinary(t)
	_, err := runVault(t, bin, t.TempDir())
	if err == nil {
		t.Fatal("expected error for no args")
	}
}

func TestCLI_MissingArgs(t *testing.T) {
	bin := buildBinary(t)
	dir := t.TempDir()
	runVault(t, bin, dir, "init")

	tests := []struct {
		name string
		args []string
	}{
		{"add-no-key", []string{"add", "project"}},
		{"rm-no-key", []string{"rm", "project"}},
		{"import-no-path", []string{"import", "project"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := runVault(t, bin, dir, tt.args...)
			if err == nil {
				t.Fatalf("expected error for %v", tt.args)
			}
		})
	}
}

func TestCLI_GetValue(t *testing.T) {
	bin := buildBinary(t)
	dir := t.TempDir()
	runVault(t, bin, dir, "init")

	runVaultWithStdin(t, bin, dir, "my-secret-123", "add", "app", "TOKEN", "--stdin")

	out, err := runVault(t, bin, dir, "get", "app", "TOKEN")
	if err != nil {
		t.Fatalf("get failed: %s: %v", out, err)
	}
	if out != "my-secret-123" {
		t.Fatalf("got %q, want %q", out, "my-secret-123")
	}
}

func TestCLI_GetValue_Pipe(t *testing.T) {
	bin := buildBinary(t)
	dir := t.TempDir()
	runVault(t, bin, dir, "init")

	runVaultWithStdin(t, bin, dir, "pipe-this-value", "add", "app", "KEY", "--stdin")

	// Simulate piping: vault get | other-command
	cmd := exec.Command("sh", "-c", bin+" get app KEY | wc -c")
	cmd.Env = append(os.Environ(), "VAULT_DIR="+dir)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("pipe failed: %s: %v", out, err)
	}
	// "pipe-this-value" = 15 chars, no trailing newline
	if !strings.Contains(strings.TrimSpace(string(out)), "15") {
		t.Fatalf("expected 15 bytes piped, got: %s", out)
	}
}

func TestCLI_GetValue_NotFound(t *testing.T) {
	bin := buildBinary(t)
	dir := t.TempDir()
	runVault(t, bin, dir, "init")

	_, err := runVault(t, bin, dir, "get", "nope", "MISSING")
	if err == nil {
		t.Fatal("expected error for nonexistent key")
	}
}

func TestCLI_AddFromStdin(t *testing.T) {
	bin := buildBinary(t)
	dir := t.TempDir()
	runVault(t, bin, dir, "init")

	out, err := runVaultWithStdin(t, bin, dir, "my-secret-from-stdin", "add", "app", "TOKEN", "--stdin")
	if err != nil {
		t.Fatalf("add --stdin failed: %s: %v", out, err)
	}
	if !strings.Contains(out, "Added TOKEN to app") {
		t.Fatalf("unexpected output: %s", out)
	}

	out, _ = runVault(t, bin, dir, "list", "app")
	if !strings.Contains(out, "TOKEN") {
		t.Fatalf("TOKEN not in list: %s", out)
	}
}

func TestCLI_AddFromStdin_Empty(t *testing.T) {
	bin := buildBinary(t)
	dir := t.TempDir()
	runVault(t, bin, dir, "init")

	_, err := runVaultWithStdin(t, bin, dir, "", "add", "app", "KEY", "--stdin")
	if err == nil {
		t.Fatal("expected error for empty stdin")
	}
}

func TestCLI_AddFromStdin_Multiline(t *testing.T) {
	bin := buildBinary(t)
	dir := t.TempDir()
	runVault(t, bin, dir, "init")

	cert := "-----BEGIN CERT-----\nMIIBxTCCAW...\n-----END CERT-----"
	out, err := runVaultWithStdin(t, bin, dir, cert, "add", "app", "TLS_CERT", "--stdin")
	if err != nil {
		t.Fatalf("add multiline --stdin failed: %s: %v", out, err)
	}

	// Sync to .env and verify it round-trips
	syncDir := t.TempDir()
	runVault(t, bin, dir, "sync", "app", "env", "--dir", syncDir)
	data, _ := os.ReadFile(filepath.Join(syncDir, ".env"))
	if !strings.Contains(string(data), "BEGIN CERT") {
		t.Fatalf("multiline value lost in sync: %s", data)
	}
}

func TestCLI_Onboard(t *testing.T) {
	bin := buildBinary(t)
	vaultDir := t.TempDir()
	runVault(t, bin, vaultDir, "init")

	// Create a fake project directory with .env files
	projectDir := t.TempDir()
	os.WriteFile(filepath.Join(projectDir, ".env"), []byte("API_KEY=abc123\nDB_URL=postgres://localhost\n"), 0644)
	os.WriteFile(filepath.Join(projectDir, ".env.local"), []byte("LOCAL_SECRET=dev-only\n"), 0644)
	os.MkdirAll(filepath.Join(projectDir, ".github"), 0755)

	out, err := runVault(t, bin, vaultDir, "onboard", projectDir)
	if err != nil {
		t.Fatalf("onboard failed: %s: %v", out, err)
	}

	if !strings.Contains(out, ".env (2 keys)") {
		t.Fatalf("expected .env import in output: %s", out)
	}
	if !strings.Contains(out, ".env.local (1 keys)") {
		t.Fatalf("expected .env.local import in output: %s", out)
	}
	if !strings.Contains(out, ".vault.json") {
		t.Fatalf("expected .vault.json creation in output: %s", out)
	}

	// Verify .vault.json was created
	manifest, err := os.ReadFile(filepath.Join(projectDir, ".vault.json"))
	if err != nil {
		t.Fatal("manifest not created")
	}
	content := string(manifest)
	if !strings.Contains(content, "API_KEY") {
		t.Fatalf("API_KEY not in manifest: %s", content)
	}
	if !strings.Contains(content, "github") {
		t.Fatalf("github sync target not auto-detected: %s", content)
	}

	// Verify secrets are in vault
	projectName := filepath.Base(projectDir)
	out, _ = runVault(t, bin, vaultDir, "list", projectName)
	if !strings.Contains(out, "API_KEY") || !strings.Contains(out, "DB_URL") || !strings.Contains(out, "LOCAL_SECRET") {
		t.Fatalf("not all keys imported: %s", out)
	}
}

func TestCLI_Onboard_NoEnvFiles(t *testing.T) {
	bin := buildBinary(t)
	vaultDir := t.TempDir()
	runVault(t, bin, vaultDir, "init")

	emptyDir := t.TempDir()
	_, err := runVault(t, bin, vaultDir, "onboard", emptyDir)
	if err == nil {
		t.Fatal("expected error when no .env files found")
	}
}

func TestCLI_Onboard_DetectsWrangler(t *testing.T) {
	bin := buildBinary(t)
	vaultDir := t.TempDir()
	runVault(t, bin, vaultDir, "init")

	projectDir := t.TempDir()
	os.WriteFile(filepath.Join(projectDir, ".env"), []byte("KEY=val\n"), 0644)
	os.WriteFile(filepath.Join(projectDir, "wrangler.toml"), []byte("[vars]\n"), 0644)

	runVault(t, bin, vaultDir, "onboard", projectDir)

	manifest, _ := os.ReadFile(filepath.Join(projectDir, ".vault.json"))
	if !strings.Contains(string(manifest), "cloudflare") {
		t.Fatalf("cloudflare not detected from wrangler.toml: %s", manifest)
	}
}

func TestCLI_SyncFromManifest(t *testing.T) {
	bin := buildBinary(t)
	vaultDir := t.TempDir()
	runVault(t, bin, vaultDir, "init")

	// Create project, onboard, then sync using manifest
	projectDir := t.TempDir()
	os.WriteFile(filepath.Join(projectDir, ".env"), []byte("SECRET=from-manifest\n"), 0644)
	runVault(t, bin, vaultDir, "onboard", projectDir)

	// Add env sync target to manifest
	projectName := filepath.Base(projectDir)
	syncDir := t.TempDir()
	manifestContent := `{"project":"` + projectName + `","keys":["SECRET"],"sync":{"env":"` + syncDir + `"}}`
	os.WriteFile(filepath.Join(projectDir, ".vault.json"), []byte(manifestContent), 0644)

	// Sync without specifying target — should use manifest
	out, err := runVault(t, bin, vaultDir, "sync", projectDir)
	if err != nil {
		t.Fatalf("manifest sync failed: %s: %v", out, err)
	}
	if !strings.Contains(out, "OK") {
		t.Fatalf("expected OK: %s", out)
	}

	data, _ := os.ReadFile(filepath.Join(syncDir, ".env"))
	if !strings.Contains(string(data), "SECRET=") {
		t.Fatalf("secret not synced via manifest: %s", data)
	}
}

func TestCLI_SyncWithKeysFilter(t *testing.T) {
	bin := buildBinary(t)
	dir := t.TempDir()
	runVault(t, bin, dir, "init")

	envFile := filepath.Join(t.TempDir(), ".env")
	os.WriteFile(envFile, []byte("API_KEY=abc\nDB_URL=postgres\nDEBUG=true\n"), 0644)
	runVault(t, bin, dir, "import", "app", envFile)

	syncDir := t.TempDir()
	out, err := runVault(t, bin, dir, "sync", "app", "env", "--dir", syncDir, "--keys", "API_KEY,DB_URL")
	if err != nil {
		t.Fatalf("sync with --keys failed: %s: %v", out, err)
	}

	data, _ := os.ReadFile(filepath.Join(syncDir, ".env"))
	content := string(data)
	if !strings.Contains(content, "API_KEY=") {
		t.Fatal("API_KEY missing from filtered sync")
	}
	if !strings.Contains(content, "DB_URL=") {
		t.Fatal("DB_URL missing from filtered sync")
	}
	if strings.Contains(content, "DEBUG=") {
		t.Fatal("DEBUG should have been filtered out by --keys")
	}
}

func TestCLI_SyncManifestWithKeysFilter(t *testing.T) {
	bin := buildBinary(t)
	vaultDir := t.TempDir()
	runVault(t, bin, vaultDir, "init")

	projectDir := t.TempDir()
	os.WriteFile(filepath.Join(projectDir, ".env"), []byte("SAFE_KEY=ok\nDANGEROUS_TOKEN=nope\n"), 0644)
	runVault(t, bin, vaultDir, "onboard", projectDir)

	// Rewrite manifest with key allowlist
	projectName := filepath.Base(projectDir)
	syncDir := t.TempDir()
	manifest := `{"project":"` + projectName + `","keys":["SAFE_KEY","DANGEROUS_TOKEN"],"sync":{"env":{"dir":"` + syncDir + `","keys":["SAFE_KEY"]}}}`
	os.WriteFile(filepath.Join(projectDir, ".vault.json"), []byte(manifest), 0644)

	out, err := runVault(t, bin, vaultDir, "sync", projectDir)
	if err != nil {
		t.Fatalf("manifest sync failed: %s: %v", out, err)
	}

	data, _ := os.ReadFile(filepath.Join(syncDir, ".env"))
	content := string(data)
	if !strings.Contains(content, "SAFE_KEY=") {
		t.Fatal("SAFE_KEY missing")
	}
	if strings.Contains(content, "DANGEROUS_TOKEN") {
		t.Fatal("DANGEROUS_TOKEN should have been filtered out by manifest keys allowlist")
	}
}
