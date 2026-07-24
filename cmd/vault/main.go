package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/yaniv242/secrets-vault/internal/clipboard"
	"github.com/yaniv242/secrets-vault/internal/sync"
	"github.com/yaniv242/secrets-vault/internal/vault"
)

func vaultDir() string {
	if dir := os.Getenv("VAULT_DIR"); dir != "" {
		return dir
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".secrets-vault")
}

func main() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn})))

	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	v := vault.New(vaultDir())

	var err error
	switch os.Args[1] {
	case "init":
		err = cmdInit(v)
	case "add":
		err = cmdAdd(v)
	case "rm", "remove":
		err = cmdRemove(v)
	case "list", "ls":
		err = cmdList(v)
	case "sync":
		err = cmdSync(v)
	case "import":
		err = cmdImport(v)
	case "onboard":
		err = cmdOnboard(v)
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", os.Args[1])
		usage()
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `secrets-vault — encrypted secrets manager

Commands:
  init                          Create a new vault
  add <project> <KEY> [flags]   Add a secret (default: from clipboard)
  rm  <project> <KEY>           Remove a secret
  list [project]                List projects or keys
  sync <project> <target>       Sync to target (github, cloudflare, env)
  import <project> <.env path>  Import secrets from .env file
  onboard [dir]                 Auto-detect .env files, import, create .vault.json

Add flags:
  --stdin                       Read value from stdin pipe
  --prompt                      Prompt for value in terminal (hidden input)`)
}

func cmdInit(v *vault.Vault) error {
	if err := v.Init(); err != nil {
		return err
	}
	fmt.Println("Vault initialized at", vaultDir())
	return nil
}

func cmdAdd(v *vault.Vault) error {
	if len(os.Args) < 4 {
		return fmt.Errorf("usage: vault add <project> <KEY> [--stdin|--prompt]")
	}
	project, key := os.Args[2], os.Args[3]

	var value string
	var err error

	switch {
	case hasFlag("--stdin"):
		data, readErr := io.ReadAll(os.Stdin)
		if readErr != nil {
			return fmt.Errorf("read stdin: %w", readErr)
		}
		value = strings.TrimRight(string(data), "\r\n")
	case hasFlag("--prompt"):
		fmt.Fprintf(os.Stderr, "Enter value for %s: ", key)
		scanner := bufio.NewScanner(os.Stdin)
		if scanner.Scan() {
			value = scanner.Text()
		}
		if scanErr := scanner.Err(); scanErr != nil {
			return fmt.Errorf("read input: %w", scanErr)
		}
	default:
		value, err = clipboard.Read()
		if err != nil {
			return fmt.Errorf("read clipboard: %w", err)
		}
		defer func() {
			if clearErr := clipboard.Clear(); clearErr != nil {
				slog.Warn("failed to clear clipboard", "error", clearErr)
			}
		}()
	}

	if value == "" {
		return fmt.Errorf("empty value")
	}

	if err := v.Add(project, key, value); err != nil {
		return err
	}

	fmt.Printf("Added %s to %s\n", key, project)
	return nil
}

func cmdRemove(v *vault.Vault) error {
	if len(os.Args) < 4 {
		return fmt.Errorf("usage: vault rm <project> <KEY>")
	}
	project, key := os.Args[2], os.Args[3]

	if err := v.Remove(project, key); err != nil {
		return err
	}

	fmt.Printf("Removed %s from %s\n", key, project)
	return nil
}

func cmdList(v *vault.Vault) error {
	if len(os.Args) >= 3 {
		project := os.Args[2]
		keys, err := v.ListKeys(project)
		if err != nil {
			return err
		}
		for _, k := range keys {
			fmt.Println(k)
		}
		return nil
	}

	projects, err := v.Projects()
	if err != nil {
		return err
	}

	if len(projects) == 0 {
		fmt.Println("(empty vault)")
		return nil
	}

	for _, project := range sortedKeys(projects) {
		keys := projects[project]
		fmt.Printf("%s (%d keys)\n", project, len(keys))
		for _, k := range keys {
			fmt.Printf("  %s\n", k)
		}
	}
	return nil
}

func cmdSync(v *vault.Vault) error {
	// If no target specified, try manifest-based sync
	if len(os.Args) < 4 {
		dir := "."
		if len(os.Args) >= 3 {
			dir = os.Args[2]
		}
		absDir, _ := filepath.Abs(dir)
		return cmdSyncFromManifest(v, absDir)
	}
	project, targetName := os.Args[2], os.Args[3]

	secrets, err := v.GetProject(project)
	if err != nil {
		return err
	}

	var target sync.Target
	switch targetName {
	case "github", "gh":
		gh := &sync.GitHub{}
		if repo := flagValue("--repo"); repo != "" {
			gh.Repo = repo
		}
		target = gh
	case "cloudflare", "cf", "wrangler":
		cf := &sync.Cloudflare{}
		if dir := flagValue("--dir"); dir != "" {
			cf.ProjectDir = dir
		}
		target = cf
	case "env", "dotenv":
		de := &sync.DotEnv{}
		if dir := flagValue("--dir"); dir != "" {
			de.ProjectDir = dir
		}
		target = de
	default:
		return fmt.Errorf("unknown target: %s (use: github, cloudflare, env)", targetName)
	}

	results := sync.All(project, secrets, target)
	fmt.Print(sync.FormatResults(results))

	for _, r := range results {
		if r.Err != nil {
			return fmt.Errorf("sync had failures")
		}
	}
	return nil
}

func cmdImport(v *vault.Vault) error {
	if len(os.Args) < 4 {
		return fmt.Errorf("usage: vault import <project> <.env path>")
	}
	project, envPath := os.Args[2], os.Args[3]

	data, err := os.ReadFile(envPath)
	if err != nil {
		return fmt.Errorf("read %s: %w", envPath, err)
	}

	count := 0
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		value = strings.Trim(value, `"'`)

		if err := v.Add(project, key, value); err != nil {
			return fmt.Errorf("add %s: %w", key, err)
		}
		count++
	}

	fmt.Printf("Imported %d keys into %s\n", count, project)
	return nil
}

// Manifest is the .vault.json schema that lives in each project repo.
type Manifest struct {
	Project string            `json:"project"`
	Keys    []string          `json:"keys"`
	Sync    map[string]string `json:"sync,omitempty"` // target → config (e.g. "github": "owner/repo")
}

func cmdOnboard(v *vault.Vault) error {
	dir := "."
	if len(os.Args) >= 3 {
		dir = os.Args[2]
	}

	absDir, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	project := filepath.Base(absDir)

	envFiles := []string{".env", ".env.local", ".env.production", ".env.development", ".dev.vars"}
	var imported []string
	allKeys := map[string]bool{}

	for _, name := range envFiles {
		path := filepath.Join(absDir, name)
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}

		count := 0
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			key, value, ok := strings.Cut(line, "=")
			if !ok {
				continue
			}
			key = strings.TrimSpace(key)
			value = strings.TrimSpace(value)
			value = strings.Trim(value, `"'`)

			if err := v.Add(project, key, value); err != nil {
				return fmt.Errorf("add %s from %s: %w", key, name, err)
			}
			allKeys[key] = true
			count++
		}

		if count > 0 {
			imported = append(imported, fmt.Sprintf("%s (%d keys)", name, count))
		}
	}

	if len(imported) == 0 {
		return fmt.Errorf("no .env files found in %s", absDir)
	}

	// Create .vault.json manifest
	keys := make([]string, 0, len(allKeys))
	for k := range allKeys {
		keys = append(keys, k)
	}
	slices.Sort(keys)

	manifest := Manifest{
		Project: project,
		Keys:    keys,
		Sync:    map[string]string{},
	}

	// Auto-detect sync targets
	if _, err := os.Stat(filepath.Join(absDir, ".github")); err == nil {
		manifest.Sync["github"] = ""
	}
	if _, err := os.Stat(filepath.Join(absDir, "wrangler.toml")); err == nil {
		manifest.Sync["cloudflare"] = ""
	}
	if _, err := os.Stat(filepath.Join(absDir, "wrangler.jsonc")); err == nil {
		manifest.Sync["cloudflare"] = ""
	}

	manifestData, _ := json.MarshalIndent(manifest, "", "  ")
	manifestPath := filepath.Join(absDir, ".vault.json")
	if err := os.WriteFile(manifestPath, manifestData, 0644); err != nil {
		return fmt.Errorf("write .vault.json: %w", err)
	}

	for _, f := range imported {
		fmt.Printf("Imported %s\n", f)
	}
	fmt.Printf("Created %s (project: %s, %d keys)\n", manifestPath, project, len(keys))

	return nil
}

// cmdSync now also supports manifest-based sync (no target arg needed from inside a project).
func cmdSyncFromManifest(v *vault.Vault, absDir string) error {
	data, err := os.ReadFile(filepath.Join(absDir, ".vault.json"))
	if err != nil {
		return fmt.Errorf("no .vault.json found — run 'vault onboard' first or specify a target")
	}

	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return fmt.Errorf("parse .vault.json: %w", err)
	}

	secrets, err := v.GetProject(m.Project)
	if err != nil {
		return err
	}

	var targets []sync.Target
	for targetName, config := range m.Sync {
		switch targetName {
		case "github":
			targets = append(targets, &sync.GitHub{Repo: config})
		case "cloudflare":
			dir := absDir
			if config != "" {
				dir = config
			}
			targets = append(targets, &sync.Cloudflare{ProjectDir: dir})
		case "env":
			dir := absDir
			if config != "" {
				dir = config
			}
			targets = append(targets, &sync.DotEnv{ProjectDir: dir})
		}
	}

	if len(targets) == 0 {
		return fmt.Errorf("no sync targets defined in .vault.json")
	}

	results := sync.All(m.Project, secrets, targets...)
	fmt.Print(sync.FormatResults(results))

	for _, r := range results {
		if r.Err != nil {
			return fmt.Errorf("sync had failures")
		}
	}
	return nil
}

func hasFlag(name string) bool {
	for _, arg := range os.Args {
		if arg == name {
			return true
		}
	}
	return false
}

func flagValue(name string) string {
	for i, arg := range os.Args {
		if arg == name && i+1 < len(os.Args) {
			return os.Args[i+1]
		}
	}
	return ""
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}
