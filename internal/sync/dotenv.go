package sync

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type DotEnv struct {
	ProjectDir string // path to write .env into
}

func (d *DotEnv) Name() string { return "env" }

func (d *DotEnv) Sync(project string, secrets map[string]string) error {
	dir := d.ProjectDir
	if dir == "" {
		dir = filepath.Join(homeDir(), "repos", project)
	}

	keys := make([]string, 0, len(secrets))
	for k := range secrets {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var b strings.Builder
	for _, k := range keys {
		fmt.Fprintf(&b, "%s=%q\n", k, secrets[k])
	}

	envPath := filepath.Join(dir, ".env")
	if err := os.WriteFile(envPath, []byte(b.String()), 0600); err != nil {
		return fmt.Errorf("write %s: %w", envPath, err)
	}

	return nil
}
