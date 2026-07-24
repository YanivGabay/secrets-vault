package sync

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
)

type Cloudflare struct {
	ProjectDir string // path to the wrangler project
}

func (c *Cloudflare) Name() string { return "cloudflare" }

func (c *Cloudflare) Sync(project string, secrets map[string]string) error {
	dir := c.ProjectDir
	if dir == "" {
		dir = filepath.Join(homeDir(), "repos", project)
	}

	for key, value := range secrets {
		cmd := exec.Command("wrangler", "secret", "put", key)
		cmd.Dir = dir
		cmd.Stdin = strings.NewReader(value)

		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("wrangler secret put %s: %s: %w", key, strings.TrimSpace(string(out)), err)
		}
	}
	return nil
}

