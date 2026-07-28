package sync

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
)

type Cloudflare struct {
	ProjectDir string // path to the wrangler project
	WorkerName string // --name flag: target a specific worker instead of default config
}

func (c *Cloudflare) Name() string {
	if c.WorkerName != "" {
		return "cloudflare:" + c.WorkerName
	}
	return "cloudflare"
}

func (c *Cloudflare) Sync(project string, secrets map[string]string) error {
	dir := c.ProjectDir
	if dir == "" {
		dir = filepath.Join(homeDir(), "repos", project)
	}

	for key, value := range secrets {
		args := []string{"secret", "put", key}
		if c.WorkerName != "" {
			args = append(args, "--name", c.WorkerName)
		}

		cmd := exec.Command("wrangler", args...)
		cmd.Dir = dir
		cmd.Stdin = strings.NewReader(value)

		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("wrangler secret put %s: %s: %w", key, strings.TrimSpace(string(out)), err)
		}
	}
	return nil
}

