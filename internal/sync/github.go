package sync

import (
	"fmt"
	"os/exec"
	"strings"
)

type GitHub struct {
	Repo string // owner/repo or empty for current directory's repo
}

func (g *GitHub) Name() string { return "github" }

func (g *GitHub) Sync(project string, secrets map[string]string) error {
	for key, value := range secrets {
		args := []string{"secret", "set", key, "--body", "-"}
		if g.Repo != "" {
			args = append(args, "--repo", g.Repo)
		}

		cmd := exec.Command("gh", args...)
		cmd.Stdin = strings.NewReader(value)

		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("gh secret set %s: %s: %w", key, strings.TrimSpace(string(out)), err)
		}
	}
	return nil
}
