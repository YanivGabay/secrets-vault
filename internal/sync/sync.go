package sync

import (
	"fmt"
	"log/slog"
	"os"
	"strings"
	gosync "sync"
)

type Target interface {
	Name() string
	Sync(project string, secrets map[string]string) error
}

type Result struct {
	Target string
	Keys   []string
	Err    error
}

// All syncs secrets to multiple targets in parallel using WaitGroup.Go().
func All(project string, secrets map[string]string, targets ...Target) []Result {
	results := make([]Result, len(targets))
	var mu gosync.Mutex
	var wg gosync.WaitGroup

	for i, t := range targets {
		idx, tgt := i, t
		wg.Go(func() {
			slog.Info("syncing", "target", tgt.Name(), "project", project, "keys", len(secrets))
			err := tgt.Sync(project, secrets)

			keys := make([]string, 0, len(secrets))
			for k := range secrets {
				keys = append(keys, k)
			}

			mu.Lock()
			results[idx] = Result{Target: tgt.Name(), Keys: keys, Err: err}
			mu.Unlock()
		})
	}

	wg.Wait()
	return results
}

func homeDir() string {
	home, _ := os.UserHomeDir()
	return home
}

// FilterKeys returns only the secrets whose keys are in the allowlist.
// If allowlist is empty, returns all secrets unchanged.
func FilterKeys(secrets map[string]string, keys []string) map[string]string {
	if len(keys) == 0 {
		return secrets
	}
	allowed := make(map[string]bool, len(keys))
	for _, k := range keys {
		allowed[k] = true
	}
	filtered := make(map[string]string, len(keys))
	for k, v := range secrets {
		if allowed[k] {
			filtered[k] = v
		}
	}
	return filtered
}

func FormatResults(results []Result) string {
	var b strings.Builder
	for _, r := range results {
		if r.Err != nil {
			fmt.Fprintf(&b, "FAIL %s: %v\n", r.Target, r.Err)
		} else {
			fmt.Fprintf(&b, "OK   %s: synced %d keys\n", r.Target, len(r.Keys))
		}
	}
	return b.String()
}
