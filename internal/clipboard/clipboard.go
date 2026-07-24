package clipboard

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

func isWSL() bool {
	data, err := os.ReadFile("/proc/version")
	if err != nil {
		return false
	}
	lower := strings.ToLower(string(data))
	return strings.Contains(lower, "microsoft") || strings.Contains(lower, "wsl")
}

func Read() (string, error) {
	var cmd *exec.Cmd

	switch {
	case isWSL():
		cmd = exec.Command("powershell.exe", "-NoProfile", "-Command", "Get-Clipboard")
	case runtime.GOOS == "darwin":
		cmd = exec.Command("pbpaste")
	default:
		cmd = exec.Command("xclip", "-selection", "clipboard", "-o")
	}

	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("read clipboard: %w", err)
	}

	return strings.TrimRight(string(out), "\r\n"), nil
}

func Clear() error {
	var cmd *exec.Cmd

	switch {
	case isWSL():
		cmd = exec.Command("powershell.exe", "-NoProfile", "-Command", "Set-Clipboard -Value $null")
	case runtime.GOOS == "darwin":
		cmd = exec.Command("pbcopy")
		cmd.Stdin = strings.NewReader("")
	default:
		cmd = exec.Command("xclip", "-selection", "clipboard", "-i")
		cmd.Stdin = strings.NewReader("")
	}

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("clear clipboard: %w", err)
	}
	return nil
}
