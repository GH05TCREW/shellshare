package terminal

import (
	"os"
	"runtime"
)

// Runner launches an interactive shell and mirrors input/output through the provided channels.
type Runner struct {
	Command string
	Args    []string
}

// DefaultRunner picks a sensible shell for the current platform.
func DefaultRunner() Runner {
	if runtime.GOOS == "windows" {
		cmd := os.Getenv("COMSPEC")
		if cmd == "" {
			cmd = "cmd.exe"
		}
		return Runner{Command: cmd, Args: []string{"/K"}}
	}
	cmd := os.Getenv("SHELL")
	if cmd == "" {
		cmd = "sh"
	}
	return Runner{Command: cmd}
}
