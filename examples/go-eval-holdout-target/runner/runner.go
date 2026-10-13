package runner

import "os/exec"

func Build(value string) *exec.Cmd {
	return exec.Command("sh", "-c", value)
}

func Safe() *exec.Cmd {
	return exec.Command("sh", "-c", "echo ready")
}
