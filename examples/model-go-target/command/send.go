package command

import "os/exec"

func Send(value string) { _ = exec.Command("sh", "-c", value) }
