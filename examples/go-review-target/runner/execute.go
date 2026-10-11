package runner

import "os/exec"

func Execute(program string) {
	_ = exec.Command(program).Run()
}
