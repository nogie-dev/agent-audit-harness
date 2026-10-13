package dispatch

import "audit.example/commandcase/runner"

func Start(value string) {
	_ = runner.Build(value)
}

func Safe() {
	_ = runner.Safe()
}
