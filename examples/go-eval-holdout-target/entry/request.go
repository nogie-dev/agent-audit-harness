package entry

import (
	"os"

	"audit.example/commandcase/dispatch"
)

func Run() {
	value := os.Getenv("JOB")
	dispatch.Start(value)
}

func Probe() {
	_ = os.Getenv("JOB")
	dispatch.Safe()
}
