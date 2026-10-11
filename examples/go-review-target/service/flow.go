package service

import (
	"audit.example/review/model"
	"audit.example/review/runner"
)

func Raw(req model.Request) {
	runner.Execute(req.Program)
}

func Checked(req model.Request) {
	if !allowed(req.Program) {
		return
	}
	runner.Execute(req.Program)
}

func allowed(program string) bool {
	return program == "date"
}

type Engine interface {
	Run(model.Request)
}

func Dynamic(engine Engine, callback func(model.Request), req model.Request) {
	engine.Run(req)
	callback(req)
}
