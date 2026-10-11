package app

import "audit.example/graph/shared"

func stage(value string) string { return shared.Normalize(value) }

type Runner interface{ Run(string) string }

func Dynamic(r Runner, callback func(string) string, value string) string {
	return callback(r.Run(value))
}
