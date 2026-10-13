package client

import (
	"audit.example/models/command"
	"audit.example/models/protocol"
)

func Entry() {
	value := protocol.ReadField()
	command.Send(value)
}

func Constant() {
	_ = protocol.ReadField()
	command.Send("constant")
}

func Unknown(callback func(string) string) {
	value := protocol.ReadField()
	command.Send(callback(value))
}
