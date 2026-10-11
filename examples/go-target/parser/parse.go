package parser

import "audit.example/graph/shared"

type Decoder struct{}

func (Decoder) Run(value string) string { return shared.Normalize(value) }

func Parse(value string) string { return (Decoder{}).Run(value) }
