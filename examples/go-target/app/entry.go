package app

import decode "audit.example/graph/parser"

func Entry(value string) string { return stage(decode.Parse(value)) }
