package protocol

import "os"

func ReadField() string { return os.Getenv("AUDIT_REQUEST") }
