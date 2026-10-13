package relay

import "audit.example/exporter/storage"

func Fetch(key string) ([]byte, error) {
	return storage.Open(key)
}

func Notice() ([]byte, error) {
	return storage.ReadNotice()
}
