package storage

import "os"

func Open(key string) ([]byte, error) {
	return os.ReadFile(key)
}

func ReadNotice() ([]byte, error) {
	return os.ReadFile("notice.txt")
}
