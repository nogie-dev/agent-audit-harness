package store

import "os"

func ReadSelected(name string) ([]byte, error) {
	return os.ReadFile(name)
}

func ReadPublic() ([]byte, error) {
	return os.ReadFile("public.txt")
}
