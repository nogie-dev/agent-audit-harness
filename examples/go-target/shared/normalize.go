package shared

func Normalize(value string) string { return value }

func Recurse(n int) int {
	if n > 0 {
		return Recurse(n - 1)
	}
	return n
}
