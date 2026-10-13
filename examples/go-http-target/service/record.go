package service

import "audit.example/httpcase/store"

func ReadPrivate() string {
	return store.Private()
}
