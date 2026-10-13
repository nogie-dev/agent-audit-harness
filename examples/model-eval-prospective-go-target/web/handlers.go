package web

import (
	"net/http"

	"audit.example/preview/store"
)

func Selected(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	data, err := store.ReadSelected(name)
	if err == nil {
		_, _ = w.Write(data)
	}
}

func Public(w http.ResponseWriter, r *http.Request) {
	_ = r.URL.Query().Get("name")
	data, err := store.ReadPublic()
	if err == nil {
		_, _ = w.Write(data)
	}
}
