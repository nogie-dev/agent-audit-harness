package web

import "net/http"

func Register(mux *http.ServeMux) {
	mux.HandleFunc("/selected", Selected)
	mux.HandleFunc("/public", Public)
}
