package web

import "net/http"

func Register(mux *http.ServeMux) {
	mux.HandleFunc("/private", Private)
}
