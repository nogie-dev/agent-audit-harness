package web

import "net/http"

func Register(mux *http.ServeMux) {
	mux.HandleFunc("/download", Download)
	mux.HandleFunc("/notice", Notice)
}
