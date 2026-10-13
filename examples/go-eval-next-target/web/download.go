package web

import (
	"net/http"

	"audit.example/exporter/relay"
)

func Download(w http.ResponseWriter, r *http.Request) {
	key := r.URL.Query().Get("asset")
	body, err := relay.Fetch(key)
	if err != nil {
		http.Error(w, "unavailable", http.StatusNotFound)
		return
	}
	_, _ = w.Write(body)
}

func Notice(w http.ResponseWriter, r *http.Request) {
	_ = r.URL.Query().Get("asset")
	body, err := relay.Notice()
	if err != nil {
		http.Error(w, "unavailable", http.StatusNotFound)
		return
	}
	_, _ = w.Write(body)
}
