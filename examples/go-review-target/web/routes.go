package web

import "net/http"

func Register() {
	http.HandleFunc("/raw", Raw)
	http.HandleFunc("/checked", Checked)
	http.HandleFunc("/dynamic", Dynamic)
}
