package web

import (
	"fmt"
	"net/http"

	"audit.example/httpcase/service"
)

func Private(w http.ResponseWriter, r *http.Request) {
	fmt.Println("ENTRY HTTP /private")
	fmt.Fprintln(w, service.ReadPrivate())
}
