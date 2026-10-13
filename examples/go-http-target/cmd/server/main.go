package main

import (
	"fmt"
	"net"
	"net/http"

	"audit.example/httpcase/web"
)

func main() {
	mux := http.NewServeMux()
	web.Register(mux)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	fmt.Println("LISTEN", listener.Addr().String())
	server := &http.Server{Handler: mux}
	if err := server.Serve(listener); err != nil {
		panic(err)
	}
}
