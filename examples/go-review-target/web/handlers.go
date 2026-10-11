package web

import (
	"audit.example/review/model"
	"audit.example/review/service"
	"net/http"
)

func Raw(w http.ResponseWriter, r *http.Request) {
	req := model.Request{Program: r.URL.Query().Get("program")}
	service.Raw(req)
}

func Checked(w http.ResponseWriter, r *http.Request) {
	req := model.Request{Program: r.URL.Query().Get("program")}
	service.Checked(req)
}

var engine service.Engine
var callback func(model.Request)

func Dynamic(w http.ResponseWriter, r *http.Request) {
	req := model.Request{Program: r.URL.Query().Get("program")}
	service.Dynamic(engine, callback, req)
}
