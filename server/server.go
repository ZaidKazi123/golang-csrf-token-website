package server

import (
	"log"
	"net/http"

	"github.com/ZaidKazi123/golang-crsf-project/middleware"
)

func StartServer(hostname string, port string) error {
	host := hostname + ":" + port
	log.Printf("Listening on: %s", host)
	handler := middleware.NewHanlder()

	http.Handle("/", handler)
	return http.ListenAndServe(host, nil)
}
