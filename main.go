package main

import (
	"log"

	"github.com/ZaidKazi123/golang-csrf-project/db"
	"github.com/ZaidKazi123/golang-csrf-project/server"
	"github.com/ZaidKazi123/golang-csrf-project/server/middleware/myJwt"
)

var host = "localhost"
var port = "9000"

func main() {
	db.InitDB()

	jwtErr := myJwt.InitJWT()
	if jwtErr != nil {
		log.Println("Error initiliazing the JWT!")
		log.Fatal(jwtErr)
	}

	serverErr := server.StartServer(host, port)
	if serverErr != nil {
		log.Println("Error starting the server")
		log.Fatal(serverErr)
	}
}
