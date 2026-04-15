package main

import (
	"log"

	"graduation_project/database"
	"graduation_project/dnsserver"
	"graduation_project/routes"

	"github.com/gin-gonic/gin"
)

func main() {
	err := database.InitDB()
	if err != nil {
		log.Fatal("database initialization failed: ", err)
	}

	dnsserver.StartDNSServer()

	r := gin.Default()
	r.LoadHTMLGlob("templates/*.html")

	routes.SetupRoutes(r)

	log.Println("Web server is running at: http://localhost:8080")
	err = r.Run(":8080")
	if err != nil {
		log.Fatal("server failed to start: ", err)
	}
}
