package routes

import (
	"graduation_project/handlers"

	"github.com/gin-gonic/gin"
)

func SetupRoutes(r *gin.Engine) {
	r.GET("/", handlers.HomePage)
	r.GET("/login", handlers.LoginPage)
	r.GET("/dashboard", handlers.DashboardPage)

	r.GET("/rules", handlers.RulesPage)
	r.POST("/rules/add", handlers.AddRule)
	r.POST("/rules/delete/:id", handlers.DeleteRule)

	r.GET("/logs", handlers.LogsPage)
	r.POST("/logs/simulate", handlers.SimulateAccess)

	r.GET("/policy", handlers.PolicyPage)
	r.POST("/policy/update", handlers.UpdatePolicy)

	r.GET("/dns-test", handlers.DNSTestPage)
	r.POST("/dns-test/check", handlers.DNSCheck)

	r.GET("/dns-service", handlers.DNSServicePage)
}
