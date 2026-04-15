package handlers

import (
	"database/sql"
	"net/http"
	"strconv"
	"strings"

	"graduation_project/database"
	"graduation_project/models"

	"github.com/gin-gonic/gin"
)

func HomePage(c *gin.Context) {
	c.HTML(http.StatusOK, "index.html", gin.H{
		"title":   "智能DNS网络保护系统",
		"message": "项目初始化成功，服务正在运行。",
	})
}

func LoginPage(c *gin.Context) {
	c.HTML(http.StatusOK, "login.html", gin.H{
		"title": "管理员登录",
	})
}

func DashboardPage(c *gin.Context) {
	c.HTML(http.StatusOK, "dashboard.html", gin.H{
		"title": "系统后台首页",
	})
}

func RulesPage(c *gin.Context) {
	rows, err := database.DB.Query("SELECT id, domain, category, action FROM domain_rules ORDER BY id ASC")
	if err != nil {
		c.String(http.StatusInternalServerError, "Failed to query rules: %v", err)
		return
	}
	defer rows.Close()

	var rules []models.DomainRule

	for rows.Next() {
		var rule models.DomainRule
		err := rows.Scan(&rule.ID, &rule.Domain, &rule.Category, &rule.Action)
		if err != nil {
			c.String(http.StatusInternalServerError, "Failed to scan rule: %v", err)
			return
		}
		rules = append(rules, rule)
	}

	c.HTML(http.StatusOK, "rules.html", gin.H{
		"title": "规则管理",
		"rules": rules,
	})
}

func AddRule(c *gin.Context) {
	domain := strings.TrimSpace(c.PostForm("domain"))
	category := strings.TrimSpace(c.PostForm("category"))
	action := strings.TrimSpace(c.PostForm("action"))

	if domain == "" || action == "" {
		c.String(http.StatusBadRequest, "domain and action are required")
		return
	}

	_, err := database.DB.Exec(
		"INSERT INTO domain_rules (domain, category, action) VALUES (?, ?, ?)",
		domain, category, action,
	)
	if err != nil {
		c.String(http.StatusInternalServerError, "Failed to insert rule: %v", err)
		return
	}

	c.Redirect(http.StatusFound, "/rules")
}

func DeleteRule(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		c.String(http.StatusBadRequest, "invalid rule id")
		return
	}

	_, err = database.DB.Exec("DELETE FROM domain_rules WHERE id = ?", id)
	if err != nil {
		c.String(http.StatusInternalServerError, "Failed to delete rule: %v", err)
		return
	}

	c.Redirect(http.StatusFound, "/rules")
}

func LogsPage(c *gin.Context) {
	rows, err := database.DB.Query("SELECT id, domain, client_ip, action, created_at FROM access_logs ORDER BY id DESC")
	if err != nil {
		c.String(http.StatusInternalServerError, "Failed to query logs: %v", err)
		return
	}
	defer rows.Close()

	var logs []models.AccessLog

	for rows.Next() {
		var logItem models.AccessLog
		err := rows.Scan(&logItem.ID, &logItem.Domain, &logItem.ClientIP, &logItem.Action, &logItem.CreatedAt)
		if err != nil {
			c.String(http.StatusInternalServerError, "Failed to scan log: %v", err)
			return
		}
		logs = append(logs, logItem)
	}

	c.HTML(http.StatusOK, "logs.html", gin.H{
		"title": "访问日志",
		"logs":  logs,
	})
}

func SimulateAccess(c *gin.Context) {
	domain := strings.TrimSpace(c.PostForm("domain"))
	if domain == "" {
		c.String(http.StatusBadRequest, "domain is required")
		return
	}

	action := "allow"

	var defaultAction string
	err := database.DB.QueryRow(
		"SELECT default_action FROM policies LIMIT 1",
	).Scan(&defaultAction)
	if err == nil && strings.TrimSpace(defaultAction) != "" {
		action = defaultAction
	}

	var ruleAction string
	err = database.DB.QueryRow(
		"SELECT action FROM domain_rules WHERE domain = ? LIMIT 1",
		domain,
	).Scan(&ruleAction)

	if err == nil {
		action = ruleAction
	} else if err != sql.ErrNoRows {
		c.String(http.StatusInternalServerError, "Failed to check rule: %v", err)
		return
	}

	clientIP := c.ClientIP()
	if clientIP == "" {
		clientIP = "127.0.0.1"
	}

	_, err = database.DB.Exec(
		"INSERT INTO access_logs (domain, client_ip, action) VALUES (?, ?, ?)",
		domain, clientIP, action,
	)
	if err != nil {
		c.String(http.StatusInternalServerError, "Failed to insert log: %v", err)
		return
	}

	c.Redirect(http.StatusFound, "/logs")
}

func PolicyPage(c *gin.Context) {
	var policy models.Policy

	err := database.DB.QueryRow(
		"SELECT id, teen_mode, default_action, allowed_start, allowed_end FROM policies LIMIT 1",
	).Scan(&policy.ID, &policy.TeenMode, &policy.DefaultAction, &policy.AllowedStart, &policy.AllowedEnd)

	if err != nil {
		c.String(http.StatusInternalServerError, "Failed to query policy: %v", err)
		return
	}

	c.HTML(http.StatusOK, "policy.html", gin.H{
		"title":  "策略配置",
		"policy": policy,
	})
}

func UpdatePolicy(c *gin.Context) {
	teenMode := c.PostForm("teen_mode")
	defaultAction := strings.TrimSpace(c.PostForm("default_action"))
	allowedStart := strings.TrimSpace(c.PostForm("allowed_start"))
	allowedEnd := strings.TrimSpace(c.PostForm("allowed_end"))

	teenModeValue := 0
	if teenMode == "1" {
		teenModeValue = 1
	}

	_, err := database.DB.Exec(
		"UPDATE policies SET teen_mode = ?, default_action = ?, allowed_start = ?, allowed_end = ? WHERE id = 1",
		teenModeValue, defaultAction, allowedStart, allowedEnd,
	)
	if err != nil {
		c.String(http.StatusInternalServerError, "Failed to update policy: %v", err)
		return
	}

	c.Redirect(http.StatusFound, "/policy")
}

func DNSTestPage(c *gin.Context) {
	c.HTML(http.StatusOK, "dns_test.html", gin.H{
		"title": "DNS 请求测试",
	})
}

func DNSCheck(c *gin.Context) {
	domain := strings.TrimSpace(c.PostForm("domain"))
	if domain == "" {
		c.String(http.StatusBadRequest, "domain is required")
		return
	}

	action := "allow"
	reason := "matched default policy"

	var policy models.Policy
	err := database.DB.QueryRow(
		"SELECT id, teen_mode, default_action, allowed_start, allowed_end FROM policies LIMIT 1",
	).Scan(&policy.ID, &policy.TeenMode, &policy.DefaultAction, &policy.AllowedStart, &policy.AllowedEnd)

	if err == nil && strings.TrimSpace(policy.DefaultAction) != "" {
		action = policy.DefaultAction
		reason = "matched default policy"
	}

	var ruleAction string
	var category string
	err = database.DB.QueryRow(
		"SELECT action, category FROM domain_rules WHERE domain = ? LIMIT 1",
		domain,
	).Scan(&ruleAction, &category)

	if err == nil {
		action = ruleAction
		reason = "matched domain rule"
	} else if err != sql.ErrNoRows {
		c.String(http.StatusInternalServerError, "Failed to check domain rule: %v", err)
		return
	}

	clientIP := c.ClientIP()
	if clientIP == "" {
		clientIP = "127.0.0.1"
	}

	_, err = database.DB.Exec(
		"INSERT INTO access_logs (domain, client_ip, action) VALUES (?, ?, ?)",
		domain, clientIP, action,
	)
	if err != nil {
		c.String(http.StatusInternalServerError, "Failed to write access log: %v", err)
		return
	}

	result := models.DNSResult{
		Domain: domain,
		Action: action,
		Reason: reason,
	}

	c.HTML(http.StatusOK, "dns_test.html", gin.H{
		"title":  "DNS 请求测试",
		"result": result,
	})
}

func DNSServicePage(c *gin.Context) {
	c.HTML(http.StatusOK, "dns_service.html", gin.H{
		"title": "DNS 服务状态",
	})
}
