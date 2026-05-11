package handlers

import (
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"graduation_project/database"
	"graduation_project/models"

	"github.com/gin-gonic/gin"
)

func isLoggedIn(c *gin.Context) bool {
	value, err := c.Cookie("auth")
	return err == nil && value == "1"
}

func requireLogin(c *gin.Context) bool {
	if !isLoggedIn(c) {
		c.Redirect(http.StatusFound, "/login")
		c.Abort()
		return false
	}
	return true
}

func HomePage(c *gin.Context) {
	c.HTML(http.StatusOK, "index.html", gin.H{
		"title":   "智能DNS网络保护系统",
		"message": "项目初始化成功，服务正在运行。",
	})
}

func LoginPage(c *gin.Context) {
	c.HTML(http.StatusOK, "login.html", gin.H{
		"title": "管理员登录",
		"error": "",
	})
}

func DashboardPage(c *gin.Context) {
	if !requireLogin(c) {
		return
	}
	c.HTML(http.StatusOK, "dashboard.html", gin.H{
		"title": "系统后台首页",
	})
}

func RulesPage(c *gin.Context) {
	if !requireLogin(c) {
		return
	}
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
	if !requireLogin(c) {
		return
	}

	filterAction := strings.TrimSpace(c.Query("action"))

	var (
		rows *sql.Rows
		err  error
	)

	if filterAction == "allow" || filterAction == "block" {
		rows, err = database.DB.Query(
			"SELECT id, domain, client_ip, action, created_at FROM access_logs WHERE action = ? ORDER BY id DESC",
			filterAction,
		)
	} else {
		filterAction = "all"
		rows, err = database.DB.Query(
			"SELECT id, domain, client_ip, action, created_at FROM access_logs ORDER BY id DESC",
		)
	}

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
		"title":        "访问日志",
		"logs":         logs,
		"filterAction": filterAction,
	})
}
func SimulateAccess(c *gin.Context) {
	domain := strings.TrimSpace(c.PostForm("domain"))
	if domain == "" {
		c.String(http.StatusBadRequest, "domain is required")
		return
	}

	action := "allow"

	var policy models.Policy
	err := database.DB.QueryRow(
		"SELECT id, teen_mode, default_action, allowed_start, allowed_end FROM policies LIMIT 1",
	).Scan(&policy.ID, &policy.TeenMode, &policy.DefaultAction, &policy.AllowedStart, &policy.AllowedEnd)

	if err == nil && strings.TrimSpace(policy.DefaultAction) != "" {
		action = policy.DefaultAction
	}

	ruleMatched := false

	var ruleAction string
	err = database.DB.QueryRow(
		"SELECT action FROM domain_rules WHERE domain = ? LIMIT 1",
		domain,
	).Scan(&ruleAction)

	if err == nil {
		action = ruleAction
		ruleMatched = true
	} else if err != sql.ErrNoRows {
		c.String(http.StatusInternalServerError, "Failed to check rule: %v", err)
		return
	}

	if policy.TeenMode == 1 {
		now := time.Now().Format("15:04")
		inAllowedTime := now >= policy.AllowedStart && now <= policy.AllowedEnd

		if !inAllowedTime {
			// 不在允许时间内时，只有显式 allow 的域名放行，其余一律 block
			if !(ruleMatched && action == "allow") {
				action = "block"
			}
		}
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
	if !requireLogin(c) {
		return
	}
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

func DNSCheck(c *gin.Context) {
	if !requireLogin(c) {
		return
	}

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
	} else if err != nil {
		c.String(http.StatusInternalServerError, "Failed to query policy: %v", err)
		return
	}

	ruleMatched := false

	var ruleAction string
	var category string
	err = database.DB.QueryRow(
		"SELECT action, category FROM domain_rules WHERE domain = ? LIMIT 1",
		domain,
	).Scan(&ruleAction, &category)

	if err == nil {
		action = ruleAction
		reason = "matched domain rule"
		ruleMatched = true
	} else if err != sql.ErrNoRows {
		c.String(http.StatusInternalServerError, "Failed to check domain rule: %v", err)
		return
	}

	aiResult := analyzeDomainRisk(domain)
	if !ruleMatched && aiResult.Level == "high" {
		action = "block"
		reason = "AI risk detection"
	}

	vtResult := queryVirusTotal(domain)

	if !ruleMatched && vtResult.Enabled && vtResult.MaliciousCount > 0 {
		action = "block"
		reason = "external threat intelligence"
	}

	if policy.TeenMode == 1 {
		now := time.Now().Format("15:04")
		inAllowedTime := now >= policy.AllowedStart && now <= policy.AllowedEnd

		if !inAllowedTime {
			if !(ruleMatched && action == "allow") {
				action = "block"
				reason = "blocked by time policy"
			}
		}
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

	teenModeText := "关闭"
	if policy.TeenMode == 1 {
		teenModeText = "开启"
	}

	vtAlert := "未命中外部威胁情报"
	vtAlertLevel := "normal"

	if vtResult.Enabled {
		if vtResult.MaliciousCount > 0 {
			vtAlert = "VirusTotal 检测到恶意命中"
			vtAlertLevel = "danger"
		} else if vtResult.SuspiciousCount > 0 {
			vtAlert = "VirusTotal 检测到可疑命中"
			vtAlertLevel = "warning"
		} else if vtResult.ErrorMessage != "" {
			vtAlert = "VirusTotal 查询异常"
			vtAlertLevel = "warning"
		} else {
			vtAlert = "VirusTotal 未发现明显恶意命中"
			vtAlertLevel = "normal"
		}
	} else if vtResult.ErrorMessage != "" {
		vtAlert = "VirusTotal 未启用"
		vtAlertLevel = "warning"
	}

	pageData := models.DNSPageData{
		Result:        result,
		TeenModeText:  teenModeText,
		DefaultAction: policy.DefaultAction,
		AllowedStart:  policy.AllowedStart,
		AllowedEnd:    policy.AllowedEnd,
		CurrentTime:   time.Now().Format("15:04"),
		AIScore:       aiResult.Score,
		AILevel:       aiResult.Level,
		AIReasons:     aiResult.Reasons,
		VT:            vtResult,
		VTAlert:       vtAlert,
		VTAlertLevel:  vtAlertLevel,
	}

	c.HTML(http.StatusOK, "dns_test.html", gin.H{
		"title":    "DNS 请求测试",
		"result":   result,
		"pageData": pageData,
	})
}

func queryVirusTotal(domain string) models.VTResult {
	apiKey := strings.TrimSpace(os.Getenv("VT_API_KEY"))
	if apiKey == "" {
		return models.VTResult{
			Enabled:      false,
			ErrorMessage: "VT_API_KEY not set",
		}
	}

	endpoint := "https://www.virustotal.com/api/v3/domains/" + url.PathEscape(domain)

	req, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		return models.VTResult{
			Enabled:      true,
			ErrorMessage: err.Error(),
		}
	}

	req.Header.Set("x-apikey", apiKey)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return models.VTResult{
			Enabled:      true,
			ErrorMessage: err.Error(),
		}
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return models.VTResult{
			Enabled:      true,
			ErrorMessage: err.Error(),
		}
	}

	if resp.StatusCode != http.StatusOK {
		return models.VTResult{
			Enabled:      true,
			ErrorMessage: "VirusTotal API returned status " + resp.Status,
		}
	}

	var vtResp struct {
		Data struct {
			Attributes struct {
				Reputation        int `json:"reputation"`
				LastAnalysisStats struct {
					Malicious  int `json:"malicious"`
					Suspicious int `json:"suspicious"`
					Harmless   int `json:"harmless"`
					Undetected int `json:"undetected"`
				} `json:"last_analysis_stats"`
			} `json:"attributes"`
		} `json:"data"`
	}

	err = json.Unmarshal(body, &vtResp)
	if err != nil {
		return models.VTResult{
			Enabled:      true,
			ErrorMessage: err.Error(),
		}
	}

	return models.VTResult{
		Enabled:         true,
		Found:           true,
		MaliciousCount:  vtResp.Data.Attributes.LastAnalysisStats.Malicious,
		SuspiciousCount: vtResp.Data.Attributes.LastAnalysisStats.Suspicious,
		HarmlessCount:   vtResp.Data.Attributes.LastAnalysisStats.Harmless,
		UndetectedCount: vtResp.Data.Attributes.LastAnalysisStats.Undetected,
		Reputation:      vtResp.Data.Attributes.Reputation,
	}
}

func DNSServicePage(c *gin.Context) {
	if !requireLogin(c) {
		return
	}
	c.HTML(http.StatusOK, "dns_service.html", gin.H{
		"title": "DNS 服务状态",
	})
}
func EditRulePage(c *gin.Context) {
	if !requireLogin(c) {
		return
	}
	idStr := c.Param("id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		c.String(http.StatusBadRequest, "invalid rule id")
		return
	}

	var rule models.DomainRule
	err = database.DB.QueryRow(
		"SELECT id, domain, category, action FROM domain_rules WHERE id = ?",
		id,
	).Scan(&rule.ID, &rule.Domain, &rule.Category, &rule.Action)

	if err != nil {
		c.String(http.StatusInternalServerError, "Failed to query rule: %v", err)
		return
	}

	c.HTML(http.StatusOK, "edit_rule.html", gin.H{
		"title": "编辑规则",
		"rule":  rule,
	})
}

func UpdateRule(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		c.String(http.StatusBadRequest, "invalid rule id")
		return
	}

	domain := strings.TrimSpace(c.PostForm("domain"))
	category := strings.TrimSpace(c.PostForm("category"))
	action := strings.TrimSpace(c.PostForm("action"))

	if domain == "" || action == "" {
		c.String(http.StatusBadRequest, "domain and action are required")
		return
	}

	_, err = database.DB.Exec(
		"UPDATE domain_rules SET domain = ?, category = ?, action = ? WHERE id = ?",
		domain, category, action, id,
	)
	if err != nil {
		c.String(http.StatusInternalServerError, "Failed to update rule: %v", err)
		return
	}

	c.Redirect(http.StatusFound, "/rules")
}
func StatsPage(c *gin.Context) {
	if !requireLogin(c) {
		return
	}
	var stats models.StatsData

	err := database.DB.QueryRow("SELECT COUNT(*) FROM access_logs").Scan(&stats.TotalRequests)
	if err != nil {
		c.String(http.StatusInternalServerError, "Failed to query total requests: %v", err)
		return
	}

	err = database.DB.QueryRow("SELECT COUNT(*) FROM access_logs WHERE action = 'block'").Scan(&stats.BlockedRequests)
	if err != nil {
		c.String(http.StatusInternalServerError, "Failed to query blocked requests: %v", err)
		return
	}

	err = database.DB.QueryRow("SELECT COUNT(*) FROM access_logs WHERE action = 'allow'").Scan(&stats.AllowedRequests)
	if err != nil {
		c.String(http.StatusInternalServerError, "Failed to query allowed requests: %v", err)
		return
	}

	err = database.DB.QueryRow(`
		SELECT domain
		FROM access_logs
		GROUP BY domain
		ORDER BY COUNT(*) DESC
		LIMIT 1
	`).Scan(&stats.TopVisitedDomain)
	if err != nil && err != sql.ErrNoRows {
		c.String(http.StatusInternalServerError, "Failed to query top visited domain: %v", err)
		return
	}

	err = database.DB.QueryRow(`
		SELECT domain
		FROM access_logs
		WHERE action = 'block'
		GROUP BY domain
		ORDER BY COUNT(*) DESC
		LIMIT 1
	`).Scan(&stats.TopBlockedDomain)
	if err != nil && err != sql.ErrNoRows {
		c.String(http.StatusInternalServerError, "Failed to query top blocked domain: %v", err)
		return
	}

	c.HTML(http.StatusOK, "stats.html", gin.H{
		"title": "统计分析",
		"stats": stats,
	})
}

func LoginSubmit(c *gin.Context) {
	username := strings.TrimSpace(c.PostForm("username"))
	password := strings.TrimSpace(c.PostForm("password"))

	var dbPassword string
	err := database.DB.QueryRow(
		"SELECT password FROM users WHERE username = ? LIMIT 1",
		username,
	).Scan(&dbPassword)

	if err != nil || dbPassword != password {
		c.HTML(http.StatusOK, "login.html", gin.H{
			"title": "管理员登录",
			"error": "用户名或密码错误",
		})
		return
	}

	c.SetCookie("auth", "1", 3600, "/", "", false, true)
	c.Redirect(http.StatusFound, "/dashboard")
}

func Logout(c *gin.Context) {
	c.SetCookie("auth", "", -1, "/", "", false, true)
	c.Redirect(http.StatusFound, "/login")
}

func countDigits(s string) int {
	count := 0
	for _, ch := range s {
		if ch >= '0' && ch <= '9' {
			count++
		}
	}
	return count
}

func DNSTestPage(c *gin.Context) {
	if !requireLogin(c) {
		return
	}

	var policy models.Policy
	err := database.DB.QueryRow(
		"SELECT id, teen_mode, default_action, allowed_start, allowed_end FROM policies LIMIT 1",
	).Scan(&policy.ID, &policy.TeenMode, &policy.DefaultAction, &policy.AllowedStart, &policy.AllowedEnd)

	if err != nil {
		c.String(http.StatusInternalServerError, "Failed to query policy: %v", err)
		return
	}

	teenModeText := "关闭"
	if policy.TeenMode == 1 {
		teenModeText = "开启"
	}

	pageData := models.DNSPageData{
		TeenModeText:  teenModeText,
		DefaultAction: policy.DefaultAction,
		AllowedStart:  policy.AllowedStart,
		AllowedEnd:    policy.AllowedEnd,
		CurrentTime:   time.Now().Format("15:04"),
		AIScore:       0,
		AILevel:       "low",
		AIReasons:     []string{},
		VT: models.VTResult{
			Enabled: false,
		},
	}

	c.HTML(http.StatusOK, "dns_test.html", gin.H{
		"title":    "DNS 请求测试",
		"pageData": pageData,
	})
}

func analyzeDomainRisk(domain string) models.AIRiskResult {
	domain = strings.ToLower(strings.TrimSpace(domain))

	score := 0
	var reasons []string

	if strings.Contains(domain, "bet") {
		score += 40
		reasons = append(reasons, "keyword: bet")
	}
	if strings.Contains(domain, "casino") {
		score += 40
		reasons = append(reasons, "keyword: casino")
	}
	if strings.Contains(domain, "adult") {
		score += 50
		reasons = append(reasons, "keyword: adult")
	}
	if strings.Contains(domain, "porn") {
		score += 50
		reasons = append(reasons, "keyword: porn")
	}
	if strings.Contains(domain, "game") {
		score += 20
		reasons = append(reasons, "keyword: game")
	}

	if len(domain) > 25 {
		score += 10
		reasons = append(reasons, "long domain length")
	}

	if countDigits(domain) >= 4 {
		score += 10
		reasons = append(reasons, "contains many digits")
	}

	if strings.Count(domain, "-") >= 2 {
		score += 10
		reasons = append(reasons, "contains multiple hyphens")
	}

	level := "low"
	if score >= 60 {
		level = "high"
	} else if score >= 30 {
		level = "medium"
	}

	return models.AIRiskResult{
		Score:   score,
		Level:   level,
		Reasons: reasons,
	}
}
