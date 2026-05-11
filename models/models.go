package models

type DomainRule struct {
	ID       int
	Domain   string
	Category string
	Action   string
}

type AccessLog struct {
	ID        int
	Domain    string
	ClientIP  string
	Action    string
	CreatedAt string
}

type Policy struct {
	ID            int
	TeenMode      int
	DefaultAction string
	AllowedStart  string
	AllowedEnd    string
}

type DNSResult struct {
	Domain string
	Action string
	Reason string
}
type StatsData struct {
	TotalRequests    int
	BlockedRequests  int
	AllowedRequests  int
	TopVisitedDomain string
	TopBlockedDomain string
}

type DNSPageData struct {
	Result        DNSResult
	TeenModeText  string
	DefaultAction string
	AllowedStart  string
	AllowedEnd    string
	CurrentTime   string
	AIScore       int
	AILevel       string
	AIReasons     []string
	VT            VTResult
	VTAlert       string
	VTAlertLevel  string
}

type AIRiskResult struct {
	Score   int
	Level   string
	Reasons []string
}

type VTResult struct {
	Enabled         bool
	Found           bool
	MaliciousCount  int
	SuspiciousCount int
	HarmlessCount   int
	UndetectedCount int
	Reputation      int
	ErrorMessage    string
}
