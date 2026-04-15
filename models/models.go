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
