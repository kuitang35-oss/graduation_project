package dnsserver

import (
	"database/sql"
	"fmt"
	"log"
	"strings"

	"graduation_project/database"

	"github.com/miekg/dns"
)

func StartDNSServer() {
	dns.HandleFunc(".", handleDNSRequest)

	server := &dns.Server{
		Addr: "127.0.0.1:5354",
		Net:  "udp",
	}

	go func() {
		log.Println("DNS server is running at: 127.0.0.1:5354")
		if err := server.ListenAndServe(); err != nil {
			log.Println("DNS server failed to start:", err)
		}
	}()
}

func handleDNSRequest(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true

	if len(r.Question) == 0 {
		_ = w.WriteMsg(m)
		return
	}

	q := r.Question[0]
	domain := strings.TrimSuffix(strings.ToLower(q.Name), ".")

	action, err := decideAction(domain)
	if err != nil {
		log.Println("failed to decide action:", err)
		_ = w.WriteMsg(m)
		return
	}

	clientIP := ""
	if w.RemoteAddr() != nil {
		clientIP = w.RemoteAddr().String()
	}

	if action == "block" {
		if q.Qtype == dns.TypeA {
			rr, err := dns.NewRR(fmt.Sprintf("%s 60 IN A 0.0.0.0", dns.Fqdn(domain)))
			if err == nil {
				m.Answer = append(m.Answer, rr)
			}
		}
		_ = writeAccessLog(domain, clientIP, "block")
		_ = w.WriteMsg(m)
		return
	}

	resp, err := forwardToUpstream(r)
	if err != nil {
		log.Println("failed to forward dns request:", err)
		_ = writeAccessLog(domain, clientIP, "allow")
		_ = w.WriteMsg(m)
		return
	}

	_ = writeAccessLog(domain, clientIP, "allow")
	_ = w.WriteMsg(resp)
}

func decideAction(domain string) (string, error) {
	action := "allow"

	var defaultAction string
	err := database.DB.QueryRow(
		"SELECT default_action FROM policies LIMIT 1",
	).Scan(&defaultAction)

	if err == nil && strings.TrimSpace(defaultAction) != "" {
		action = strings.TrimSpace(defaultAction)
	} else if err != nil && err != sql.ErrNoRows {
		return "", err
	}

	var ruleAction string
	err = database.DB.QueryRow(
		"SELECT action FROM domain_rules WHERE lower(domain) = lower(?) LIMIT 1",
		domain,
	).Scan(&ruleAction)

	if err == nil && strings.TrimSpace(ruleAction) != "" {
		action = strings.TrimSpace(ruleAction)
	} else if err != nil && err != sql.ErrNoRows {
		return "", err
	}

	return action, nil
}

func forwardToUpstream(r *dns.Msg) (*dns.Msg, error) {
	client := new(dns.Client)
	resp, _, err := client.Exchange(r, "8.8.8.8:53")
	return resp, err
}

func writeAccessLog(domain, clientIP, action string) error {
	_, err := database.DB.Exec(
		"INSERT INTO access_logs (domain, client_ip, action) VALUES (?, ?, ?)",
		domain, clientIP, action,
	)
	return err
}
