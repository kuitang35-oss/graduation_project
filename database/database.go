package database

import (
	"database/sql"

	_ "modernc.org/sqlite"
)

var DB *sql.DB

func InitDB() error {
	var err error

	DB, err = sql.Open("sqlite", "./data/app.db")
	if err != nil {
		return err
	}

	createUsersTable := `
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT NOT NULL UNIQUE,
		password TEXT NOT NULL
	);
	`

	createDomainRulesTable := `
	CREATE TABLE IF NOT EXISTS domain_rules (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		domain TEXT NOT NULL,
		category TEXT,
		action TEXT NOT NULL
	);
	`

	createAccessLogsTable := `
	CREATE TABLE IF NOT EXISTS access_logs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		domain TEXT NOT NULL,
		client_ip TEXT,
		action TEXT NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	`
	createPoliciesTable := `
CREATE TABLE IF NOT EXISTS policies (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	teen_mode INTEGER NOT NULL DEFAULT 1,
	default_action TEXT NOT NULL DEFAULT 'allow',
	allowed_start TEXT NOT NULL DEFAULT '08:00',
	allowed_end TEXT NOT NULL DEFAULT '22:00'
);
`

	_, err = DB.Exec(createUsersTable)
	if err != nil {
		return err
	}

	_, err = DB.Exec(createDomainRulesTable)
	if err != nil {
		return err
	}

	_, err = DB.Exec(createAccessLogsTable)
	if err != nil {
		return err
	}

	_, err = DB.Exec(createPoliciesTable)
	if err != nil {
		return err
	}

	insertAdmin := `
INSERT OR IGNORE INTO users (username, password)
VALUES ('admin', '123456');
`

	_, err = DB.Exec(insertAdmin)
	if err != nil {
		return err
	}

	insertRules := `
INSERT INTO domain_rules (domain, category, action)
SELECT 'facebook.com', 'social', 'block'
WHERE NOT EXISTS (
	SELECT 1 FROM domain_rules WHERE domain = 'facebook.com'
);

INSERT INTO domain_rules (domain, category, action)
SELECT 'youtube.com', 'video', 'block'
WHERE NOT EXISTS (
	SELECT 1 FROM domain_rules WHERE domain = 'youtube.com'
);

INSERT INTO domain_rules (domain, category, action)
SELECT 'wikipedia.org', 'education', 'allow'
WHERE NOT EXISTS (
	SELECT 1 FROM domain_rules WHERE domain = 'wikipedia.org'
);
`

	_, err = DB.Exec(insertRules)
	if err != nil {
		return err
	}

	insertPolicy := `
INSERT INTO policies (teen_mode, default_action, allowed_start, allowed_end)
SELECT 1, 'allow', '08:00', '22:00'
WHERE NOT EXISTS (SELECT 1 FROM policies);
`

	_, err = DB.Exec(insertPolicy)
	if err != nil {
		return err
	}

	return nil
}
