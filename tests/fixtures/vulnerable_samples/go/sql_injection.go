// Vulnerable Go code with SQL injection — for testing purposes ONLY.
// This file intentionally contains security vulnerabilities for testing the Hunter.
// Do NOT use this pattern in production code.

package main

import (
	"database/sql"
	"fmt"
	"net/http"
)

// GetUserVulnerable demonstrates SQL injection via string concatenation in db.Query.
// Hunter should detect: source=r.FormValue, sink=db.Query, CWE-89.
func GetUserVulnerable(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")

	// VULNERABLE: Direct string concatenation in SQL query
	query := "SELECT * FROM users WHERE name = '" + username + "'"
	rows, err := db.Query(query)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	fmt.Fprintf(w, "Query executed")
}

func main() {
	db, _ := sql.Open("sqlite3", ":memory:")
	http.HandleFunc("/user", func(w http.ResponseWriter, r *http.Request) {
		GetUserVulnerable(db, w, r)
	})
	http.ListenAndServe(":8080", nil)
}
