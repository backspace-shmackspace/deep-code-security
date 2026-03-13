// Safe Go code using parameterized queries — should produce ZERO findings.
// This demonstrates secure database access patterns.

package main

import (
	"database/sql"
	"fmt"
	"net/http"
	"os/exec"
)

// GetUserSafe uses parameterized queries — not flagged by Hunter.
func GetUserSafe(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")

	// SAFE: Parameterized query with placeholder
	rows, err := db.Query("SELECT * FROM users WHERE name = $1", username)
	if err != nil {
		http.Error(w, "Query failed", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	fmt.Fprintf(w, "Safe query executed")
}

// PingHostSafe uses separate arguments — not flagged as command injection.
func PingHostSafe(w http.ResponseWriter, r *http.Request) {
	host := r.FormValue("host")

	// SAFE: Separate arguments — no shell interpolation
	cmd := exec.Command("ping", "-c", "1", host)
	out, err := cmd.Output()
	if err != nil {
		http.Error(w, "Ping failed", http.StatusInternalServerError)
		return
	}
	fmt.Fprintf(w, "%s", out)
}

func main() {
	db, _ := sql.Open("sqlite3", ":memory:")
	http.HandleFunc("/user", func(w http.ResponseWriter, r *http.Request) {
		GetUserSafe(db, w, r)
	})
	http.HandleFunc("/ping", PingHostSafe)
	http.ListenAndServe(":8080", nil)
}
