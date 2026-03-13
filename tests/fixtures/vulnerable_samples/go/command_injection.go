// Vulnerable Go code with command injection — for testing purposes ONLY.
// This file intentionally contains security vulnerabilities for testing the Hunter.
// Do NOT use this pattern in production code.

package main

import (
	"fmt"
	"net/http"
	"os/exec"
)

// PingHostVulnerable demonstrates OS command injection via exec.Command with sh -c.
// Hunter should detect: source=r.FormValue, sink=exec.Command, CWE-78.
func PingHostVulnerable(w http.ResponseWriter, r *http.Request) {
	host := r.FormValue("host")

	// VULNERABLE: User input passed directly to shell command via sh -c
	cmd := exec.Command("sh", "-c", "ping -c 1 "+host)
	output, err := cmd.Output()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	fmt.Fprintf(w, "%s", output)
}

// RunCommandVulnerable uses exec.Command with user-controlled arguments directly.
func RunCommandVulnerable(w http.ResponseWriter, r *http.Request) {
	cmdArg := r.URL.Query().Get("cmd")

	// VULNERABLE: User input as command argument
	cmd := exec.Command("sh", "-c", cmdArg)
	out, _ := cmd.CombinedOutput()
	fmt.Fprintf(w, "%s", out)
}

func main() {
	http.HandleFunc("/ping", PingHostVulnerable)
	http.HandleFunc("/run", RunCommandVulnerable)
	http.ListenAndServe(":8080", nil)
}
