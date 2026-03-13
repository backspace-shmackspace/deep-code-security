#!/bin/sh
# Sandbox execution wrapper with timeout, resource limits, and structured output
# Usage: entrypoint.sh <language> <poc_script_path> <timeout_seconds>

set -e

LANGUAGE="${1:-python}"
POC_SCRIPT="${2:-/exploit/poc.py}"
TIMEOUT="${3:-30}"

# Set resource limits (defense in depth)
ulimit -t "${TIMEOUT}"   # CPU time limit
ulimit -v 524288         # 512MB virtual memory (in KB)
ulimit -n 64             # Max open files
ulimit -u 64             # Max processes/threads

# Verify the exploit script exists
if [ ! -f "${POC_SCRIPT}" ]; then
    echo "ERROR: PoC script not found: ${POC_SCRIPT}" >&2
    exit 127
fi

# Execute based on language
case "${LANGUAGE}" in
    python)
        exec timeout "${TIMEOUT}" python3 "${POC_SCRIPT}"
        ;;
    go)
        SCRIPT_NAME="$(basename "${POC_SCRIPT}")"
        cd /tmp
        cp "${POC_SCRIPT}" main.go
        exec timeout "${TIMEOUT}" sh -c "go run main.go"
        ;;
    c)
        SCRIPT_NAME="$(basename "${POC_SCRIPT}" .c)"
        cd /tmp
        cp "${POC_SCRIPT}" poc.c
        gcc -o poc poc.c 2>&1
        exec timeout "${TIMEOUT}" ./poc
        ;;
    *)
        echo "ERROR: Unsupported language: ${LANGUAGE}" >&2
        exit 1
        ;;
esac
