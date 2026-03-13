# Go sandbox for exploit PoC execution
# Security policy: no-network, read-only fs, noexec tmpfs, no capabilities, non-root, seccomp
FROM golang:1.22-alpine

# Create non-root user (nobody: 65534:65534)
RUN addgroup -g 65534 nobody-sandbox 2>/dev/null || true && \
    adduser -u 65534 -G nobody-sandbox -D -h /tmp -s /sbin/nologin nobody-sandbox 2>/dev/null || true

# Install minimal tools
RUN apk add --no-cache \
    coreutils

# Copy entrypoint
COPY entrypoint.sh /entrypoint.sh
RUN chmod 555 /entrypoint.sh

# Create exploit directory (will be overwritten by mount)
RUN mkdir -p /exploit /target && \
    chmod 555 /exploit /target

# Set GOPATH to writable location (tmpfs will be mounted at /tmp)
ENV GOPATH=/tmp/gopath
ENV GOCACHE=/tmp/gocache
ENV HOME=/tmp

# Run as nobody
USER 65534:65534

# Default working directory
WORKDIR /tmp

# Entrypoint: run PoC with timeout
ENTRYPOINT ["/entrypoint.sh", "go"]
CMD ["/exploit/poc.go", "30"]

# Security labels
LABEL dcs.security.policy="no-network,read-only,noexec-tmpfs,no-capabilities,non-root,seccomp"
LABEL dcs.language="go"
LABEL dcs.version="1.0.0"
