# C sandbox for exploit PoC execution (stretch goal)
# Security policy: no-network, read-only fs, noexec tmpfs, no capabilities, non-root, seccomp
FROM gcc:12-slim

# Create non-root user (nobody: 65534:65534)
RUN groupadd -g 65534 nobody-sandbox 2>/dev/null || true && \
    useradd -u 65534 -g 65534 -d /tmp -s /sbin/nologin nobody-sandbox 2>/dev/null || true

# Install minimal tools
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        coreutils \
    && rm -rf /var/lib/apt/lists/*

# Copy entrypoint
COPY entrypoint.sh /entrypoint.sh
RUN chmod 555 /entrypoint.sh

# Create exploit directory (will be overwritten by mount)
RUN mkdir -p /exploit /target && \
    chmod 555 /exploit /target

# Run as nobody
USER 65534:65534

# Default working directory (tmpfs mounted here)
WORKDIR /tmp

# Entrypoint: compile and run PoC with timeout
ENTRYPOINT ["/entrypoint.sh", "c"]
CMD ["/exploit/poc.c", "30"]

# Security labels
LABEL dcs.security.policy="no-network,read-only,noexec-tmpfs,no-capabilities,non-root,seccomp"
LABEL dcs.language="c"
LABEL dcs.version="1.0.0"
