.PHONY: lint test test-hunter test-auditor test-architect test-mcp test-fuzzer \
        test-c-fuzzer test-bridge test-tui test-integration sast security build \
        build-sandboxes build-fuzz-sandbox build-fuzz-c-sandbox clean check-vendor \
        install install-dev audit-deps

PYTHON := python3
PYTEST := pytest
RUFF := ruff
BANDIT := bandit
SRC := src/deep_code_security
TESTS := tests

# Install production dependencies
install:
	$(PYTHON) -m pip install -e .

# Install development dependencies
install-dev:
	$(PYTHON) -m pip install -e ".[dev]"

# Lint with ruff
lint:
	$(RUFF) check $(SRC) $(TESTS)
	$(RUFF) format --check $(SRC) $(TESTS)

# Format code
format:
	$(RUFF) format $(SRC) $(TESTS)
	$(RUFF) check --fix $(SRC) $(TESTS)

# Run all tests with coverage
test:
	$(PYTEST) $(TESTS) -v \
		--cov=$(SRC) \
		--cov-report=term-missing \
		--cov-fail-under=90 \
		--ignore=$(TESTS)/test_integration

# Run hunter tests
test-hunter:
	$(PYTEST) $(TESTS)/test_hunter -v \
		--cov=$(SRC)/hunter \
		--cov-report=term-missing

# Run auditor tests
test-auditor:
	$(PYTEST) $(TESTS)/test_auditor -v \
		--cov=$(SRC)/auditor \
		--cov-report=term-missing

# Run architect tests
test-architect:
	$(PYTEST) $(TESTS)/test_architect -v \
		--cov=$(SRC)/architect \
		--cov-report=term-missing

# Run MCP tests
test-mcp:
	$(PYTEST) $(TESTS)/test_mcp -v \
		--cov=$(SRC)/mcp \
		--cov-report=term-missing

# Run fuzzer tests
test-fuzzer:
	$(PYTEST) $(TESTS)/test_fuzzer -v \
		--cov=$(SRC)/fuzzer \
		--cov-report=term-missing

# Run C fuzzer plugin tests only
test-c-fuzzer:
	$(PYTEST) $(TESTS)/test_fuzzer/test_plugins/test_c_target.py \
		$(TESTS)/test_fuzzer/test_ai/test_c_prompts.py \
		$(TESTS)/test_fuzzer/test_ai/test_c_response_parser.py \
		$(TESTS)/test_fuzzer/test_execution/test_c_worker_validation.py \
		$(TESTS)/test_fuzzer/test_execution/test_c_container_backend.py \
		$(TESTS)/test_fuzzer/test_c_harness_validation_adversarial.py \
		$(TESTS)/test_fuzzer/test_ai/test_ai_engine_extensibility.py \
		-v --cov=$(SRC)/fuzzer --cov-report=term-missing

# Run bridge tests
test-bridge:
	$(PYTEST) $(TESTS)/test_bridge -v \
		--cov=$(SRC)/bridge \
		--cov-report=term-missing

# Run TUI tests (requires textual installed)
test-tui:
	$(PYTEST) $(TESTS)/test_tui -v \
		--cov=$(SRC)/tui \
		--cov-report=term-missing

# Run integration tests (requires Docker or Podman)
test-integration:
	$(PYTEST) $(TESTS)/test_integration -v --timeout=120

# Static security analysis
sast:
	$(BANDIT) -r $(SRC) -ll

# Security audit (sast + dependency audit)
security: sast
	pip-audit

# Build the fuzzer sandbox container image (Podman)
build-fuzz-sandbox:
	podman build -t dcs-fuzz-python:latest -f sandbox/Containerfile.fuzz-python .

# Build the C fuzzer sandbox container image (Podman)
build-fuzz-c-sandbox:
	podman build -t dcs-fuzz-c:latest -f sandbox/Containerfile.fuzz-c .

# Build sandbox Docker images
build-sandboxes:
	@echo "Building Python sandbox image..."
	docker build -f sandbox/Dockerfile.python -t deep-code-security-sandbox-python:latest sandbox/
	@echo "Building Go sandbox image..."
	docker build -f sandbox/Dockerfile.go -t deep-code-security-sandbox-go:latest sandbox/
	@echo "Building C sandbox image..."
	docker build -f sandbox/Dockerfile.c -t deep-code-security-sandbox-c:latest sandbox/

# Check vendored shared library against upstream
check-vendor:
	@echo "Checking vendored shared library..."
	@if [ -f $(SRC)/mcp/shared/VENDORED_FROM.md ]; then \
		echo "VENDORED_FROM.md found. Check manually against upstream helper-mcps."; \
	else \
		echo "WARNING: VENDORED_FROM.md not found in $(SRC)/mcp/shared/"; \
		exit 1; \
	fi

# Build Python package
build:
	$(PYTHON) -m build

# Clean build artifacts
clean:
	rm -rf dist/ build/ *.egg-info src/*.egg-info
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".ruff_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -name ".coverage" -delete
	find . -name "coverage.xml" -delete

# Audit dependencies for known vulnerabilities
audit-deps:
	pip-audit --extra fuzz
	pip-audit --extra vertex

# Run MCP server (for development)
serve:
	$(PYTHON) -m deep_code_security.mcp
