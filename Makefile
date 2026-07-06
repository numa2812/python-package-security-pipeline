# ==============================================================
#  Makefile
#
#  Provides short commands for common development tasks.
#  Run `make help` to see all available targets.
#
#  Requirements:
#    - Python 3.11+
#    - Trivy CLI  (https://trivy.dev)
#    - pip install -r scanner/requirements.txt
#
#  Usage:
#    make scan              # scan default requirements with ignore list applied
#    make scan-demo         # scan intentionally vulnerable demo with ignore list
#    make scan-demo-all     # scan intentionally vulnerable demo without ignore list
#    make install           # install Python dependencies
#    make install-dev       # Install development and test dependencies
#    make test              # Run unit tests
#    make trivy-install     # install Trivy CLI (Linux/macOS)
#    make help              # show this help message
# ==============================================================

.PHONY: help install install-dev trivy-install test scan scan-demo scan-demo-all

# Default target: show help
.DEFAULT_GOAL := help

# Trivy version — keep in sync with .github/workflows/security-scan.yml
TRIVY_VERSION ?= 0.69.3


# ──────────────────────────────────────────────────────────────
#  Help
# ──────────────────────────────────────────────────────────────

help:
	@echo ""
	@echo "  Python Package Security Pipeline — available commands"
	@echo ""
	@echo "  make install          Install scanner dependencies"
	@echo "  make install-dev      Install development and test dependencies"
	@echo "  make test             Run unit tests"
	@echo "  make trivy-install    Install Trivy $(TRIVY_VERSION) CLI (Linux/macOS)"
	@echo "  make scan             Run default security scan with ignore list applied"
	@echo "  make scan-demo        Run vulnerable demo scan with ignore list applied"
	@echo "  make scan-demo-all    Run vulnerable demo scan showing all CVEs"
	@echo ""


# ──────────────────────────────────────────────────────────────
#  Setup
# ──────────────────────────────────────────────────────────────

install:
	pip install -r scanner/requirements.txt
	@echo ""
	@echo "  ✅  Python dependencies installed."
	@echo ""

install-dev:
	python -m pip install -r requirements-dev.txt
	@echo ""
	@echo "  Development and test dependencies installed."
	@echo ""

trivy-install:
	@# Detect OS (Darwin = macOS) and CPU architecture, then download the matching
	@# Trivy binary directly from GitHub Releases at the pinned TRIVY_VERSION.
	@OS=$$(uname -s); \
	ARCH=$$(uname -m); \
	if [ "$$OS" = "Darwin" ]; then OS_TAG="macOS"; else OS_TAG="Linux"; fi; \
	if [ "$$ARCH" = "arm64" ] || [ "$$ARCH" = "aarch64" ]; then ARCH_TAG="ARM64"; else ARCH_TAG="64bit"; fi; \
	ARCHIVE="trivy_$(TRIVY_VERSION)_$${OS_TAG}-$${ARCH_TAG}.tar.gz"; \
	echo "  Downloading $${ARCHIVE} ..."; \
	curl -sfL "https://github.com/aquasecurity/trivy/releases/download/v$(TRIVY_VERSION)/$${ARCHIVE}" | tar -xzf - -C /usr/local/bin trivy
	@trivy --version
	@echo ""
	@echo "  ✅  Trivy $(TRIVY_VERSION) installed."
	@echo ""


# ──────────────────────────────────────────────────────────────
#  Scan
# ──────────────────────────────────────────────────────────────

scan:
	@echo ""
	@echo "  Running default security scan with ignore list..."
	@echo ""
	python -m scanner.main packages/requirements.txt --ignore-list

scan-demo:
	@echo ""
	@echo "  Running vulnerable demo scan with ignore list..."
	@echo ""
	python -m scanner.main packages/vulnerable-requirements.txt --ignore-list

scan-demo-all:
	@echo ""
	@echo "  Running vulnerable demo scan (all CVEs, no ignore list)..."
	@echo ""
	python -m scanner.main packages/vulnerable-requirements.txt


# ──────────────────────────────────────────────────────────────
#  Tests
# ──────────────────────────────────────────────────────────────

test:
	python -m pytest -v
