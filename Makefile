# ==============================================================
#  Makefile
#
#  Provides short commands for common development tasks.
#  Run `make help` to see all available targets.
#
#  Requirements:
#    - Python 3.11+
#    - Trivy CLI  (https://trivy.dev)
#    - pip install pyyaml
#
#  Usage:
#    make scan              # scan with ignore list applied
#    make scan-all          # scan showing all CVEs (no ignore list)
#    make install           # install Python dependencies
#    make trivy-install     # install Trivy CLI (Linux/macOS)
#    make help              # show this help message
# ==============================================================

.PHONY: help install trivy-install scan scan-all

# Default target: show help
.DEFAULT_GOAL := help


# ──────────────────────────────────────────────────────────────
#  Help
# ──────────────────────────────────────────────────────────────

help:
	@echo ""
	@echo "  Python Package Security Pipeline — available commands"
	@echo ""
	@echo "  make install          Install Python dependencies (pyyaml)"
	@echo "  make trivy-install    Install Trivy CLI via official installer"
	@echo "  make scan             Run security scan with ignore list applied"
	@echo "  make scan-all         Run security scan showing all CVEs"
	@echo ""


# ──────────────────────────────────────────────────────────────
#  Setup
# ──────────────────────────────────────────────────────────────

install:
	pip install pyyaml
	@echo ""
	@echo "  ✅  Python dependencies installed."
	@echo ""

trivy-install:
	curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
		| sh -s -- -b /usr/local/bin
	trivy --version
	@echo ""
	@echo "  ✅  Trivy installed."
	@echo ""


# ──────────────────────────────────────────────────────────────
#  Scan
# ──────────────────────────────────────────────────────────────

scan:
	@echo ""
	@echo "  Running security scan with ignore list..."
	@echo ""
	python -m scanner.main packages/requirements.txt --ignore-list

scan-all:
	@echo ""
	@echo "  Running security scan (all CVEs, no ignore list)..."
	@echo ""
	python -m scanner.main packages/requirements.txt
