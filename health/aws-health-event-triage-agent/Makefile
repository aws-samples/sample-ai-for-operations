# Makefile — aws-health-event-triage-agent
# Run `make test` to execute unit tests + forbidden-term lint.

VENV := .venv
PYTHON := $(VENV)/bin/python
PYTEST := $(VENV)/bin/pytest

.PHONY: test test-unit lint lint-terms

test: test-unit lint-terms

test-unit:
	$(PYTEST) tests/ -q

lint-terms:
	@echo "Checking for forbidden terms (PHD / Personal Health Dashboard) in src/ ..."
	@if grep -rin "phd\|personal health dashboard" \
	    --include="*.py" --include="*.ts" --include="*.md" --include="*.yaml" --include="*.json" \
	    src/ infra/ tests/ README.md SECURITY.md QUICKSTART.md 2>/dev/null \
	    | grep -v "\.kiro/" \
	    | grep -iv "phase\|philosophy"; then \
	    echo "FAIL: Found forbidden terms (PHD / Personal Health Dashboard)."; \
	    exit 1; \
	else \
	    echo "OK: No forbidden terms found."; \
	fi

lint:
	@if [ -f $(VENV)/bin/ruff ]; then \
	    $(VENV)/bin/ruff check src/ tests/; \
	else \
	    echo "ruff not installed, skipping lint"; \
	fi
