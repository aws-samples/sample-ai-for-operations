# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
PY ?= python3.12
VENV ?= .venv
BIN := $(VENV)/bin

.PHONY: help install demo test lint security synth deploy clean

help:
	@echo "install   create .venv and install with dev extras"
	@echo "demo      render a full report from the synthetic estate (no AWS access)"
	@echo "test      unit and integration tests with coverage"
	@echo "lint      ruff"
	@echo "security  bandit over src/"
	@echo "synth     cdk synth (needs Node.js)"
	@echo "deploy    cdk deploy; pass CONTEXT='-c flowLogBucketName=... -c flowLogTable=...'"

$(BIN)/nfi:
	$(PY) -m venv $(VENV)
	$(BIN)/pip install -q --upgrade pip
	$(BIN)/pip install -q -e ".[dev,cli]"

install: $(BIN)/nfi

demo: $(BIN)/nfi
	$(BIN)/nfi demo --out ./reports

test: $(BIN)/nfi
	$(BIN)/pytest tests/ --cov=src/network_flow_insight --cov-report=term-missing

lint: $(BIN)/nfi
	$(BIN)/ruff check src tests scripts

security: $(BIN)/nfi
	$(BIN)/bandit -q -r src -c pyproject.toml

infra/node_modules:
	cd infra && npm ci --no-audit --no-fund

synth: infra/node_modules
	cd infra && npx cdk synth --quiet $(CONTEXT)

deploy: infra/node_modules
	cd infra && npx cdk deploy $(CONTEXT)

clean:
	rm -rf $(VENV) reports infra/cdk.out .pytest_cache .ruff_cache
