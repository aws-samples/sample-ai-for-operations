PYTHON := .venv/bin/python
PIP := .venv/bin/pip

.PHONY: install install-dev test test-unit test-integration lint deploy

install:
	$(PIP) install -r requirements.txt

install-dev:
	$(PIP) install -r requirements-dev.txt

test-unit:
	.venv/bin/pytest tests/unit/ -v --cov=src --cov-report=term-missing

test-integration:
	.venv/bin/pytest tests/integration/ -v

test-all:
	.venv/bin/pytest tests/ -v --cov=src --cov-report=term-missing

lint:
	.venv/bin/ruff check src/ tests/

deploy:
	cd infra && npm ci && npx cdk deploy --require-approval never
