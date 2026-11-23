PYTHON ?= python3
export PYTHONPATH := .

.PHONY: test test-unit test-coverage sample lint typecheck

test: test-unit

test-unit:
	$(PYTHON) -m pytest tests/unit -v

test-coverage:
	$(PYTHON) -m coverage run --source=src -m pytest tests
	$(PYTHON) -m coverage report -m --fail-under=80

sample:
	$(PYTHON) -m src.assessment_core assess \
		--input samples/minimal_assessment.json \
		--output reports/sample-report.html \
		--assessment-json reports/sample-assessment.json \
		--findings-json reports/sample-findings.json \
		--summary-md reports/sample-summary.md \
		--no-session

lint:
	$(PYTHON) -m ruff check src tests
	$(PYTHON) -m mypy src

typecheck: lint
