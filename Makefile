.PHONY: init test test-e2e lint format pre-commit clean all

VENV = .venv
PYTHON = $(VENV)/bin/python
PIP = $(VENV)/bin/pip
PYLINTHOME ?= $(CURDIR)/.pylint.d

$(VENV)/bin/activate:
	python3 -m venv $(VENV)

init: $(VENV)/bin/activate
	$(PIP) install --upgrade pip
	$(PIP) install -e ".[dev]"
	$(PYTHON) -m pre_commit install

format:
	$(PYTHON) -m black src/ tests/
	$(PYTHON) -m isort src/ tests/

lint:
	PYLINTHOME=$(PYLINTHOME) $(PYTHON) -m pylint src/ tests/unit/
	$(PYTHON) -m mypy src/ --strict

test:
	PYTHONPATH=src $(PYTHON) -m pytest tests/unit -v --cov=download_js_map_files --cov-report=term-missing --cov-report=json:.coverage.json --cov-fail-under=95

test-e2e:
	PYTHONPATH=src $(PYTHON) -m pytest tests/e2e -v

all: format lint test test-e2e

clean:
	rm -rf $(VENV) .pylint.d/ build/ dist/ *.egg-info src/*.egg-info .coverage .coverage.json htmlcov/ js_recon_out/
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type d -name ".pytest_cache" -exec rm -rf {} +
	find . -type d -name ".mypy_cache" -exec rm -rf {} +
