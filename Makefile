.PHONY: help clean install install-dev install-all \
		lint sort-imports test dist release

VIRTUAL_ENV := $(or $(VIRTUAL_ENV), $(VIRTUAL_ENV), venv)

help: ## Show this message and exit.
	@awk 'BEGIN {FS = ":.*##"; printf "Usage:\n  make \033[36m<target>\033[0m\n\nTargets:\n"} \
	/^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

clean: ## Remove all build artifacts.
	rm -rf build dist wheels venv
	find . \( -name *.pyc -o -name *.pyo -o -name __pycache__ -o -name *.egg-info \) -exec rm -rf {} +

install: ## Install package and all features.
	$(VIRTUAL_ENV)/bin/pip install -e .

install-dev: ## Install package, all features, and linting and testing dependencies.
	$(VIRTUAL_ENV)/bin/pip install -e ".[dev.lint,dev.test]"

install-all: install-dev ## Install package and all development dependencies.
	$(VIRTUAL_ENV)/bin/pip install twine

lint: ## Run all lints.
	$(VIRTUAL_ENV)/bin/flake8 --max-complexity 12 .

sort-imports: ## Sort import statements according to isort configuration.
	$(VIRTUAL_ENV)/bin/isort --recursive .

test: ## Run all tests.
	$(VIRTUAL_ENV)/bin/pytest -vv --cov=passthesalt --cov-report term-missing --cov-fail-under 90

dist: clean ## Build source and wheel package.
	$(VIRTUAL_ENV)/bin/python setup.py sdist bdist_wheel
	ls -l dist

release: dist ## Package and upload a release.
	$(VIRTUAL_ENV)/bin/twine upload dist/*
