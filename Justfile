#!/usr/bin/env just

# Show this message and exit.
help:
    @just --list

# Install package.
install:
    pip install -e .

# Install package and development dependencies.
install-dev:
    pip install -e . -r dev-requirements.in

# Auto-format the code.
fmt:
    black .
    isort .

# Run all lints.
lint:
    black --diff --check .
    isort --diff --check .
    flake8 .

# Run all tests.
test:
    pytest -vv --cov=passthesalt --cov-report term-missing --cov-fail-under 90
