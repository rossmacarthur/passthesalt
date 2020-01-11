#!/usr/bin/env just

export PYTHON := "python"
export VIRTUAL_ENV := env_var_or_default("VIRTUAL_ENV", "venv")

# Show this message and exit.
help:
    @just --list

# Remove all build artifacts.
clean:
    rm -rf venv build dist wheels
    find . \( -name *.pyc -o -name *.pyo -o -name __pycache__ -o -name *.egg-info \) -exec rm -rf {} +

# Create a virtualenv.
venv:
    $PYTHON -m venv venv

# Check the VIRTUAL_ENV variable, and if it is not set create a virtualenv.
check-venv:
    #!/usr/bin/env sh
    if [ "$VIRTUAL_ENV" = "venv" ]; then
        just create-env
    else
        echo "Not creating virtualenv because VIRTUAL_ENV is set."
    fi

# Install package and all features.
install: check-venv
    $VIRTUAL_ENV/bin/pip install -e .

# Install package, all features, and all development dependencies.
install-all: check-venv
    $VIRTUAL_ENV/bin/pip install -r ci/requirements.txt -e .

# Run all lints.
lint:
    $VIRTUAL_ENV/bin/black --target-version py36 --skip-string-normalization --check .
    $VIRTUAL_ENV/bin/flake8 --max-complexity 12 .

# Blacken and sort import statements.
blacken:
    $VIRTUAL_ENV/bin/isort --recursive .
    $VIRTUAL_ENV/bin/black --target-version py36 --skip-string-normalization .

# Run all tests.
test:
    $VIRTUAL_ENV/bin/pytest -vv --cov=passthesalt --cov-report term-missing --cov-fail-under 90

# Build source and wheel package.
dist: clean
    $VIRTUAL_ENV/bin/python setup.py sdist bdist_wheel --universal
    @ls -l dist

# Package and upload a release.
release: dist
    $VIRTUAL_ENV/bin/twine upload dist/*
