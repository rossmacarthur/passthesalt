#!/usr/bin/env bash

set -ex

just install-all

if [ "$COVERAGE" = true ]; then
    pip install codecov
fi
