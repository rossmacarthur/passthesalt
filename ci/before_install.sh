#!/usr/bin/env bash

set -ex

mkdir -p "$HOME/.local/bin"

curl --proto '=https' -fLsS https://rossmacarthur.github.io/install/crate.sh \
    | sh -s -- --repo "casey/just" --target "x86_64-unknown-linux-musl" --to "$HOME/.local/bin"
