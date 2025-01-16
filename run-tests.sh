#!/bin/bash
# Wrapper script to run tests with proper permissions

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    if ! command -v sudo >/dev/null 2>&1; then
        echo "Error: sudo is required but not installed" >&2
        exit 1
    fi
    exec sudo --preserve-env=PATH "$0" "$@"
fi

if [[ ! -x "./test.sh" ]]; then
    echo "Error: test.sh not found or not executable" >&2
    exit 1
fi

./test.sh "$@" 