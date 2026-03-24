#!/bin/bash

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"

shell_files=(
    "$REPO_DIR/KratoSSH.sh"
    "$REPO_DIR"/lib/*.sh
)

echo "Running bash syntax checks..."
for file in "${shell_files[@]}"; do
    bash -n "$file" || exit 1
done

echo "Checking CLI help path..."
bash "$REPO_DIR/KratoSSH.sh" --help >/dev/null || exit 1

echo "Running verify_hardening_state functional test..."
bash "$REPO_DIR/tests/test-verify.sh" || exit 1

echo "Running CLI functional tests..."
bash "$REPO_DIR/tests/test-cli.sh" || exit 1

echo "Running hardening engine functional tests..."
bash "$REPO_DIR/tests/test-hardening.sh" || exit 1

echo "Running CLI fix functional test..."
bash "$REPO_DIR/tests/test-fix.sh" || exit 1

if command -v shellcheck >/dev/null 2>&1; then
    echo "Running shellcheck..."
    shellcheck -x "$REPO_DIR/KratoSSH.sh" "$REPO_DIR"/lib/*.sh "$REPO_DIR"/tests/*.sh || exit 1
else
    echo "shellcheck not found; skipping static lint."
fi

echo "All shell checks passed."