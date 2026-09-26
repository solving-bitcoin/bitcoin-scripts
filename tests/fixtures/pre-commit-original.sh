#!/usr/bin/env bash
# Preserved from PR source head 79308bd8f831d19f8585fbaee03c0d47631258c8.
set -euo pipefail

root="$(git rev-parse --show-toplevel)"
cd "$root"

python3 tools/kb.py validate
cargo fmt --all -- --check

needs_metrics=0
while IFS= read -r path; do
    case "$path" in
        src/*|tests/primitive_metrics.rs|knowledge/catalog.json|README.md|*/README.md|Cargo.toml|Cargo.lock)
            needs_metrics=1
            break
            ;;
    esac
done < <(git diff --cached --name-only --diff-filter=ACMR)

if ((needs_metrics)); then
    cargo test --locked --test primitive_metrics
fi
