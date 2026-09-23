#!/usr/bin/env bash
# Run a command; if it fails, publish the part of its output that explains why
# as a GitHub Actions error annotation.
#
#   ./scripts/ci-annotate.sh "title" command args...
#
# Job logs on GitHub are readable only when signed in. Annotations are public,
# show inline on pull requests, and are returned by the checks API -- so a
# failure can be diagnosed by anyone, including a contributor without access.
# Outside Actions this is a plain pass-through.
set -uo pipefail

title=$1
shift
log=$(mktemp)
trap 'rm -f "$log"' EXIT

"$@" 2>&1 | tee "$log"
status=${PIPESTATUS[0]}
[[ $status -eq 0 || -z "${GITHUB_ACTIONS:-}" ]] && exit "$status"

# Go test failures, panics and data races first; otherwise the tail.
excerpt=$(grep -n -E -A30 -- '^(--- FAIL|panic:|WARNING: DATA RACE|FAIL[[:space:]])|_test\.go:[0-9]+: ' "$log" | head -200)
[[ -n "$excerpt" ]] || excerpt=$(tail -80 "$log")

# Workflow commands take one line; %, CR and LF must be escaped.
excerpt=${excerpt//'%'/'%25'}
excerpt=${excerpt//$'\r'/'%0D'}
excerpt=${excerpt//$'\n'/'%0A'}
echo "::error title=${title}::exit ${status}%0A${excerpt}"
exit "$status"
