#!/usr/bin/env bash
# Run a command, but surface only what a reviewer needs:
#   pass -> the summary tail
#   fail -> matching failure lines + the tail
# Keeps large test output out of an agent's context window.
# Usage: bash scripts/test-quiet.sh npm test
set -o pipefail
out="$(mktemp)"
"$@" >"$out" 2>&1
code=$?
if [ "$code" -eq 0 ]; then
  tail -n 15 "$out"
else
  echo "=== failures ==="
  grep -nE '(FAIL|not ok|✗|✘|AssertionError|Assertion failed|Error:|error TS[0-9]+|error:)' "$out" | head -n 60
  echo "=== tail ==="
  tail -n 25 "$out"
fi
rm -f "$out"
exit "$code"
