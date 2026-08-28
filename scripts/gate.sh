#!/usr/bin/env bash
# SELF-CHECK for the reference artifact-provenance row.
#
# Runs the row over every fixture and compares its EXIT CODE against the one
# the fixture was written to produce. A row nobody has run against a known-bad
# input is a row whose FAIL branch has never executed, and an unexecuted FAIL
# branch is the most common way a gate reports success while doing nothing.
#
# The exit code is captured WITHOUT a pipe. `cmd | tee` under `set -o pipefail`
# reports tee's status, and `cmd | grep -q PASS` reports 141 on exactly the
# runs where the pattern WAS found -- grep exits at the first match, the writer
# takes SIGPIPE, and pipefail propagates it. Both of those turn a measurement
# into a coin flip. So: run, capture into a variable, read `$?`, match the
# variable.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SPECS="${HERE}/../specs"
ROW="${HERE}/provenance-row.py"

# fixture:expected-exit-code
CASES=(
  "production.implemented.yaml:0"
  "production.declined.yaml:0"
  "production.no-tlog.yaml:1"
  "production.no-tlog-but-verified.yaml:1"
  "production.sign-only.yaml:1"
  "production.ignore-tlog.yaml:1"
  "production.online-verify.yaml:1"
  "production.comment-only.yaml:1"
  "production.permissions-only.yaml:1"
  "production.decayed.yaml:1"
  "production.evidence-empty.yaml:1"
  "production.expired-waiver.yaml:1"
)

n=0
mismatches=0
for c in "${CASES[@]}"; do
  f="${c%%:*}"
  want="${c##*:}"
  out="$(python3 "$ROW" "${SPECS}/${f}" 2>&1)"
  rc=$?
  n=$((n + 1))
  echo "--- specs/${f}"
  echo "$out" | sed 's/^/    /'
  if [ "$rc" -ne "$want" ]; then
    mismatches=$((mismatches + 1))
    echo "    exit ${rc}  (expected ${want})   *** MISMATCH ***"
  else
    echo "    exit ${rc}  (expected ${want})"
  fi
  echo
done

echo "cases: ${n}   mismatches: ${mismatches}"
if [ "$mismatches" -ne 0 ]; then
  echo "ROW SELF-CHECK FAILED" >&2
  exit 1
fi
# A self-check that ran zero cases prints "mismatches: 0" and means nothing.
if [ "$n" -eq 0 ]; then
  echo "ROW SELF-CHECK RAN NOTHING" >&2
  exit 1
fi
echo "ROW SELF-CHECK OK"
