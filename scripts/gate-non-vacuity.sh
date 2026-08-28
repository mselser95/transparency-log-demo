#!/usr/bin/env bash
# NON-VACUITY of the reference row, proven CONSTRUCTIVELY.
#
# For each interesting predicate: take a fixture the full row FAILS, remove
# that one predicate, and require the SAME FILE to now PASS. A predicate whose
# removal changes no verdict on any input was never a gate; it was a line of
# code that ran.
#
# The first mutation is the one that matters most in this repo. `signing-only`
# is not an invented weakening -- it is a faithful reproduction of the
# `artifact-provenance` row that `_shared/probes/verify-standard.sh` ships
# today: citations, plus a keyword match for a signing mechanism in the
# executable lines of the workflow. Running it against the `no-tlog` fixture
# shows the upstream row passing the exact configuration this demo exists to
# separate from a real one.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SPECS="${HERE}/../specs"
ROW="${HERE}/provenance-row.py"

# mode : fixture : what the predicate distinguishes
MUTATIONS=(
  "signing-only:production.no-tlog.yaml:P2+P3+P4 -- the upstream row, reproduced: a keyword match for 'cosign' cannot see that the transparency log was switched off"
  "signing-only:production.permissions-only.yaml:P2+P3+P4, on a workflow with NO SIGNING STEP AT ALL -- a PROMOTED finding: the upstream pattern's 'attestations:' alternative matches the 'attestations: write' entry of a GitHub permissions block"
  "no-tlog-check:production.no-tlog-but-verified.yaml:P2 -- the difference between a signature and a timestamped, witnessed signature"
  "no-anchor-check:production.online-verify.yaml:P4 -- the difference between verifying a proof and asking the log whether it is honest"
  "no-evidence-check:production.evidence-empty.yaml:P5 -- the difference between evidence that records a measurement and evidence that uses the word 'verified'"
)

mutations=0
without_flip=0
for m in "${MUTATIONS[@]}"; do
  mode="${m%%:*}"
  rest="${m#*:}"
  fixture="${rest%%:*}"
  why="${rest#*:}"
  mutations=$((mutations + 1))

  echo "=== ${mode} -- ${why}"
  echo "    fixture: specs/${fixture}"

  # Exit codes measured with NO pipe in sight, and the environment variable
  # EXPORTED rather than prefixed. `VAR=x python3 row.py $VAR/f` expands $VAR
  # from the CALLER's environment, before the assignment ever happens.
  full_out="$(python3 "$ROW" "${SPECS}/${fixture}" 2>&1)"
  full_rc=$?

  mut_out="$(TXL_ROW_MODE="$mode" python3 "$ROW" "${SPECS}/${fixture}" 2>&1)"
  mut_rc=$?

  echo "    full row              : exit ${full_rc}"
  echo "    TXL_ROW_MODE=${mode} : exit ${mut_rc}"
  echo "$mut_out" | sed 's/^/      /'

  if [ "$full_rc" -eq 1 ] && [ "$mut_rc" -eq 0 ]; then
    echo "    => the predicate is LOAD-BEARING: removing it flips FAIL to PASS on the same file."
  else
    without_flip=$((without_flip + 1))
    echo "    => NO FLIP (full=${full_rc} mutated=${mut_rc}). This predicate is not doing what it claims." >&2
  fi
  echo
done

echo "mutations: ${mutations}   without a flip: ${without_flip}"
if [ "$mutations" -eq 0 ] || [ "$without_flip" -ne 0 ]; then
  echo "NON-VACUITY FAILED" >&2
  exit 1
fi
echo "NON-VACUITY OK"
