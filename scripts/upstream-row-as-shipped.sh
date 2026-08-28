#!/usr/bin/env bash
# The artifact-provenance row that `_shared/probes/verify-standard.sh` ships
# TODAY, reproduced VERBATIM and executed against this repo's fixtures.
#
# This exists because "the upstream row would pass this" is a claim, and a claim
# about a gate is the one kind of statement this collection does not accept from
# itself. The two lines below are copied character for character from the probe
# (the `wf_exec=` assignment and the `grep -qE` condition); the surrounding loop
# is this file's own. If the probe changes, this file is wrong in a way a reader
# can check by diffing two short strings.
#
# Source: _shared/probes/verify-standard.sh, the `artifact-provenance` row.
#
#   wf_exec="$(grep -rhE "^[^#]*" $wf/*.yaml 2>/dev/null | sed 's/#.*//' || true)"
#   if grep -qE "cosign|--provenance=|actions/attest|attestations:" <<<"$wf_exec"; then
#     row "artifact-provenance" PASS "signing/attestation step present"
#
# Note what the probe does RIGHT, because the finding is not that it is careless:
# it strips comments before matching (an earlier version PASSed on a comment
# explaining why provenance was impossible), and it reads into a variable rather
# than piping into `grep -q` (which under pipefail reports FALSE on exactly the
# runs where the pattern WAS found). Both of those are scars. The gap is that
# what remains is a keyword match, and a keyword cannot see a flag.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
WF="${HERE}/../specs/workflows"
TMP="$(mktemp -d -t txl-upstream-row)"
trap '/bin/rm -r "$TMP" 2>/dev/null || true' EXIT

echo "The artifact-provenance row as shipped, run against each fixture."
echo "PASS below means: verify-standard.sh reports \"signing/attestation step present\"."
echo

pass=0
total=0
for f in "$WF"/*.yml; do
  b="$(basename "$f")"
  # The probe globs *.yaml in a workflow directory; the fixtures are .yml, so
  # each is copied under the name the probe would see. Nothing else is changed.
  /bin/rm -r "${TMP}/wf" 2>/dev/null || true
  mkdir -p "${TMP}/wf"
  cp "$f" "${TMP}/wf/release.yaml"
  wf="${TMP}/wf"

  # ---- verbatim from verify-standard.sh -----------------------------------
  wf_exec="$(grep -rhE "^[^#]*" $wf/*.yaml 2>/dev/null | sed 's/#.*//' || true)"
  if grep -qE "cosign|--provenance=|actions/attest|attestations:" <<<"$wf_exec"; then
    verdict='PASS  "signing/attestation step present"'
    pass=$((pass + 1))
  else
    verdict='FAIL  "no provenance and no live waiver"'
  fi
  # -------------------------------------------------------------------------

  total=$((total + 1))
  printf '  %-42s %s\n' "$b" "$verdict"
  # Show WHICH line satisfied it, because on two of these fixtures the answer is
  # the finding. `grep -m1` with `|| true`: no match is a legitimate outcome
  # here and must not abort the loop.
  hit="$(grep -m1 -nE "cosign|--provenance=|actions/attest|attestations:" <<<"$wf_exec" || true)"
  if [ -n "$hit" ]; then
    printf '  %-42s   matched: %s\n' "" "$(echo "$hit" | sed 's/^[0-9]*://' | sed 's/^ *//' | cut -c1-72)"
  fi
done

echo
echo "fixtures: ${total}   passed by the row as shipped: ${pass}"
echo
echo "Of those passes, these have no timestamped, witnessed, offline-verifiable"
echo "provenance at all:"
echo "  release-sign-no-tlog.yml         signs with --tlog-upload=false"
echo "  release-sign-only.yml            signs and logs, verifies nothing"
echo "  release-verify-ignore-tlog.yml   verifies with --insecure-ignore-tlog"
echo "  release-verify-online.yml        verifies by asking the log about itself"
echo "  release-no-tlog-but-verified.yml offline-verified, never logged"
echo "  release-permissions-only.yml     NO SIGNING STEP AT ALL -- matched on the"
echo "                                   'attestations: write' line of a GitHub"
echo "                                   permissions block"
