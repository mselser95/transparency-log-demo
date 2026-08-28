#!/usr/bin/env python3
"""A REFERENCE probe row for tier-policy's `supply_chain.artifact_provenance`.

`_shared/tier-policy.yaml` says, in `defaults` and again at tier 0:

    supply_chain: { secret_scan: all_triggers, vuln_scan: required, sbom: required,
                    artifact_provenance: required, secretless_presubmit: required }

and `_shared/probes/verify-standard.sh` DOES carry a row for it:

    wf_exec="$(grep -rhE "^[^#]*" $wf/*.yaml 2>/dev/null | sed 's/#.*//' || true)"
    if grep -qE "cosign|--provenance=|actions/attest|attestations:" <<<"$wf_exec"; then
      row "artifact-provenance" PASS "signing/attestation step present"

That row is careful about the things it checks -- it strips comments before
matching, and it reads into a variable rather than piping into `grep -q`, both
of which are scars from real false PASSes. It is nonetheless a KEYWORD GREP for
the string `cosign`, and every one of the following passes it:

  * `cosign sign --tlog-upload=false ...`  -- a signature with no timestamp and
    no witness. This repo's sibling demo, image-signing-demo, signs exactly
    this way, on purpose, and would PASS the row today.
  * a workflow that signs and never verifies anything.
  * a workflow that verifies with `--insecure-ignore-tlog`.
  * a workflow that verifies by ASKING the log at verification time, so the
    answer is only as good as the log's honesty at that moment.

This row executes the distinction. Six predicates:

  P0 citations   the cited workflow and evidence file resolve on disk
  P1 signing     an EXECUTABLE line invokes a real signing/attestation
                 mechanism (this is where the current probe row stops)
  P2 log upload  transparency-log upload is not disabled, and a log is named
  P3 verify      a verification step consumes the log entry and is not
                 neutered by --insecure-ignore-tlog / --ignore-tlog
  P4 anchor      that verification is anchored OFFLINE -- against a signed
                 checkpoint or bundle -- rather than by asking the log
  P5 evidence    the cited evidence records a real verification: a log index,
                 an integrated time and a recomputed root

Sources: Newman, Meyers & Torres-Arias, "Sigstore: Software Signing for
Everybody", ACM CCS 2022; Laurie, Langley & Kasper, RFC 6962; Merkle, CRYPTO
'87. Full citations in README.md.

    provenance-row.py <spec.yaml>            exit 0 = PASS, 1 = FAIL, 2 = usage
    TXL_ROW_MODE=signing-only|no-tlog-check|no-anchor-check|no-evidence-check
"""
import datetime
import os
import re
import sys

import yaml

MODE = os.environ.get("TXL_ROW_MODE", "full")
VALID_MODES = {"full", "signing-only", "no-tlog-check", "no-anchor-check", "no-evidence-check"}

# Real signing / attestation mechanisms. Deliberately the SAME family the
# upstream probe row matches, so that P1 is a faithful reproduction of it and
# the non-vacuity demonstration compares like with like.
SIGN_RE = re.compile(r"\bcosign\b|--provenance=|actions/attest|attestations:|\bslsa-github-generator\b")

# Ways to switch the transparency log off. Each of these is a legitimate flag
# someone reached for on a Friday, and each turns a logged signature back into
# an unlogged one without changing the shape of the pipeline.
NO_TLOG_RE = re.compile(r"--tlog-upload[= ]false|--no-tlog-upload|--tlog-upload=0")

# Ways to ask a verifier to look away.
IGNORE_TLOG_RE = re.compile(r"--insecure-ignore-tlog|--ignore-tlog|--insecure-ignore-sct")

VERIFY_RE = re.compile(r"\bcosign\s+verify\b|\bcosign\s+verify-blob\b|\bcosign\s+verify-attestation\b"
                       r"|\btxl-verify\b|\bslsa-verifier\b|\bgh\s+attestation\s+verify\b")

# An OFFLINE anchor: the verification is settled against material already on
# disk -- a bundle, a signed checkpoint, an explicit offline mode -- rather
# than by a question put to the log at verification time.
OFFLINE_RE = re.compile(r"--offline\b|--bundle[= ]|--provenance-path[= ]"
                        r"|txl-verify\s+inclusion|--anchor[= ]signed-checkpoint|--trusted-root[= ]")

# A verification that names a log URL and no offline material is an ONLINE
# verification: correct, useful, and dependent on the log being honest at that
# instant.
ONLINE_ONLY_RE = re.compile(r"--rekor-url[= ]|--certificate-oidc-issuer[= ]")


def executable_lines(path):
    """Workflow lines with comments stripped and shell continuations JOINED.

    Two things, both learned from real false verdicts:

    Stripping comments is not tidiness. The upstream probe row PASSed, once, on
    a comment that EXPLAINED WHY provenance was impossible in that repo. A row
    that reads prose is reading the wrong file.

    Joining `\\`-continuations is the same class one level down. Almost every
    interesting flag in a workflow -- `--tlog-upload=false`, `--bundle`,
    `--insecure-ignore-tlog` -- sits on a continuation line, several lines below
    the command it modifies. A row that matches per PHYSICAL line sees a
    `cosign verify-blob` with no flags and a set of orphan flags attached to no
    command, and it will happily report that a blinded verification is a
    verification. The shell joins them; so does this.
    """
    out = []
    pending = ""
    for raw in open(path, encoding="utf-8").read().splitlines():
        line = re.sub(r"#.*$", "", raw)
        if not line.strip():
            continue
        stripped = line.rstrip()
        if stripped.endswith("\\"):
            pending += stripped[:-1].rstrip() + " "
            continue
        out.append((pending + line.strip()) if pending else line)
        pending = ""
    if pending:
        out.append(pending)
    return out


def fmt(label, ok, detail):
    print(f"{label:<18}: {'PASS' if ok else 'FAIL'} {detail}")
    return ok


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    if MODE not in VALID_MODES:
        print(f"unknown TXL_ROW_MODE={MODE!r}; expected one of {sorted(VALID_MODES)}", file=sys.stderr)
        return 2

    spec_path = os.path.abspath(sys.argv[1])
    base = os.path.dirname(spec_path)
    spec = yaml.safe_load(open(spec_path))
    comp = spec.get("component", "<unnamed>")
    tier = spec.get("tier", "?")
    sc = (spec.get("supply_chain") or {})

    print(f"spec              : {spec_path}")
    print(f"component         : {comp}   tier {tier}   dimension 9")
    print(f"row mode          : {MODE}")

    # --- a ratified decline, or a waiver, short-circuits the row -------------
    #
    # A decline is a legitimate answer. An EXPIRED waiver is not, and the
    # distinction is the whole reason the registries carry expiry dates: an
    # exemption nobody renews is an exemption nobody re-examined.
    waiver = sc.get("artifact_provenance_waiver")
    if waiver:
        owner = waiver.get("owner")
        expires = waiver.get("expires")
        today = datetime.date.today()
        if not owner or not expires:
            print(f"waiver            : FAIL waiver without owner and expiry is not an exemption")
            print("VERDICT FAIL")
            return 1
        exp = expires if isinstance(expires, datetime.date) else datetime.date.fromisoformat(str(expires))
        if exp < today:
            print(f"waiver            : FAIL waiver expired {exp} (owner {owner}); "
                  f"an expired waiver is not an exemption")
            print("VERDICT FAIL")
            return 1
        print(f"waiver            : NA   live waiver, owner {owner}, expires {exp}")
        print("VERDICT PASS")
        return 0

    checks = []

    # --- P0: the citations resolve ------------------------------------------
    wf_rel = sc.get("workflow")
    ev_rel = sc.get("evidence")
    wf = os.path.normpath(os.path.join(base, wf_rel)) if wf_rel else None
    ev = os.path.normpath(os.path.join(base, ev_rel)) if ev_rel else None
    missing = [r for r, p in ((wf_rel, wf), (ev_rel, ev)) if not p or not os.path.exists(p)]
    checks.append(fmt("P0 citations", not missing,
                      f"{wf_rel} -> {'ok' if wf and os.path.exists(wf) else 'MISSING'}, "
                      f"{ev_rel} -> {'ok' if ev and os.path.exists(ev) else 'MISSING'}"))
    if missing:
        print("VERDICT FAIL")
        return 1

    lines = executable_lines(wf)
    text = "\n".join(lines)

    # --- P1: a real signing step (what the upstream row checks) -------------
    sign_lines = [l for l in lines if SIGN_RE.search(l)]
    # Every match is printed, not just the first. A PROMOTED finding from
    # mutation-testing this row: the upstream pattern's `attestations:`
    # alternative also matches the `attestations: write` entry of a GitHub
    # `permissions:` block, which is a declaration of intent and not a step. A
    # row that prints only its first match hides that; printing them all makes
    # a match list of ["permissions:", "attestations: write"] read as what it
    # is. See specs/workflows/release-permissions-only.yml.
    shown = "; ".join(re.sub(r"\s+", " ", l.strip())[:60] for l in sign_lines[:3])
    checks.append(fmt("P1 signing", bool(sign_lines),
                      f"{len(sign_lines)} executable line(s) match a signing/attestation mechanism"
                      + (f": [{shown}]" if sign_lines else
                         " -- the string may appear only in a comment, which is prose, not a gate")))

    if MODE == "signing-only":
        # This mode IS the upstream probe row: citations plus a keyword match
        # for a signing mechanism. It exists so the demo can show, rather than
        # assert, what that row cannot see.
        print("VERDICT " + ("PASS" if all(checks) else "FAIL"))
        return 0 if all(checks) else 1

    # --- P2: the transparency log is actually written to ---------------------
    if MODE != "no-tlog-check":
        disabled = [l.strip() for l in lines if NO_TLOG_RE.search(l)]
        ok = not disabled
        checks.append(fmt("P2 log upload", ok,
                          "no executable line disables transparency-log upload" if ok else
                          f"transparency-log upload is DISABLED: {disabled[0][:80]} "
                          f"-- the signature proves custody of a key and nothing about when"))

    # --- P3: something verifies, and is not told to look away ---------------
    verify_lines = [l for l in lines if VERIFY_RE.search(l)]
    blinded = [l.strip() for l in lines if IGNORE_TLOG_RE.search(l)]
    if not verify_lines:
        checks.append(fmt("P3 verify", False,
                          "no verification step: the pipeline produces provenance and consumes none of it"))
    elif blinded:
        checks.append(fmt("P3 verify", False,
                          f"verification is told to ignore the log: {blinded[0][:80]}"))
    else:
        checks.append(fmt("P3 verify", True,
                          f"{len(verify_lines)} verification step(s): {verify_lines[0].strip()[:70]}"))

    # --- P4: the verification is anchored offline ---------------------------
    if MODE != "no-anchor-check":
        offline = [l for l in verify_lines if OFFLINE_RE.search(l)]
        online = [l for l in verify_lines if ONLINE_ONLY_RE.search(l)]
        if offline:
            checks.append(fmt("P4 offline anchor", True,
                              f"{len(offline)} verification step(s) settle against material on disk: "
                              f"{offline[0].strip()[:60]}"))
        elif online:
            checks.append(fmt("P4 offline anchor", False,
                              "the verification ASKS THE LOG at verify time; the answer is only as "
                              "good as the log's honesty at that instant"))
        else:
            checks.append(fmt("P4 offline anchor", False,
                              "no verification step names a bundle, a signed checkpoint or an offline mode"))

    # --- P5: the evidence records a measurement, not a word -----------------
    if MODE != "no-evidence-check":
        body = open(ev, encoding="utf-8").read()
        has_index = re.search(r"log index\s*:\s*\d+", body)
        has_time = re.search(r"integrated time\s*:\s*\d+", body)
        roots = re.findall(r"^\s*(?:recomputed root|root the log SIGNED)\s*:\s*([0-9a-f]{64})\s*$",
                           body, re.M)
        verdict = re.search(r"VERDICT INCLUSION: VERIFIED\s+\((\d+) checks, 0 failed\)", body)
        ok = bool(has_index and has_time and len(roots) >= 2 and verdict)
        detail = (f"log index, integrated time, {len(roots)} recomputed/signed root(s), "
                  f"{verdict.group(1) if verdict else 0} checks with 0 failed")
        if not ok:
            detail = (f"the cited evidence does not record a verification: "
                      f"log index {'yes' if has_index else 'NO'}, "
                      f"integrated time {'yes' if has_time else 'NO'}, "
                      f"roots {len(roots)}, "
                      f"verdict line {'yes' if verdict else 'NO'}")
        checks.append(fmt("P5 evidence", ok, detail))

    print("VERDICT " + ("PASS" if all(checks) else "FAIL"))
    return 0 if all(checks) else 1


if __name__ == "__main__":
    sys.exit(main())
