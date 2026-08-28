#!/usr/bin/env python3
"""Flip ONE BIT inside a logged entry's body and write the result back out.

Used by `TXL_CONTROL=tampered-entry`. The bit is chosen inside the base64
signature blob so the entry stays well-formed JSON of the right kind -- the
point is a record that still looks like a record, not a corrupted file that
any parser would reject. Everything else in the document (the inclusion proof,
the signed checkpoint, the Signed Entry Timestamp) is left exactly as the log
returned it.

That is the realistic shape of the attack. Rewriting an entry in a log's
database is easy; producing a checkpoint that commits to the rewritten tree
requires the log's signing key, and producing one that is CONSISTENT with the
checkpoints already published requires it never to have been published. The
demo shows the second half failing.

    tamper-entry.py <in.json> <out.json>
"""
import base64
import json
import sys


def main() -> int:
    src, dst = sys.argv[1], sys.argv[2]
    doc = json.load(open(src))
    if len(doc) != 1:
        print(f"tamper-entry: expected exactly one entry, got {len(doc)}", file=sys.stderr)
        return 2
    uuid = next(iter(doc))
    entry = doc[uuid]

    body = base64.b64decode(entry["body"])
    parsed = json.loads(body)

    # ROUND-TRIP CONTROL, and it is not paranoia. This script re-serialises the
    # record after editing it. If the re-serialisation differed from Rekor's
    # canonical form even by a space, the leaf hash would change for that
    # reason and the control would "detect tampering" it did not perform --
    # a green light wired to the wrong wire, in the direction that looks like
    # success. So: serialise the UNCHANGED record first and require it to be
    # byte-identical to what the log stored.
    roundtrip = json.dumps(parsed, separators=(",", ":"), sort_keys=True).encode()
    if roundtrip != body:
        print("tamper-entry: this script's JSON serialisation is NOT byte-identical to "
              "Rekor's canonical form, so any hash divergence it produces would be an "
              "artefact of the round-trip and not of the tamper.", file=sys.stderr)
        print(f"  stored     : {body[:120]!r}", file=sys.stderr)
        print(f"  round-trip : {roundtrip[:120]!r}", file=sys.stderr)
        return 3

    sig = parsed["spec"]["signature"]["content"]

    # Deterministic: the byte at index 8 of the base64 signature string, one
    # bit. Deterministic matters -- a random tamper makes a control whose
    # output nobody can compare against a previous run.
    i = 8
    before = sig[i]
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    after = alphabet[(alphabet.index(before) + 1) % len(alphabet)]
    parsed["spec"]["signature"]["content"] = sig[:i] + after + sig[i + 1:]

    # Re-serialise the way Rekor canonicalises: sorted keys, no whitespace.
    new_body = json.dumps(parsed, separators=(",", ":"), sort_keys=True).encode()
    entry["body"] = base64.b64encode(new_body).decode()
    json.dump(doc, open(dst, "w"))

    print(f"   round-trip control : the UNCHANGED record re-serialises to the exact "
          f"{len(body)} bytes the log stored, so the divergence below is the tamper")
    print(f"   tampered file      : {dst}")
    print(f"   what was changed   : one base64 character of spec.signature.content, "
          f"position {i}: {before!r} -> {after!r}")
    print(f"   body length before : {len(body)} bytes")
    print(f"   body length after  : {len(new_body)} bytes")
    print("   left untouched     : the inclusion proof, the signed checkpoint, "
          "the Signed Entry Timestamp")
    return 0


if __name__ == "__main__":
    sys.exit(main())
