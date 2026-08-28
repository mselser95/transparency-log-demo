#!/usr/bin/env python3
"""Build a Rekor entry that is a complete fiction and passes a CORRECT
inclusion-proof verification.

Used by `TXL_CONTROL=unanchored-root`, which is the control that matters most
in this repo, so it is worth being precise about what is forged and what is
not.

WHAT IS REAL in the document this writes:
  * the artifact hash -- SHA-256 of a file genuinely on disk;
  * the signature -- genuinely made by the demo's signing key, over that file,
    and it genuinely verifies;
  * the entry UUID -- genuinely SHA-256(0x00 || body) of the body below, so the
    entry's own name is self-consistent;
  * the checkpoint -- copied verbatim from the LIVE LOG. It is genuinely signed
    by the log's key and that signature genuinely verifies.

WHAT IS FORGED:
  * the audit path. Three sibling hashes, invented.
  * `rootHash`. Computed by running RFC 6962's own algorithm forwards over the
    invented path, so that a verifier which recomputes the path and compares
    the result against this field gets a MATCH. Every step of that arithmetic
    is correct. It is anchored to nothing.
  * `logIndex`, `treeSize`, `integratedTime`: numbers.

The entry was never uploaded to anything. There is no log in the world in which
it appears. A verifier that does the Merkle recomputation correctly and then
compares the answer against the root that arrived in the same response will
say VERIFIED, because both halves of that comparison came from the same
author -- and that describes a very large fraction of the code people write
after reading RFC 6962.

The only thing that catches it is comparing the recomputed root against a root
the LOG SIGNED. That is what `--anchor=signed-checkpoint` does, and it is the
difference between an inclusion proof and a well-formed assertion.

    forge-unanchored-entry.py <artifact> <signature.b64> <signer.pub> \
                              <real-entry.json> <out.json>
"""
import base64
import hashlib
import json
import sys


def node(l: bytes, r: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + l + r).digest()


def root_from_path(leaf: bytes, index: int, size: int, path: list[bytes]) -> bytes:
    """RFC 6962 section 2.1.1, forwards. The same arithmetic the verifier does."""
    r, fn, sn = leaf, index, size - 1
    for p in path:
        if sn == 0:
            raise ValueError("path longer than the tree is deep")
        if fn % 2 == 1 or fn == sn:
            r = node(p, r)
            while fn != 0 and fn % 2 == 0:
                fn >>= 1
                sn >>= 1
        else:
            r = node(r, p)
        fn >>= 1
        sn >>= 1
    if sn != 0:
        raise ValueError("path shorter than the tree is deep")
    return r


def main() -> int:
    artifact, sig_path, pub_path, real_entry_path, out = sys.argv[1:6]

    art = open(artifact, "rb").read()
    art_sha = hashlib.sha256(art).hexdigest()
    sig_b64 = open(sig_path).read().strip()
    pub_pem = open(pub_path, "rb").read()

    body_obj = {
        "apiVersion": "0.0.1",
        "kind": "hashedrekord",
        "spec": {
            "data": {"hash": {"algorithm": "sha256", "value": art_sha}},
            "signature": {
                "content": sig_b64,
                "publicKey": {"content": base64.b64encode(pub_pem).decode()},
            },
        },
    }
    body = json.dumps(body_obj, separators=(",", ":"), sort_keys=True).encode()
    leaf = hashlib.sha256(b"\x00" + body).digest()

    # The invented siblings. Deterministic so two runs of this control produce
    # the same document and a reader can diff them.
    index, size = 3, 8
    path = [hashlib.sha256(f"txl-invented-sibling-{i}".encode()).digest() for i in range(3)]
    root = root_from_path(leaf, index, size, path)

    real = json.load(open(real_entry_path))
    real_uuid = next(iter(real))
    real_entry = real[real_uuid]
    tree_prefix = real_uuid[: len(real_uuid) - 64]  # the log's tree id, as hex
    checkpoint = real_entry["verification"]["inclusionProof"]["checkpoint"]

    forged_uuid = tree_prefix + leaf.hex()
    doc = {
        forged_uuid: {
            "body": base64.b64encode(body).decode(),
            "integratedTime": real_entry["integratedTime"],
            "logID": real_entry["logID"],
            "logIndex": index,
            "verification": {
                # Copied verbatim from the live log. It VERIFIES. It commits to
                # a root that has nothing to do with the path above.
                "inclusionProof": {
                    "checkpoint": checkpoint,
                    "hashes": [h.hex() for h in path],
                    "logIndex": index,
                    "rootHash": root.hex(),
                    "treeSize": size,
                },
                # Also copied verbatim, and it will NOT verify over this body.
                # Left in on purpose: the forged document is as complete as a
                # real one, so the only thing distinguishing them is whether
                # anybody checks the log's signatures.
                "signedEntryTimestamp": real_entry["verification"]["signedEntryTimestamp"],
            },
        }
    }
    json.dump(doc, open(out, "w"))

    signed_root = base64.b64decode(checkpoint.split("\n")[2]).hex()
    print(f"   forged entry file  : {out}")
    print(f"   artifact           : {artifact}  sha256:{art_sha}")
    print("   signature          : REAL -- made by the demo's signing key over that file")
    print(f"   invented siblings  : {len(path)}  (index {index} of a claimed tree size {size})")
    print(f"   rootHash written   : {root.hex()}   <- computed from the invented path")
    print(f"   checkpoint copied  : REAL, signed by the live log, committing to")
    print(f"                        {signed_root}")
    print("   the two roots      : differ. Nothing in the forged document says so.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
