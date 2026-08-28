# The transparency log entry, verified offline — a demo you can run

This directory demonstrates a supply-chain property: **a signature proves
custody of a key and nothing more. An entry in an append-only transparency log
adds WHEN, and makes the ABSENCE of an entry something a third party can
notice. An inclusion proof verified OFFLINE — recomputing the Merkle path
yourself and comparing the result against a root the log SIGNED — is what turns
"the log says my artifact is in there" into "the log cannot have said otherwise
without me noticing".**

Everything runs on a laptop, against a real [Rekor][rekor] transparency log in
five pinned containers. Every docker name is `txl-`-prefixed and lives on its
own `txl-net` network; exactly one port is published, `7990`. No cloud, no paid
service, no Kubernetes. The only network traffic is the image pull and one
pinned, checksum-verified `cosign` download.

**~85 seconds** from a clean clone on an M-series Mac, measured. The controls
are full runs of the same length.

---

## What this adds to `image-signing-demo`

This extends the collection's [`image-signing-demo`][isd], and the extension is
precise enough to state in one line: that demo proves **who**, this one proves
**when** and **that anyone can check**.

`image-signing-demo` holds a signing key in a vault it cannot leave, signs an
image *by digest*, and has an admission controller refuse anything unsigned. It
is right about everything it claims. And it signs like this:

```
"$COSIGN" sign --yes --tlog-upload=false --allow-insecure-registry \
  --key "hashivault://${KEY}" ...
```

`--tlog-upload=false`, deliberately — that demo's verifier checks a key, and a
log would be a dependency it does not need. Three things follow, and none of
them are defects in that demo; they are the boundary of what a signature is:

1. **There is no time in a signature.** A release signed today and a release
   signed by a key stolen in March are the same object. Revoking the key
   invalidates both, which is why revocation is so expensive: without a
   timestamp there is no way to keep the good signatures.
2. **A signature that exists only where its maker put it cannot be missed.** If
   an attacker with the key signs one artifact, for one target, and publishes it
   nowhere else, there is no place anyone could look to notice. Suppression is
   free.
3. **Both of those are invisible to the framework's own gate.** The
   `artifact-provenance` row in `_shared/probes/verify-standard.sh` passes that
   configuration. It is measured below, by running the row's own code.

This demo signs against a log, fetches the inclusion proof, and verifies it
**offline** — with a program that opens no sockets, recomputes the RFC 6962
audit path itself, and refuses to compare the answer against anything but a root
the log put its signature on.

---

## Run it

Requires `docker`, `go`, `python3` with PyYAML, `jq`, `curl`, `shasum`,
`openssl`, `tar` and `git` — all checked at step 1, so a missing one fails
before a container exists rather than four minutes in.

```bash
./run-demo.sh                                    # the validated run; exits 0
TXL_CONTROL=tampered-entry    ./run-demo.sh      # exits 1 — a rewritten entry
TXL_CONTROL=never-uploaded    ./run-demo.sh      # exits 1 — a perfect signature, no entry
TXL_CONTROL=unanchored-root   ./run-demo.sh      # exits 1 — correct arithmetic, anchored to nothing
TXL_CONTROL=self-check        ./run-demo.sh      # exits 1 — substitute `return 0` for the verifier
./teardown.sh                                    # removes everything and COUNTS what survives
```

Every run begins by tearing down, so it is idempotent. `teardown.sh` removes
containers **by name**, removes one network **by name**, never runs
`docker system prune`, and never touches the shared `kind` network or anything
it did not create — several other demos are running on this machine at the same
time.

**A demo that cannot fail proves nothing.** Each control is a full run, executes
the failure rather than describing it, and exits non-zero naming *which property
the run did not establish* — never merely that something went wrong.

---

## The sources

**Newman, Z., Meyers, J. S. & Torres-Arias, S., "Sigstore: Software Signing for
Everybody".** *Proceedings of the 2022 ACM SIGSAC Conference on Computer and
Communications Security (CCS '22)*, Los Angeles, November 2022, pp. 2353–2367.
DOI [10.1145/3548606.3560596][sigstore-doi]. The system this demo runs. Its
argument is that signing fails in practice not because the cryptography is hard
but because key management is, and that the way out is ephemeral keys plus a
public, append-only log — so that what a verifier checks is not "do I trust this
key forever" but "was this signature made, by this identity, at a time this log
witnessed". This demo uses a long-lived key rather than an ephemeral one,
because Fulcio needs an OIDC identity provider and this must run on a laptop
with no cloud; that is a real divergence from the paper and it is listed under
*what this does not prove*.

**Laurie, B., Langley, A. & Kasper, E., "Certificate Transparency".** RFC 6962,
IETF, June 2013. DOI [10.17487/RFC6962][rfc6962]. Section 2.1 defines the Merkle
Tree Hash; 2.1.1 the audit path and its verification; 2.1.2 the consistency
proof. `verifier/merkle.go` is an implementation of those three sections, and
`verifier/merkle_test.go` is a **second, independent** implementation of the same
three sections in the RFC's own recursive form, used to calibrate the first.

**Merkle, R. C., "A Digital Signature Based on a Conventional Encryption
Function".** *Advances in Cryptology — CRYPTO '87*, LNCS 293, Springer, 1988,
pp. 369–378. DOI [10.1007/3-540-48184-2_32][merkle]. The tree. What RFC 6962
adds to it is the domain separation (`0x00` for leaves, `0x01` for interior
nodes) that makes a second preimage on the root inconstructible, and the
consistency proof that makes the *append-only* claim checkable rather than
promised.

`_shared/tier-policy.yaml`, `_shared/dimensions.md` §9 and
`_shared/probes/verify-standard.sh` are quoted verbatim throughout; they are
this framework's own text, not an external source.

---

## What you should see, and what each line proves

Numbers are from the recorded run in the evidence files here. The log's key,
its tree ID, and every root are generated fresh on each run and will differ;
verdicts and counts do not.

| Step | What it prints | What that proves |
|---|---|---|
| 2/12 | `CALIBRATION inclusion: sizes 1..16, valid (leaf,size) pairs verified: 136, mutants rejected: 604, mutants accepted: 0` | **The detector is calibrated on a known-good case before it is pointed at anything, with counts in both directions.** The known-good case is RFC 6962's own recursive definition, implemented separately in `merkle_test.go`. 136 valid proofs accepted *and* 604 corrupted ones refused: a detector that accepts everything also accepts the truth, so the positive count alone would mean nothing. |
| 2/12 | `CALIBRATION consistency: … verified: 136, mutants rejected: 555, mutants accepted: 0` | Same, for the append-only proof. Both counts come out of `go test -v`, so they are recomputed on every run rather than quoted. |
| 2/12 | `CALIBRATION domain separation: 3 distinctions asserted, 0 collisions` | The `0x00`/`0x01` prefixes are present and load-bearing. Their absence is invisible — every root still matches every proof — and only a second-preimage attack notices. |
| 4/12 | `root hash now : e3b0c442…b855` and `SHA-256('') : e3b0c442…b855`, asserted equal | The empty log's root is **a value a reader can check**, not a claim the log makes about itself. It is the first thing in the run that is verified rather than reported, and it is one line of RFC 6962 §2.1. |
| 4/12 | `SHA-256 of that key : 23734c98…` and later `key hint 23734c98 = SHA-256(log key)[:4] = logID prefix` | The log's identity is a **derived** value, not a name. A checkpoint that verifies is worth something only if it verifies under the key you were told to expect, and this is the arithmetic that ties the two together. |
| 5/12 | `cosign darwin-arm64: sha256 4d41cc18… == the pin` | The tool is pinned **and checked**, not named. `tier-policy.yaml`'s `gate_tooling_pinned: immutable_identifier` says a tag is not a pin; neither is a version number in a comment. |
| 6–8/12 | three releases, then the artifact at index 3, then four more; `tree size 8` | **The audit path has three sibling hashes and the RFC 6962 loop takes both of its branches.** A leaf at index 0 of a tree of size 1 has an EMPTY path: the root *is* the leaf, the comparison succeeds without walking anything, and a demo that verified that would be reporting on arithmetic it never performed. The first version of this script did exactly that, and printed green. |
| 9/12 | `entries in the log: 8`, `verified offline: 8`, `refused: 0`, `audit path lengths: 3 3 3 3 3 3 3 3`, `tampered mutants REFUSED: 8`, `ACCEPTED: 0` | **The second calibration, on the live log**, covering everything the RFC calibration cannot: Rekor's wire format, its canonical leaf bytes, its note format, its signatures. Both directions, counted, before any of it is used to make a claim. |
| 10/12 | ten numbered checks, all `PASS`, then `recomputed root : a1fc76de…` beside `root the log SIGNED: a1fc76de…` | **The property.** The path was walked here, the root was recomputed here, and the comparison is against a root inside a note the log signed — printed next to each other so the reader does the comparison too. |
| 10/12 | `[ 9] signed-entry-timestamp PASS the log signed integratedTime=1787929748 (2026-08-28T15:09:08Z)` | **WHEN is a signed fact.** Without the Signed Entry Timestamp, `integratedTime` is a number in a JSON document that anyone can edit. This check is the whole reason a log is worth more than a signature. |
| 10/12 | `[ 5] leaf-hash PASS SHA-256(0x00||body) = ad64e7c5… = the uuid suffix` | The entry's own name is a checkable value: a Rekor UUID is the tree ID followed by the leaf hash. An entry whose body was edited after it was logged no longer matches its own identifier. |
| 10/12 | the same verifier against a self-consistent forgery: `VERDICT INCLUSION: REFUSED (10 checks, 2 failed: root-anchor, signed-entry-timestamp)`, `exit 1` | **The negative is executed inside the positive run.** A validated run that only walks the happy path is a happy path with a control bolted on beside it. |
| 11/12 | `index search … -> 1 entry/entries` and, for an artifact nobody signed, `-> 0 entries` | **Suppression is detectable.** A signature can be made and kept private; an entry cannot. Its *absence* is as checkable as its presence, which is how a signature the key's owner never made becomes something somebody could notice. |
| 11/12 | `[ 3] append-only PASS 1 node(s) prove size 4 is a prefix of size 8`, between two checkpoints this run captured minutes apart | **The log did not rewrite its own history.** This is the half an inclusion proof cannot give you: an inclusion proof says "my entry is under root R", a consistency proof says "the root you signed earlier is a prefix of the root you signed now". |
| 11/12 | the same check on a proof with one hex digit changed: `REFUSED`, `exit 1` | Non-vacuity of that check, in the validated run. |
| 12/12 | `fixtures: 8   passed by the row as shipped: 7` | **The gap, measured by running the shipped gate's own code.** Seven of eight CI-workflow fixtures pass the `artifact-provenance` row that `verify-standard.sh` ships today. Exactly one of the eight signs, logs, and verifies the inclusion proof offline. |
| 12/12 | `cases: 12   mismatches: 0` / `ROW SELF-CHECK OK` | The reference row was run against every fixture and its exit code compared with the one the fixture was written to produce. A row nobody has run against a known-bad input has a FAIL branch that has never executed. |
| 12/12 | `mutations: 5   without a flip: 0` / `NON-VACUITY OK` | Each of the row's predicates is **load-bearing, proven by removing it**: the same file flips FAIL → PASS. A predicate whose removal changes no verdict on any input was never a gate. |

---

## The four ways to be wrong, each executed

### `TXL_CONTROL=tampered-entry` — a rewritten record

One bit inside the logged record is changed. The audit path, the signed
checkpoint and the Signed Entry Timestamp are left byte-identical to what the
log returned, and the record stays well-formed JSON of the right kind.

```
   [ 5] leaf-hash              FAIL  SHA-256(0x00||body) = 89dd86d904… but the uuid is 3397386283…a0238ae267cca246 -- the body was altered after it was logged
   [ 7] root-anchor            FAIL  recomputed aa3baf764ac0ca19…, the SIGNED checkpoint commits to 33302f9694c9ef8a…
   VERDICT INCLUSION: REFUSED   (10 checks, 4 failed: entry-signature, leaf-hash, root-anchor, signed-entry-timestamp)

!! NOT PROVEN: that this artifact is in the log.
     recomputed from the tampered record : aa3baf764ac0ca19224ceca09eb3bf09c9f08733388964f7429bc61812f9ee56
     root the log SIGNED                 : 33302f9694c9ef8a54379a077d5073f3d3e7fab5bdc6014556db0f2b701bb23a
```

The tamper script contains a **round-trip control** that matters more than it
looks: it serialises the *unchanged* record first and requires the result to be
byte-identical to what the log stored. Without that, a hash divergence caused by
this script's own JSON formatting would read exactly like a detected tamper —
a green light wired to the wrong wire, in the direction that looks like success.

### `TXL_CONTROL=never-uploaded` — a perfect signature, and no entry

The one people assume is covered by "we sign everything". The artifact is signed
with `--tlog-upload=false`, which is the sibling demo's configuration.

```
   WARNING: Skipping tlog verification is an insecure practice ...
   Verified OK
   cosign verify-blob exit : 0

   index search for sha256:e7ce99475b3e30a07537f778... -> 0 entries
      [ 1] log-entry-present      FAIL  the log holds 0 entries for this artifact; a signature alone carries no timestamp and no witness

!! NOT PROVEN: when this artifact was signed, or that any third party can ever see that the signature exists.
```

The signature is not weak, or misconfigured, or expired. `cosign verify-blob`
returns 0. It was made by the expected key over exactly these bytes. What it
cannot do is distinguish a release signed today from one signed by a key stolen
in March, and it cannot be used to *notice* a signature the key's owner never
made, because noticing requires somewhere to look.

### `TXL_CONTROL=unanchored-root` — correct arithmetic, anchored to nothing

**The control to read twice.** A forged entry, verified by a verification that
recomputes the RFC 6962 audit path *correctly* and compares the answer against
the `rootHash` field of the same response the path arrived in.

```
   [ 3] entry-signature        PASS  verifies over the artifact, signer key sha256:5d9d0adf
   [ 5] leaf-hash              PASS  SHA-256(0x00||body) = f202038e4ed238a4… = the uuid suffix
   [ 6] merkle-path            PASS  3 sibling hash(es), index 3 of tree size 8 -> root 182e25dfa183c71c…
   [ 7] root-anchor            PASS  recomputed root == the rootHash field OF THE SAME RESPONSE (self-consistent; anchored to nothing)
   VERDICT INCLUSION: VERIFIED  (10 checks, 0 failed)
   exit 0
```

Every step of that is right. The entry is a fiction: it was never uploaded to
anything, the audit path is three hashes this demo invented, and `rootHash` was
computed *forwards* from that invented path so the comparison would succeed.
Both halves of the comparison had the same author.

Everything else in the document is genuine — the artifact hash is real, the
signature is real and verifies, the UUID is a real `SHA-256(0x00||body)` of its
own body, and the checkpoint is copied verbatim from the live log and is
genuinely signed by it. The control then runs the **same document** with the
anchor put back:

```
   [ 7] root-anchor            FAIL  recomputed 182e25dfa183c71c…, the SIGNED checkpoint commits to 61d68dd9baf42f83…
   [10] signed-entry-timestamp FAIL  ECDSA signature does not verify
   VERDICT INCLUSION: REFUSED   (10 checks, 2 failed: root-anchor, signed-entry-timestamp)
   exit 1

!! NOT PROVEN: that the root this verification recomputed is a root any log ever committed to.
```

This is the class worth naming, because the code that has it is not sloppy code.
It reads RFC 6962, implements §2.1.1 correctly, tests it against the spec, and
never asks where the root came from. It is the same shape as the sibling
`canary-abort-demo`'s sharpest control — a *correct* statistical analysis that
promotes a broken build — and it is here for the same reason: the failure a
whole class of check cannot see is worth more than four failures it can.

### `TXL_CONTROL=self-check` — substitute `return 0`

Every verification in the run is performed by `bin/txl-verify-stub`, a binary
that prints a successful verification and exits 0 **without opening a single
file**. The run's own assertions must catch it, and the run counts how many did.

```
   CATCH 1 of 3 FIRED: the calibration accepted 8 tampered entries, ...
   CATCH 2 of 3 FIRED: a self-consistent forgery was accepted, ...
   CATCH 3 of 3 FIRED: a corrupted consistency proof was accepted.

!! NOT PROVEN: that this artifact is in the log.
   What this run DID prove is that the validated run's success assertions are
   load-bearing. A verifier substituted with `return 0` was caught in 3 of 3 places
```

If fewer than three fire, the run fails with a different message — *the other
N are decoration and the validated run's green is worth less than it looks*.
Asserting that a check is load-bearing is not the same as substituting `return
0` and watching the gate notice; this is the second one.

---

## How this becomes a production-skills gate

**Dimension:** `_shared/dimensions.md` **§9 Security**, whose inventory names
"artifact signing/provenance" and whose Row line is *"each supply-chain gate
present/absent"*.

**Tier-policy key:** `supply_chain.artifact_provenance`, in the `defaults` block
and again at tier 0 of `_shared/tier-policy.yaml`:

```yaml
supply_chain: { secret_scan: all_triggers, vuln_scan: required, sbom: required,
                artifact_provenance: required, secretless_presubmit: required }
```

**A probe row for this key DOES exist** — `_shared/probes/verify-standard.sh`,
the `artifact-provenance` row. It is quoted here in full because the finding is
not that it is missing:

```bash
wf_exec="$(grep -rhE "^[^#]*" $wf/*.yaml 2>/dev/null | sed 's/#.*//' || true)"
if grep -qE "cosign|--provenance=|actions/attest|attestations:" <<<"$wf_exec"; then
  row "artifact-provenance" PASS "signing/attestation step present"
elif waived artifact-provenance-signing; then
  row "artifact-provenance" NA "live waiver with owner+expiry in registries/waivers.yaml"
else row "artifact-provenance" FAIL "no provenance and no live waiver (an expired or missing waiver is not an exemption)"; fi
```

Note first what it does **right**, because this is a careful row: it strips
comments before matching (an earlier version PASSed on a comment that *explained
why provenance was impossible*), and it reads into a variable rather than piping
into `grep -q` (which under `pipefail` reports FALSE on exactly the runs where
the pattern WAS found). Both are scars.

What remains is a **keyword match**, and a keyword cannot see a flag.
`scripts/upstream-row-as-shipped.sh` reproduces the two load-bearing lines
character for character and runs them over eight CI-workflow fixtures. The
result is in `07-gate-artifact-provenance-row.txt`:

```
  release-comment-only.yml                   FAIL  "no provenance and no live waiver"
  release-no-tlog-but-verified.yml           PASS  "signing/attestation step present"
                                               matched: attestations: write
  release-permissions-only.yml               PASS  "signing/attestation step present"
                                               matched: attestations: write
  release-sign-no-tlog.yml                   PASS  "signing/attestation step present"
  release-sign-only.yml                      PASS  "signing/attestation step present"
  release-signed-logged-verified.yml         PASS  "signing/attestation step present"
  release-verify-ignore-tlog.yml             PASS  "signing/attestation step present"
  release-verify-online.yml                  PASS  "signing/attestation step present"

fixtures: 8   passed by the row as shipped: 7
```

Seven of eight pass. **One** of the eight signs, logs, and verifies the
inclusion proof offline.

### A finding this demo did not set out to make

`release-permissions-only.yml` contains **no signing step of any kind** and the
shipped row passes it. The pattern's `attestations:` alternative — there to
catch GitHub's artifact-attestation action — also matches the `attestations:
write` entry of a `permissions:` block, which is a declaration of intent and not
a step:

```
  release-permissions-only.yml   PASS  "signing/attestation step present"
                                   matched: attestations: write
```

So: copy the permissions block from GitHub's `attest-build-provenance`
documentation in anticipation of wiring it up next quarter, never wire it up,
and the supply-chain provenance gate goes green having found a YAML key. This
was surfaced by mutation-testing *this demo's own row* — the mutation
`TXL_ROW_MODE=signing-only` reproduces the upstream row, and running it across
the fixture set showed a PASS where no `cosign` string exists — and then
confirmed by executing the shipped code, not by reading it.

### The reference row

`scripts/provenance-row.py` is a **REFERENCE row**, offered because a row for
this key exists and is too weak, not because none does. Six predicates:

| | Predicate | What it separates |
|---|---|---|
| P0 | citations resolve | a row whose evidence was deleted must FAIL, not skip |
| P1 | a real signing step in the **executable** lines | (this is where the shipped row stops) |
| P2 | transparency-log upload not disabled | a signature from a timestamped, witnessed signature |
| P3 | a verification step that consumes the entry and is not `--insecure-ignore-tlog` | producing provenance from consuming it |
| P4 | that verification is anchored **offline** | verifying a proof from asking the log whether it is honest |
| P5 | the evidence records a measurement | a log index, an integrated time, two roots and a checks-failed count — not the word "verified" |

with `NA/PASS` for a waiver carrying an owner and a live expiry, and `FAIL` for
one that has expired. Twelve fixtures, twelve expected exit codes, zero
mismatches (`07-…`); five mutations, five flips (`08-…`).

### Where it travels: **[B] once per org**

This is an org-level control, not a per-repo one, and the reason is the anchor.
P4 asks what the recomputed root is compared against, and the honest answers —
a trusted-root bundle, a known log public key, a witness or monitor that keeps
old checkpoints so a consistency proof has something to be consistent *with* —
are all things a single repository cannot supply for itself. A repo that pins
its own idea of the log's key has anchored to a value it also controls, which is
the `unanchored-root` control one level up.

What ships once per org: the log (or the decision to use the public Sigstore
instance), the trusted-root distribution, the monitor that watches for
signatures nobody meant to make, and the verifier binary. What each repo then
does is one CI step and one `artifact_provenance` line in its spec.

---

## Files

| File | What it is |
|---|---|
| `run-demo.sh` | The whole demonstration, twelve steps, plus the four controls |
| `teardown.sh` | Removes containers, network, images and scratch; **counts survivors** |
| `verifier/merkle.go` | RFC 6962 §2.1, §2.1.1, §2.1.2, implemented from the text |
| `verifier/merkle_test.go` | A **second** implementation, in the RFC's recursive form, used to calibrate the first |
| `verifier/main.go` | `txl-verify`: ten offline checks for an inclusion proof, three for a consistency proof |
| `verifier/stub/main.go` | The deliberately vacuous verifier the self-check substitutes |
| `scripts/upstream-row-as-shipped.sh` | The shipped `artifact-provenance` row, reproduced verbatim and executed |
| `scripts/provenance-row.py` | The reference row: six predicates, four mutation modes |
| `scripts/gate.sh` | Row self-check: twelve fixtures, twelve expected exit codes |
| `scripts/gate-non-vacuity.sh` | Five predicate mutations, each required to flip FAIL → PASS |
| `scripts/tamper-entry.py` | One bit, with a byte-identical round-trip control |
| `scripts/forge-unanchored-entry.py` | The self-consistent forgery, with a precise list of what is real in it |
| `specs/workflows/*.yml` | Eight CI-workflow fixtures |
| `specs/production.*.yaml` | Twelve spec fixtures, including a ratified decline and an expired waiver |

| Evidence | Produced by |
|---|---|
| `01-log-identity.txt` | the log's key, its logID, and the empty tree's root checked against `SHA-256('')` |
| `02-calibration-rfc6962.txt` | `go test -v`: 136 + 136 valid, 604 + 555 mutants rejected |
| `03-calibration-live-log.txt` | 8 entries verified, 8 tampered mutants refused |
| `04-inclusion-proof-verified.txt` | the ten checks, the two roots, the integrated time |
| `05-entry-and-inclusion-proof.json` | the raw Rekor entry, so the wire shape can be read without running anything |
| `06-consistency-and-suppression.txt` | two signed checkpoints, the proof between them, and both index searches |
| `07-gate-artifact-provenance-row.txt` | the shipped row over 8 fixtures, then the reference row over 12 |
| `08-gate-non-vacuity.txt` | five mutations, five flips |
| `09-negative-tampered-entry.txt` | the `tampered-entry` control |
| `10-negative-never-uploaded.txt` | the `never-uploaded` control |
| `11-negative-unanchored-root.txt` | the `unanchored-root` control, both anchors |
| `12-negative-self-check.txt` | the `self-check` control, 3 of 3 catches |

Evidence 01–08 is written only by the validated run; 09–12 only by their own
control. A control cannot overwrite the file a reader would compare it against.
Because each run creates a fresh log with a fresh key, the roots and tree IDs in
09–12 belong to different log instances than those in 01–08; the verdicts and
counts are what carry across.

---

## Three things this cost to learn

Each is a comment in the code, because none of them announces itself.

- **`docker exec mysql mysql -u… ` is the wrong readiness probe for a client
  that connects over TCP.** This image's entrypoint brings mysqld up on the UNIX
  socket first, for its own initialisation, before it listens on 3306. Measured
  on the third run of this script: the socket probe went green after 14s, both
  Trillian containers started and immediately died with `dial tcp
  192.168.80.2:3306: connect: connection refused`, Rekor panicked on a Trillian
  it could not reach, and the run reported **"Rekor did not become ready within
  240s"** — a message about the wrong container, four minutes after the fault,
  never mentioning MySQL. The two earlier runs had passed only because the image
  was warm. The fix is `--protocol=TCP` plus a probe from another container on
  the network: measure what is used.

- **`docker images -q <repo>@sha256:…` returns empty for an image that is
  present.** It matches on repository:TAG, and a digest reference has no tag.
  The first teardown loop used it, printed `not present` for all four images,
  exited 0 on that branch, and left every one of them on the disk. What caught
  it was the **survivor count at the bottom of the file**, which is an
  independent measurement rather than a summary of the lines above — the exact
  reason it is written that way.

- **`sed -n '/root-anchor/p; /VERDICT/p'` prints the VERDICT line twice.** The
  verdict names every failed check, so a pattern matching a check name matches
  the summary too. Harmless in a demo's console output; the same shape one level
  over is a count of "how many checks failed" that is silently wrong.

And a fourth, from the sibling demos' shell-discipline list, which bit here as
well: `cmd | grep -q PATTERN` under `set -o pipefail` reports FALSE on exactly
the runs where the pattern **was** found — `grep -q` exits at the first match,
the writer takes SIGPIPE, and pipefail propagates 141. Nothing in this repo pipes
a producer into `grep -q`; every measurement captures into a variable and reads
`$?` with `|| rc=$?` so `set -e` does not abort the runs a control expects to
fail.

---

## What this demo does **not** prove

- **It does not use ephemeral keys, and that is the Sigstore paper's central
  idea.** The paper's argument is that keyless signing — a short-lived
  certificate bound to an OIDC identity, logged and then discarded — is what
  removes the key-management problem that makes signing fail in practice. That
  needs Fulcio and an identity provider; this demo runs on a laptop with no
  cloud, so it signs with a long-lived key pair. What is demonstrated here is
  the *log* half of Sigstore, not the *keyless* half.

- **The log's checkpoint key is generated in memory at boot.** The container runs
  `--rekor_server.signer=memory`. A real log's key is in an HSM, and the entire
  value of a signed checkpoint is that its signer cannot be impersonated. Every
  signature this demo verifies is real; the threat model in which it would matter
  is not.

- **It does not prove the log is honest, only that it is consistent with itself
  over the window this run observed.** A log can serve one view to one client
  and another to everybody else — a *split view* — and neither an inclusion proof
  nor a consistency proof detects that from inside a single client. Detecting it
  needs independent parties that see the log's checkpoints and compare them —
  RFC 6962 gives that job to its Monitor (§5.3) and Auditor (§5.4) roles, and
  §5.4 is explicit that it takes more than one client: *"All clients should
  gossip with each other, exchanging STHs at least; this is all that is required
  to ensure that they all have a consistent view."* This demo implements none of
  that. Its consistency proof compares two checkpoints **this same process**
  fetched from **the same endpoint**, minutes apart. That is a strictly weaker
  claim than "the log has one history", and it is the honest limit of what one
  laptop can show.

- **It does not prove the entry is about the right *build*.** The record binds a
  signature to bytes and a time. Whether those bytes came from the source they
  claim to is provenance attestation — a different artifact, a different
  verification, and `dimensions.md` §9's SBOM and attestation lines.

- **It does not prove a monitor exists.** The suppression argument at step 11 is
  that an absence is *checkable*, not that anyone is checking. A transparency
  log with no monitor watching for signatures its keys' owners never made is a
  place where evidence would be, if anyone looked. That monitor is the part that
  travels **[B] once per org**, and this demo does not build one.

- **The `self-check` control's louder branch has never fired.** If fewer than
  three of the three assertions caught the stub, the run says so in different
  words and fails. That branch has not executed in any run recorded here, so its
  message is untested text rather than observed output.

- **The reference row is not installed anywhere.** It runs against fixtures in
  this directory. Wiring it into `verify-standard.sh` — replacing a row that
  passes seven of eight fixtures with one that passes one — is a change to the
  probe, and the probe is TCB.

[rekor]: https://github.com/sigstore/rekor
[isd]: https://github.com/mselser95/image-signing-demo
[sigstore-doi]: https://doi.org/10.1145/3548606.3560596
[rfc6962]: https://doi.org/10.17487/RFC6962
[merkle]: https://doi.org/10.1007/3-540-48184-2_32
