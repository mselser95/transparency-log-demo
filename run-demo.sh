#!/usr/bin/env bash
# A signature proves custody of a key. It does not prove WHEN.
#
# An entry in an append-only transparency log adds the time, and makes the
# ABSENCE of an entry something a third party can notice. An inclusion proof
# VERIFIED OFFLINE -- recomputing the Merkle path yourself and comparing the
# result against a root the log SIGNED -- is what turns "the log says my
# artifact is in there" into "the log cannot have said otherwise without me
# noticing".
#
# This demo stands up a real Rekor transparency log on the laptop, signs an
# artifact against it with cosign, and then verifies the inclusion proof with a
# program that opens no sockets. It prints the log index, the entry's
# integrated time, the root it recomputed and the root the log signed, side by
# side.
#
#   ./run-demo.sh                                    the validated run; exits 0
#   TXL_CONTROL=tampered-entry    ./run-demo.sh      exits 1 (a rewritten entry)
#   TXL_CONTROL=never-uploaded    ./run-demo.sh      exits 1 (a perfect signature, no entry)
#   TXL_CONTROL=unanchored-root   ./run-demo.sh      exits 1 (correct arithmetic, anchored to nothing)
#   TXL_CONTROL=self-check        ./run-demo.sh      exits 1 (substitute `return 0` for the verifier)
#   ./teardown.sh                                    removes everything and COUNTS
#
# Everything is `txl-`-prefixed and lives on its own docker network. Exactly one
# port is published, 7990. No cloud, no paid service, no Kubernetes; the only
# network traffic is the image pull and one pinned cosign download, and the
# download is checksum-verified.
#
# This extends the collection's image-signing-demo, which signs an image with a
# key held in a vault and refuses unsigned images at admission -- and which
# signs with `--tlog-upload=false`, deliberately. What that demo cannot tell you
# is WHEN a signature was made, or whether one exists that its key's owner never
# made. That is what this demo adds. See README.md.
#
# Sources: Newman, Meyers & Torres-Arias, "Sigstore: Software Signing for
# Everybody", ACM CCS 2022, pp. 2353-2367; Laurie, Langley & Kasper,
# "Certificate Transparency", RFC 6962, 2013; Merkle, "A Digital Signature
# Based on a Conventional Encryption Function", CRYPTO '87. Full citations in
# README.md.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="${HERE}/work"
BIN="${HERE}/bin"
cd "$HERE"

# --- pins --------------------------------------------------------------------
# Every image is pinned BY DIGEST, never by tag. The tag is in the comment so a
# human can read what the digest is; the digest is what docker resolves, so a
# moved tag cannot change what this demo runs. tier-policy.yaml's
# `gate_tooling_pinned: immutable_identifier` says a tag is not a pin.
#
# Rekor v1.4.2. Rekor v1 needs Trillian for the tree and MySQL underneath it.
# Rekor v2 (rekor-tiles) drops both and would be one container instead of five,
# but its image is not publicly pullable at the time of writing --
# `docker manifest inspect ghcr.io/sigstore/rekor-tiles/rekor-server:latest`
# returns `denied`. So: five containers, and the complexity is imposed rather
# than chosen.
REKOR_IMAGE='ghcr.io/sigstore/rekor/rekor-server@sha256:a8052cbed56cdfc6e134c5d405bce83458005cf9f8a9f627bc50b183785f1cbd'
REKOR_TAG='v1.4.2'
# Trillian v1.7.2. These three images are amd64-ONLY -- there is no arm64
# manifest -- so on an M-series Mac they run under emulation and `--platform
# linux/amd64` is REQUIRED. Without it docker picks the host platform, finds no
# matching manifest, and fails with a message about manifest lists that never
# mentions emulation.
TRILLIAN_SERVER_IMAGE='gcr.io/trillian-opensource-ci/log_server@sha256:d12a110a578d3ee71f5d9bc5e16b21348b7d57b89fc32b01f367099a5e0016cc'
TRILLIAN_SIGNER_IMAGE='gcr.io/trillian-opensource-ci/log_signer@sha256:195bd72513721db9a4b7e2360834c82d1979005d95e430b5a4a309d0e458369c'
TRILLIAN_DB_IMAGE='gcr.io/trillian-opensource-ci/db_server@sha256:c3d5e243a2995e6bd83479c59cf5f586244f0988f97429f44e3334da0a95a5d0'
TRILLIAN_TAG='v1.7.2'
# redis 7.4.1-alpine. Rekor's search index; it is what makes "is there an entry
# for this artifact hash?" answerable at all, which is the suppression half of
# the property.
REDIS_IMAGE='redis@sha256:c1e88455c85225310bbea54816e9c3f4b5295815e6dbf80c34d40afc6df28275'
REDIS_TAG='7.4.1-alpine'

# cosign 2.6.5, pinned and CHECKSUM-VERIFIED, and downloaded into ./bin even
# when a cosign is already on PATH.
#
# 3.x is not a drop-in: `cosign sign-blob --help` in 3.1.3 has no `--rekor-url`
# at all -- the service URLs come from a TUF-provided signing config -- so a
# demo built on the system cosign would sign against the PUBLIC Sigstore log or
# fail outright, depending on the machine. Neither is this demo. The sibling
# image-signing-demo pins 2.x for a DIFFERENT 3.x incompatibility; this is the
# second one the collection has hit, which is why the version is verified here
# rather than assumed.
COSIGN_VERSION='2.6.5'
cosign_sha256_for() { # cosign_sha256_for <os>-<arch>; from cosign_checksums.txt
  case "$1" in
    darwin-arm64) echo 4d41cc18f0563907c0c785b51db76e1d1af10db4422b605ba876b1758e1771ab ;;
    darwin-amd64) echo 0f8a1a70c81de9740a2b62e91307ff396ce54e7dd80568d42411bb2d9d44269c ;;
    linux-amd64)  echo c3b4f5410e608af03a5eb0aaac84a4313d8da131248e08ff1759ac70c79d1644 ;;
    linux-arm64)  echo 426193b4c5da4d4d643e822f48fe0cc8a476ca1782a272704831f5a0cef716d7 ;;
    *) echo "" ;;
  esac
}

# --- names (every one txl-prefixed) ------------------------------------------
NET=txl-net
C_DB=txl-mysql
C_TLS=txl-trillian-log-server
C_TSG=txl-trillian-log-signer
C_REDIS=txl-redis
C_REKOR=txl-rekor
# One published port, in the 7990s this batch was allocated. The other four
# containers talk over the docker network and publish nothing, so this demo
# occupies exactly one port on a machine other demos are running on.
REKOR_PORT=7990
REKOR="http://127.0.0.1:${REKOR_PORT}"

# The artifact's position in the log. Three releases land before it and four
# after, so its audit path has three sibling hashes and the RFC 6962 loop takes
# both of its branches.
#
# This is not decoration. A leaf at index 0 of a tree of size 1 has an EMPTY
# audit path: the root IS the leaf, the comparison succeeds without walking
# anything, and a demo that verified that would be reporting on arithmetic it
# never performed. The first version of this script did exactly that, and it
# printed a green verdict.
DECOYS_BEFORE=3
DECOYS_AFTER=4
TARGET_INDEX="$DECOYS_BEFORE"

CONTROL="${TXL_CONTROL:-}"
case "$CONTROL" in
  ''|tampered-entry|never-uploaded|unanchored-root|self-check) ;;
  *) echo "unknown TXL_CONTROL='${CONTROL}' (expected: tampered-entry | never-uploaded | unanchored-root | self-check)" >&2; exit 2 ;;
esac

# The never-uploaded control signs the artifact WITHOUT logging it, so the tree
# is one leaf shorter throughout and every size below has to say so. A run that
# waited for a size that will never arrive reports a timeout, and a timeout is
# the least informative thing a control can print.
if [ "$CONTROL" = "never-uploaded" ]; then
  SIZE_AT_SIGNING="$DECOYS_BEFORE"
  FINAL_SIZE=$((DECOYS_BEFORE + DECOYS_AFTER))
else
  SIZE_AT_SIGNING=$((DECOYS_BEFORE + 1))
  FINAL_SIZE=$((DECOYS_BEFORE + 1 + DECOYS_AFTER))
fi

say()  { printf '\n\033[1m== %s\033[0m\n' "$*"; }
note() { printf '   %s\n' "$*"; }
fail() { printf '\n\033[1;31m!! %s\033[0m\n' "$*" >&2; exit 1; }

# Print a "what this run did NOT prove" block and exit 1. A control that says
# only "error" has told you nothing about which property is missing.
notproven() {
  printf '\n\033[1;31m!! NOT PROVEN: %s\033[0m\n' "$1" >&2
  shift
  local l
  for l in "$@"; do printf '   %s\n' "$l" >&2; done
  exit 1
}

# Evidence files 01-08 describe the VALIDATED run. A control run must not
# overwrite them: a reader comparing 04 against a control's output would
# otherwise be comparing a file the control itself wrote.
ev() { # ev <filename>   -- reads stdin
  if [ -z "$CONTROL" ]; then cat > "${HERE}/$1"; else cat > /dev/null; fi
}

# curl with a timeout. Every measurement in this script captures output into a
# variable and reads the status separately, with `|| rc=$?` so `set -e` does not
# abort on the runs a control EXPECTS to fail. Nothing is ever piped into
# `grep -q`: under `pipefail` that reports FALSE on exactly the runs where the
# pattern WAS found, because grep exits at the first match and the writer takes
# SIGPIPE 141.
rget() { curl -sS --max-time 20 "$@"; }

wait_for() { # wait_for <seconds> <what> <command...>
  local budget="$1" what="$2"; shift 2
  local i
  for i in $(seq 1 "$budget"); do
    if "$@" >/dev/null 2>&1; then return 0; fi
    sleep 1
  done
  # A timeout must SAY what it was looking at. "Rekor did not become ready" sends
  # you to look at Rekor, and on the run that produced this function the actual
  # fault was two containers down the stack.
  echo "" >&2
  echo "--- last log lines from every container in the stack:" >&2
  local c
  for c in "$C_DB" "$C_TLS" "$C_TSG" "$C_REDIS" "$C_REKOR"; do
    if [ -n "$(docker ps -aq --filter "name=^${c}\$" 2>/dev/null)" ]; then
      echo "=== ${c}  ($(docker inspect -f '{{.State.Status}}' "$c" 2>/dev/null))" >&2
      docker logs --tail 8 "$c" 2>&1 | sed 's/^/    /' >&2
    fi
  done
  fail "${what} did not become ready within ${budget}s"
}

# A container that has already died is not "not ready yet"; it is a different
# failure, and waiting 240 seconds to report it as a timeout hides the reason.
ensure_running() { # ensure_running <container> <what it is>
  local c="$1" what="$2" state
  state="$(docker inspect -f '{{.State.Status}}' "$c" 2>/dev/null || echo missing)"
  if [ "$state" != "running" ]; then
    echo "" >&2
    echo "--- ${c} is ${state}; its last log lines:" >&2
    docker logs --tail 20 "$c" 2>&1 | sed 's/^/    /' >&2
    fail "${what} exited instead of starting"
  fi
}

tree_size() {
  local body
  body="$(rget "${REKOR}/api/v1/log" 2>/dev/null || true)"
  [ -n "$body" ] || { echo -1; return 0; }
  echo "$body" | jq -r '.treeSize // -1' 2>/dev/null || echo -1
}

wait_tree_size() { # wait_tree_size <n> <budget>
  local want="$1" budget="$2" i have=-1
  for i in $(seq 1 "$budget"); do
    have="$(tree_size)"
    if [ "$have" = "$want" ]; then return 0; fi
    sleep 1
  done
  fail "the log's tree never reached size ${want} (last seen: ${have}). Trillian's SIGNER is what integrates queued leaves; if it is not running, createLogEntry still returns 200 and nothing is ever sequenced."
}

# =============================================================================
say "1/12  Preflight: tools, pins, a free port, a clean slate"

for t in docker go python3 jq curl shasum openssl tar git sed awk base64; do
  command -v "$t" >/dev/null || fail "$t is required"
done
python3 -c 'import yaml' 2>/dev/null \
  || fail "python3 needs PyYAML (scripts/provenance-row.py parses the spec fixtures with it)"
note "docker  : $(docker version --format '{{.Server.Version}}')"
note "go      : $(go version)"
note "python3 : $(python3 -VV | head -1)"
note "cosign  : v${COSIGN_VERSION} (pinned; downloaded and checksum-verified at step 5)"
note "rekor   : ${REKOR_TAG}     ${REKOR_IMAGE##*@}"
note "trillian: ${TRILLIAN_TAG}  (log_server, log_signer, db_server; amd64-only, run under emulation)"
note "redis   : ${REDIS_TAG} ${REDIS_IMAGE##*@}"

# Tear down first, so the run is idempotent. The teardown removes containers BY
# NAME and never by pattern across the whole daemon: other demos are running on
# this machine right now.
TXL_KEEP_IMAGES=1 bash "${HERE}/teardown.sh" >/dev/null 2>&1 || true
/bin/rm -rf "$WORK" 2>/dev/null || true
mkdir -p "$WORK" "${WORK}/dist" "$BIN"

# A connect attempt, not `lsof`, because lsof is not guaranteed to exist. If
# something already answers on 7990 this demo must refuse to start rather than
# sign against whatever it is -- which is a small instance of the exact failure
# the demo is about.
if rget -o /dev/null "${REKOR}/api/v1/log" >/dev/null 2>&1; then
  fail "something is already answering on ${REKOR}; refusing to run"
fi
note "port ${REKOR_PORT} is free"

if [ -n "$CONTROL" ]; then
  note ""
  note "TXL_CONTROL=${CONTROL}  -- this run is EXPECTED to exit non-zero."
fi

# =============================================================================
say "2/12  The offline verifier, and CALIBRATION against RFC 6962's own construction"
note "The detector is calibrated on a known-good case BEFORE it is pointed at"
note "the log, with counts, so a later 'nothing was wrong' is evidence rather"
note "than silence. The known-good case is the RFC's own recursive definition of"
note "MTH, PATH and PROOF, implemented a SECOND time in verifier/merkle_test.go"
note "and cross-checked against the iterative verifier over every (leaf, tree"
note "size) pair up to size 16. Every positive count is paired with a mutation"
note "count, because a detector that accepts everything also accepts the truth."
export GOFLAGS=-mod=mod
export GOPROXY=off
export CGO_ENABLED=0
( cd "${HERE}/verifier" && go vet ./... ) || fail "go vet failed on the verifier"
( cd "${HERE}/verifier" && go build -o "${BIN}/txl-verify" . ) || fail "the verifier did not build"
( cd "${HERE}/verifier" && go build -o "${BIN}/txl-verify-stub" ./stub ) || fail "the stub verifier did not build"

TEST_RC=0
TEST_OUT="$( cd "${HERE}/verifier" && go test -v ./... 2>&1 )" || TEST_RC=$?
echo "$TEST_OUT" | sed -n 's/^ *merkle_test.go:[0-9]*: /   /p'
if [ "$TEST_RC" -ne 0 ]; then
  echo "$TEST_OUT" >&2
  fail "the verifier's calibration against RFC 6962 did not pass"
fi
CAL_VERIFIED="$(echo "$TEST_OUT" | sed -n 's/.*CALIBRATION inclusion:.*pairs verified: \([0-9]*\),.*/\1/p')"
CAL_REJECTED="$(echo "$TEST_OUT" | sed -n 's/.*CALIBRATION inclusion:.*mutants rejected: \([0-9]*\),.*/\1/p')"
CAL_ACCEPTED="$(echo "$TEST_OUT" | sed -n 's/.*CALIBRATION inclusion:.*mutants accepted: \([0-9]*\).*/\1/p')"
[ "${CAL_VERIFIED:-0}" -gt 0 ] || fail "the calibration reported zero verifications, so it measured nothing"
[ "${CAL_REJECTED:-0}" -gt 0 ] || fail "the calibration reported zero mutant rejections, so it is vacuous"
[ "${CAL_ACCEPTED:-1}" -eq 0 ] || fail "the calibration ACCEPTED ${CAL_ACCEPTED} mutant(s); the verifier is not reading the audit path"
note ""
note "calibration: ${CAL_VERIFIED} valid proofs accepted, ${CAL_REJECTED} mutants rejected, ${CAL_ACCEPTED} mutants accepted"
{
  echo "=== CALIBRATION: verifier/merkle.go against a second implementation of RFC 6962"
  echo
  echo "$TEST_OUT"
} | ev "02-calibration-rfc6962.txt"

# The verifier used for the rest of the run. `self-check` substitutes a binary
# that prints a successful verification and exits 0 without opening a file.
VERIFY="${BIN}/txl-verify"
if [ "$CONTROL" = "self-check" ]; then
  VERIFY="${BIN}/txl-verify-stub"
  note ""
  note "CONTROL self-check: every verification below runs txl-verify-stub, which"
  note "exits 0 unconditionally without opening a file. The run's own assertions"
  note "must catch it."
fi

# =============================================================================
say "3/12  A real transparency log, on this laptop: five pinned containers"

docker network create "$NET" >/dev/null 2>&1 || true
note "network ${NET}"

docker run -d --name "$C_DB" --network "$NET" --platform linux/amd64 \
  -e MYSQL_ROOT_PASSWORD=zaphod -e MYSQL_DATABASE=test \
  -e MYSQL_USER=test -e MYSQL_PASSWORD=zaphod \
  "$TRILLIAN_DB_IMAGE" >/dev/null
# PROBE THE PATH TRILLIAN WILL TAKE, not a path that happens to answer sooner.
#
# `docker exec txl-mysql mysql -utest ...` connects over the container's UNIX
# SOCKET, and this image's entrypoint brings mysqld up on the socket first, to
# run its own initialisation, before it ever listens on TCP. So the socket probe
# goes green while port 3306 is still refusing connections -- and Trillian, one
# container away, connects over TCP.
#
# Measured on 2026-08-28, third run of this script: the socket probe returned
# after 14s, both Trillian containers started, and both died immediately with
# `dial tcp 192.168.80.2:3306: connect: connection refused`. Rekor then panicked
# on a Trillian it could not reach, and the run reported "Rekor did not become
# ready within 240s" -- a message about the wrong container, four minutes after
# the actual fault, with no mention of MySQL anywhere. The two earlier runs had
# passed only because the image was already warm.
#
# --protocol=TCP forces the client onto the same transport, so what is measured
# is what is used. The cross-network probe after it is the real thing: a
# container on this network resolving the name and connecting, exactly as
# Trillian does.
wait_for 240 "the Trillian database (TCP)" \
  docker exec "$C_DB" mysql --protocol=TCP -h 127.0.0.1 -P 3306 -utest -pzaphod -e 'select 1' test
wait_for 60 "the Trillian database from another container on ${NET}" \
  docker run --rm --network "$NET" --platform linux/amd64 "$TRILLIAN_DB_IMAGE" \
    mysql -h "$C_DB" -P 3306 -utest -pzaphod -e 'select 1' test
note "${C_DB}      : up  (Trillian's storage; the tree lives here)"

docker run -d --name "$C_TLS" --network "$NET" --platform linux/amd64 "$TRILLIAN_SERVER_IMAGE" \
  --quota_system=noop --storage_system=mysql \
  --mysql_uri="test:zaphod@tcp(${C_DB}:3306)/test" \
  --rpc_endpoint=0.0.0.0:8090 --http_endpoint=0.0.0.0:8091 --alsologtostderr >/dev/null
sleep 3
ensure_running "$C_TLS" "the Trillian log server"
note "${C_TLS} : up  (serves the Merkle tree)"

# The SIGNER is what actually integrates queued leaves and produces a new
# signed tree head. Without it `createLogEntry` returns 200, the entry is
# queued, the tree size never moves, and every inclusion proof fails with a
# message about the tree that never says "the sequencer is not running".
docker run -d --name "$C_TSG" --network "$NET" --platform linux/amd64 "$TRILLIAN_SIGNER_IMAGE" \
  --quota_system=noop --storage_system=mysql \
  --mysql_uri="test:zaphod@tcp(${C_DB}:3306)/test" \
  --rpc_endpoint=0.0.0.0:8090 --http_endpoint=0.0.0.0:8091 --force_master --alsologtostderr >/dev/null
sleep 3
ensure_running "$C_TSG" "the Trillian log signer"
note "${C_TSG} : up  (sequences queued leaves into the tree)"

docker run -d --name "$C_REDIS" --network "$NET" "$REDIS_IMAGE" \
  --bind 0.0.0.0 --appendonly no >/dev/null
wait_for 60 "redis" docker exec "$C_REDIS" redis-cli ping
note "${C_REDIS}      : up  (Rekor's search index: 'is there an entry for this hash?')"

docker run -d --name "$C_REKOR" --network "$NET" -p "${REKOR_PORT}:3000" "$REKOR_IMAGE" \
  serve --trillian_log_server.address="$C_TLS" --trillian_log_server.port=8090 \
  --redis_server.address="$C_REDIS" --redis_server.port=6379 \
  --rekor_server.address=0.0.0.0 --rekor_server.signer=memory \
  --search_index.storage_provider=redis >/dev/null
wait_for 240 "Rekor" rget -o /dev/null "${REKOR}/api/v1/log"
note "${C_REKOR}      : up  on ${REKOR}"
note ""
note "The log signs its checkpoints with a key it generates in memory at boot"
note "(--rekor_server.signer=memory). That is a TEST configuration and it is said"
note "here rather than only in the README: a real log's key lives in an HSM, and"
note "the entire value of a checkpoint is that its signer cannot be impersonated."

# =============================================================================
say "4/12  The log's identity, and the value of an empty tree"

rget "${REKOR}/api/v1/log/publicKey" > "${WORK}/rekor.pub"
LOG_KEY_SHA="$(openssl pkey -pubin -in "${WORK}/rekor.pub" -outform DER 2>/dev/null | shasum -a 256 | cut -d' ' -f1)"
STH0="$(rget "${REKOR}/api/v1/log")"
SIZE0="$(echo "$STH0" | jq -r '.treeSize')"
ROOT0="$(echo "$STH0" | jq -r '.rootHash')"
EMPTY_SHA="$(printf '' | shasum -a 256 | cut -d' ' -f1)"
note "log public key      : $(sed -n 2p "${WORK}/rekor.pub" | cut -c1-48)..."
note "SHA-256 of that key : ${LOG_KEY_SHA}"
note "  ...which is the logID every entry carries, and whose first four bytes"
note "  are the key hint inside every signed checkpoint. A checkpoint that"
note "  verifies is worth something only if it is the key you were told to expect."
note "tree size now       : ${SIZE0}"
note "root hash now       : ${ROOT0}"
note "SHA-256 of ''       : ${EMPTY_SHA}"
[ "$ROOT0" = "$EMPTY_SHA" ] \
  || fail "the empty log's root is ${ROOT0}, but RFC 6962 2.1 says MTH({}) = SHA-256('') = ${EMPTY_SHA}"
note "  MTH({}) = SHA-256('') -- RFC 6962 2.1. The empty tree's root is a VALUE a"
note "  reader can check, not a claim the log makes about itself, and it matches."
note "  That is the first thing in this run that was verified rather than reported."
{
  echo "=== the log's identity, before anything was written to it"
  echo
  cat "${WORK}/rekor.pub"
  echo "SHA-256(DER public key) = logID = ${LOG_KEY_SHA}"
  echo "key hint (first 4 bytes)        = ${LOG_KEY_SHA:0:8}"
  echo
  echo "tree size    : ${SIZE0}"
  echo "root hash    : ${ROOT0}"
  echo "SHA-256('')  : ${EMPTY_SHA}   <- RFC 6962 2.1, MTH({})"
  echo
  echo "signed tree head:"
  echo "$STH0" | jq -r '.signedTreeHead'
} | ev "01-log-identity.txt"

# =============================================================================
say "5/12  cosign ${COSIGN_VERSION}, pinned and checksum-verified"

case "$(uname -s)/$(uname -m)" in
  Darwin/arm64)  PLAT=darwin-arm64 ;;
  Darwin/x86_64) PLAT=darwin-amd64 ;;
  Linux/aarch64) PLAT=linux-arm64 ;;
  Linux/arm64)   PLAT=linux-arm64 ;;
  Linux/x86_64)  PLAT=linux-amd64 ;;
  *) fail "no pinned cosign checksum for $(uname -s)/$(uname -m)" ;;
esac
WANT_SHA="$(cosign_sha256_for "$PLAT")"
[ -n "$WANT_SHA" ] || fail "no pinned cosign checksum for ${PLAT}"
COSIGN="${BIN}/cosign"
if [ ! -x "$COSIGN" ]; then
  curl -sSfL -o "$COSIGN" \
    "https://github.com/sigstore/cosign/releases/download/v${COSIGN_VERSION}/cosign-${PLAT}" \
    || fail "could not download cosign ${COSIGN_VERSION} for ${PLAT}"
  chmod +x "$COSIGN"
fi
GOT_SHA="$(shasum -a 256 "$COSIGN" | cut -d' ' -f1)"
[ "$GOT_SHA" = "$WANT_SHA" ] \
  || fail "cosign checksum mismatch for ${PLAT}: got ${GOT_SHA}, pinned ${WANT_SHA}"
note "cosign ${PLAT}: sha256 ${GOT_SHA}"
note "                == the pin"
note "$("$COSIGN" version 2>/dev/null | sed -n 's/^GitVersion: */GitVersion : /p')"

export COSIGN_PASSWORD=""
( cd "$WORK" && "$COSIGN" generate-key-pair --output-key-prefix txl >/dev/null 2>&1 ) \
  || fail "could not generate the signing key pair"
SIGNER_KEY="${WORK}/txl.key"
SIGNER_PUB="${WORK}/txl.pub"
note "signing key pair generated (the ARTIFACT's key; the log has its own)"

# =============================================================================
say "6/12  ${DECOYS_BEFORE} earlier releases land in the log"
note "Other teams' artifacts, so that the log is a shared log and the artifact"
note "this demo cares about has an audit path with siblings in it."

sign_and_log() { # sign_and_log <file>  -> prints the log index
  local f="$1" out rc=0
  out="$("$COSIGN" sign-blob --yes --key "$SIGNER_KEY" --rekor-url "$REKOR" \
          --bundle "${f}.bundle.json" "$f" 2>&1)" || rc=$?
  if [ "$rc" -ne 0 ]; then
    echo "$out" >&2
    return 1
  fi
  echo "$out" | sed -n 's/^tlog entry created with index: //p'
}

for i in $(seq 1 "$DECOYS_BEFORE"); do
  printf 'txl-other-team-release-%d\n' "$i" > "${WORK}/dist/other-${i}.tar.gz"
  idx="$(sign_and_log "${WORK}/dist/other-${i}.tar.gz")" \
    || fail "cosign could not sign other-${i}.tar.gz against ${REKOR}"
  note "other-${i}.tar.gz -> log index ${idx}"
done

# =============================================================================
say "7/12  The artifact this run is about"

ARTIFACT="${WORK}/dist/txl-payments-service-1.4.2.tar.gz"
tar -czf "$ARTIFACT" -C "$HERE" verifier scripts
ART_SHA="$(shasum -a 256 "$ARTIFACT" | cut -d' ' -f1)"
note "artifact : work/dist/txl-payments-service-1.4.2.tar.gz"
note "size     : $(wc -c < "$ARTIFACT" | tr -d ' ') bytes"
note "sha256   : ${ART_SHA}"

if [ "$CONTROL" = "never-uploaded" ]; then
  note ""
  note "CONTROL never-uploaded: signing with --tlog-upload=false. The signature"
  note "will be perfect. Nothing will be written to any log."
  SIG_RC=0
  SIG_OUT="$("$COSIGN" sign-blob --yes --key "$SIGNER_KEY" --tlog-upload=false \
              --output-signature "${WORK}/artifact.sig" "$ARTIFACT" 2>&1)" || SIG_RC=$?
  [ "$SIG_RC" -eq 0 ] || { echo "$SIG_OUT" >&2; fail "cosign could not sign the artifact"; }
  note "signature written to work/artifact.sig, and to no log anywhere"
else
  TARGET_IDX="$(sign_and_log "$ARTIFACT")" \
    || fail "cosign could not sign the artifact against ${REKOR}"
  note ""
  note "cosign uploaded the signature to the log: index ${TARGET_IDX}"
  [ "$TARGET_IDX" = "$TARGET_INDEX" ] \
    || fail "expected the artifact at log index ${TARGET_INDEX}, got ${TARGET_IDX}"
fi

wait_tree_size "$SIZE_AT_SIGNING" 180
STH_EARLY="$(rget "${REKOR}/api/v1/log")"
echo "$STH_EARLY" | jq -r '.signedTreeHead' > "${WORK}/checkpoint-${SIZE_AT_SIGNING}.txt"
note "the tree is now size ${SIZE_AT_SIGNING}; its signed tree head is saved as"
note "work/checkpoint-${SIZE_AT_SIGNING}.txt -- step 11 proves that head has not been rewritten."

# =============================================================================
say "8/12  ${DECOYS_AFTER} later releases; the tree grows to ${FINAL_SIZE}"
note "This is what gives the artifact's entry a real audit path. A leaf at index"
note "0 of a tree of size 1 has an EMPTY path: the root IS the leaf, every"
note "comparison succeeds trivially, and verifying it proves nothing about a"
note "Merkle path because none was walked."

for i in $(seq 1 "$DECOYS_AFTER"); do
  printf 'txl-other-team-later-release-%d\n' "$i" > "${WORK}/dist/later-${i}.tar.gz"
  idx="$(sign_and_log "${WORK}/dist/later-${i}.tar.gz")" \
    || fail "cosign could not sign later-${i}.tar.gz"
  note "later-${i}.tar.gz -> log index ${idx}"
done
wait_tree_size "$FINAL_SIZE" 180
STH_NOW="$(rget "${REKOR}/api/v1/log")"
echo "$STH_NOW" | jq -r '.signedTreeHead' > "${WORK}/checkpoint-${FINAL_SIZE}.txt"
note "tree size ${FINAL_SIZE}, root $(echo "$STH_NOW" | jq -r '.rootHash')"

# =============================================================================
say "9/12  CALIBRATION on the LIVE log: every entry, verified and then mutated"
note "Step 2 calibrated the arithmetic. This calibrates the whole path end to"
note "end -- Rekor's wire format, its canonical leaf bytes, its note format, its"
note "signatures -- on entries that were really uploaded, and then shows it can"
note "tell those from tampered ones. Counts, in both directions."

CAL_OK=0; CAL_BAD=0; CAL_MUT_REFUSED=0; CAL_MUT_ACCEPTED=0
CAL_PATHLENS=""
for i in $(seq 0 $((FINAL_SIZE - 1))); do
  rget "${REKOR}/api/v1/log/entries?logIndex=${i}" > "${WORK}/entry-${i}.json"
  ehash="$(python3 -c 'import base64,json,sys; d=json.load(open(sys.argv[1])); e=next(iter(d.values())); print(json.loads(base64.b64decode(e["body"]))["spec"]["data"]["hash"]["value"])' "${WORK}/entry-${i}.json")"
  src=""
  for f in "${WORK}"/dist/*.tar.gz; do
    if [ "$(shasum -a 256 "$f" | cut -d' ' -f1)" = "$ehash" ]; then src="$f"; break; fi
  done
  [ -n "$src" ] || fail "log index ${i} is about sha256:${ehash}, which matches no file this run produced"
  plen="$(jq -r '.[].verification.inclusionProof.hashes | length' "${WORK}/entry-${i}.json")"
  CAL_PATHLENS="${CAL_PATHLENS}${plen} "

  rc=0
  out="$("$VERIFY" inclusion --entry "${WORK}/entry-${i}.json" --artifact "$src" \
          --log-pubkey "${WORK}/rekor.pub" --signer-pubkey "$SIGNER_PUB" 2>&1)" || rc=$?
  if [ "$rc" -eq 0 ]; then
    CAL_OK=$((CAL_OK + 1))
  else
    CAL_BAD=$((CAL_BAD + 1))
    echo "$out" | sed 's/^/     /'
  fi

  python3 "${HERE}/scripts/tamper-entry.py" "${WORK}/entry-${i}.json" "${WORK}/entry-${i}.tampered.json" >/dev/null \
    || fail "the tamper script could not produce a mutant for log index ${i}"
  mrc=0
  "$VERIFY" inclusion --entry "${WORK}/entry-${i}.tampered.json" --artifact "$src" \
    --log-pubkey "${WORK}/rekor.pub" --signer-pubkey "$SIGNER_PUB" >/dev/null 2>&1 || mrc=$?
  if [ "$mrc" -ne 0 ]; then
    CAL_MUT_REFUSED=$((CAL_MUT_REFUSED + 1))
  else
    CAL_MUT_ACCEPTED=$((CAL_MUT_ACCEPTED + 1))
  fi
done

note ""
note "entries in the log        : ${FINAL_SIZE}"
note "verified offline          : ${CAL_OK}"
note "refused                   : ${CAL_BAD}"
note "audit path lengths        : ${CAL_PATHLENS}"
note "tampered mutants REFUSED  : ${CAL_MUT_REFUSED}"
note "tampered mutants ACCEPTED : ${CAL_MUT_ACCEPTED}"
{
  echo "=== CALIBRATION on the live log"
  echo "entries in the log        : ${FINAL_SIZE}"
  echo "verified offline          : ${CAL_OK}"
  echo "refused                   : ${CAL_BAD}"
  echo "audit path lengths        : ${CAL_PATHLENS}"
  echo "tampered mutants REFUSED  : ${CAL_MUT_REFUSED}"
  echo "tampered mutants ACCEPTED : ${CAL_MUT_ACCEPTED}"
} | ev "03-calibration-live-log.txt"

if [ "$CAL_OK" -ne "$FINAL_SIZE" ] || [ "$CAL_BAD" -ne 0 ]; then
  fail "${CAL_BAD} of ${FINAL_SIZE} genuine entries were REFUSED by the offline verifier"
fi

# CATCH 1 of 3. In the validated run this is a hard assertion. Under
# `self-check` the assertion is expected to fire, and the run counts it.
CAUGHT_STUB=0
if [ "$CAL_MUT_ACCEPTED" -ne 0 ]; then
  if [ "$CONTROL" = "self-check" ]; then
    CAUGHT_STUB=$((CAUGHT_STUB + 1))
    note ""
    note "CATCH 1 of 3 FIRED: the calibration accepted ${CAL_MUT_ACCEPTED} tampered entries,"
    note "which is the condition the validated run treats as fatal."
  else
    fail "the verifier ACCEPTED ${CAL_MUT_ACCEPTED} tampered entries -- every PASS in this run is decoration"
  fi
elif [ "$CONTROL" = "self-check" ]; then
  note ""
  note "CATCH 1 of 3 MISSED: the calibration refused every tampered entry even"
  note "though it was running the stub. That would mean this assertion is not"
  note "watching the verifier at all."
fi

# =============================================================================
say "10/12  The inclusion proof, verified OFFLINE"

if [ "$CONTROL" = "never-uploaded" ]; then
  note "First, what the signature alone establishes."
  VB_RC=0
  VB_OUT="$("$COSIGN" verify-blob --key "$SIGNER_PUB" --signature "${WORK}/artifact.sig" \
             --insecure-ignore-tlog=true "$ARTIFACT" 2>&1)" || VB_RC=$?
  echo "$VB_OUT" | sed 's/^/   /'
  note "cosign verify-blob exit : ${VB_RC}"
  [ "$VB_RC" -eq 0 ] || fail "the signature itself did not verify; that is not what this control is about"
  note ""
  note "The signature is VALID. It was made by the right key over exactly these"
  note "bytes. Now ask the log whether it has ever seen them."
  SEARCH="$(rget -X POST "${REKOR}/api/v1/index/retrieve" -H 'Content-Type: application/json' \
             -d "{\"hash\":\"sha256:${ART_SHA}\"}")"
  N_FOUND="$(echo "$SEARCH" | jq -r 'length')"
  note "index search for sha256:${ART_SHA:0:24}... -> ${N_FOUND} entries"
  printf '{}' > "${WORK}/no-entry.json"
  RC=0
  OUT="$("$VERIFY" inclusion --entry "${WORK}/no-entry.json" --artifact "$ARTIFACT" \
          --log-pubkey "${WORK}/rekor.pub" --signer-pubkey "$SIGNER_PUB" 2>&1)" || RC=$?
  echo "$OUT" | sed 's/^/   /'
  {
    echo "=== CONTROL never-uploaded"
    echo "artifact sha256      : ${ART_SHA}"
    echo
    echo "--- cosign verify-blob (signature only), exit ${VB_RC}:"
    echo "$VB_OUT"
    echo
    echo "--- the log's index search for that hash: ${N_FOUND} entries"
    echo
    echo "--- offline transparency-log verification, exit ${RC}:"
    echo "$OUT"
  } > "${HERE}/10-negative-never-uploaded.txt"
  [ "$N_FOUND" -eq 0 ] || fail "the log has an entry for an artifact this control never uploaded"
  [ "$RC" -ne 0 ] || fail "the offline verifier ACCEPTED an artifact with no log entry; it is not checking for one"
  notproven "when this artifact was signed, or that any third party can ever see that the signature exists." \
    "The signature is perfect. cosign verify-blob returned 0. It was made by the" \
    "expected key, over exactly these bytes, and nothing about it is wrong." \
    "" \
    "The log holds ${N_FOUND} entries for sha256:${ART_SHA:0:32}..." \
    "" \
    "So the signature establishes custody of a key, and nothing else. It cannot" \
    "distinguish a release signed today from one signed by a key stolen in March" \
    "and used quietly ever since: there is no time inside a signature, and no" \
    "record anywhere that a third party could examine. It also cannot be used to" \
    "NOTICE a signature the key's owner never made, because noticing requires" \
    "somewhere to look, and this signature exists only where its maker put it." \
    "" \
    "This is the case people assume is covered by 'we sign everything'. It is" \
    "the configuration of this repo's own sibling demo, image-signing-demo," \
    "which signs with --tlog-upload=false on purpose and is right to, for what" \
    "it proves. And it PASSES the artifact-provenance row that" \
    "verify-standard.sh ships today -- see 07-gate-artifact-provenance-row.txt" \
    "and 08-gate-non-vacuity.txt, first mutation."
fi

ENTRY="${WORK}/entry-${TARGET_INDEX}.json"
ENTRY_FOR_VERIFY="$ENTRY"
VERIFY_ARTIFACT="$ARTIFACT"
ANCHOR=signed-checkpoint
UNLOGGED=""

if [ "$CONTROL" = "tampered-entry" ]; then
  note "CONTROL tampered-entry: rewriting one bit of the logged record."
  python3 "${HERE}/scripts/tamper-entry.py" "$ENTRY" "${WORK}/entry-tampered.json" \
    || fail "the tamper script failed"
  ENTRY_FOR_VERIFY="${WORK}/entry-tampered.json"
  note ""
fi

if [ "$CONTROL" = "unanchored-root" ]; then
  note "CONTROL unanchored-root: a forged entry, verified by a verification that"
  note "does the Merkle arithmetic correctly and compares the answer against the"
  note "root that arrived in the same document."
  UNLOGGED="${WORK}/dist/txl-never-logged-9.9.9.tar.gz"
  printf 'txl-artifact-that-was-never-logged\n' > "$UNLOGGED"
  "$COSIGN" sign-blob --yes --key "$SIGNER_KEY" --tlog-upload=false \
    --output-signature "${WORK}/unlogged.sig" "$UNLOGGED" >/dev/null 2>&1 \
    || fail "could not sign the never-logged artifact"
  python3 "${HERE}/scripts/forge-unanchored-entry.py" \
    "$UNLOGGED" "${WORK}/unlogged.sig" "$SIGNER_PUB" "$ENTRY" "${WORK}/entry-forged.json" \
    || fail "the forge script failed"
  ENTRY_FOR_VERIFY="${WORK}/entry-forged.json"
  VERIFY_ARTIFACT="$UNLOGGED"
  ANCHOR=response-roothash
  note ""
fi

RC=0
OUT="$("$VERIFY" inclusion --entry "$ENTRY_FOR_VERIFY" --artifact "$VERIFY_ARTIFACT" \
        --log-pubkey "${WORK}/rekor.pub" --signer-pubkey "$SIGNER_PUB" \
        --anchor "$ANCHOR" 2>&1)" || RC=$?
echo "$OUT"
note "exit ${RC}"

if [ "$CONTROL" = "tampered-entry" ]; then
  SIGNED_ROOT="$(echo "$OUT" | sed -n 's/^ *root the log SIGNED: *//p')"
  RECOMPUTED="$(echo "$OUT" | sed -n 's/^ *recomputed root *: *//p')"
  {
    echo "=== CONTROL tampered-entry"
    python3 "${HERE}/scripts/tamper-entry.py" "$ENTRY" "${WORK}/entry-tampered.json"
    echo
    echo "$OUT"
    echo "exit ${RC}"
  } > "${HERE}/09-negative-tampered-entry.txt"
  [ "$RC" -ne 0 ] || fail "the verifier ACCEPTED a rewritten entry; it is decoration"
  notproven "that this artifact is in the log." \
    "One bit of the logged record was changed. Everything else in the document" \
    "-- the audit path, the signed checkpoint, the Signed Entry Timestamp -- is" \
    "byte-identical to what the log returned, and the record is still" \
    "well-formed JSON of the right kind." \
    "" \
    "  recomputed from the tampered record : ${RECOMPUTED}" \
    "  root the log SIGNED                 : ${SIGNED_ROOT}" \
    "" \
    "The two roots differ, and no further editing of the entry can make them" \
    "agree. Producing a checkpoint that commits to the rewritten tree needs the" \
    "log's signing key; producing one CONSISTENT with the checkpoints already" \
    "published needs that key to have been the only one, all along, and needs" \
    "nobody to have kept an older checkpoint. That is what append-only buys." \
    "" \
    "It is also the reason the recomputation has to happen on the relying" \
    "party's machine. A verifier that asked the log 'is this record correct?'" \
    "would be asking the only party with a reason to lie."
fi

if [ "$CONTROL" = "unanchored-root" ]; then
  {
    echo "=== CONTROL unanchored-root"
    python3 "${HERE}/scripts/forge-unanchored-entry.py" \
      "$UNLOGGED" "${WORK}/unlogged.sig" "$SIGNER_PUB" "$ENTRY" "${WORK}/entry-forged.json"
    echo
    echo "--- verification with --anchor=response-roothash (the control), exit ${RC}:"
    echo "$OUT"
  } > "${HERE}/11-negative-unanchored-root.txt"
  [ "$RC" -eq 0 ] \
    || fail "the control did not reproduce its own finding: a self-consistent forged proof was REFUSED by --anchor=response-roothash, so this control is measuring something other than the anchor"
  note ""
  note "Now the SAME document, with the anchor put back."
  RC2=0
  OUT2="$("${BIN}/txl-verify" inclusion --entry "$ENTRY_FOR_VERIFY" --artifact "$VERIFY_ARTIFACT" \
           --log-pubkey "${WORK}/rekor.pub" --signer-pubkey "$SIGNER_PUB" \
           --anchor signed-checkpoint 2>&1)" || RC2=$?
  echo "$OUT2"
  note "exit ${RC2}"
  {
    echo
    echo "--- the SAME document, with --anchor=signed-checkpoint, exit ${RC2}:"
    echo "$OUT2"
  } >> "${HERE}/11-negative-unanchored-root.txt"
  [ "$RC2" -ne 0 ] || fail "the real verifier ACCEPTED the forged entry; the anchor is not load-bearing"
  notproven "that the root this verification recomputed is a root any log ever committed to." \
    "Every step of the arithmetic above is correct. The leaf hash is right. The" \
    "RFC 6962 section 2.1.1 path walk is right. The recomputed root equals the" \
    "rootHash field of the response, exactly as it should." \
    "" \
    "The entry is a fiction. It was never uploaded to anything. The audit path is" \
    "three hashes this demo invented, and the rootHash field was computed" \
    "FORWARDS from that invented path so the comparison would succeed. Both" \
    "halves of the comparison had the same author." \
    "" \
    "Everything else in the document is genuine: the artifact hash is real, the" \
    "signature is real and verifies, the entry UUID is a real SHA-256(0x00||body)" \
    "of its own body, and the checkpoint is copied verbatim from the live log and" \
    "is genuinely signed by it. Only the path and the root are invented, and" \
    "nothing inside the document says so." \
    "" \
    "The same document with --anchor=signed-checkpoint exits ${RC2}. The whole" \
    "difference is one comparison: recomputed root against the root inside a note" \
    "the LOG SIGNED, rather than against a number that travelled in the same JSON" \
    "as the path it is supposed to check." \
    "" \
    "This is the class worth naming, because the code that has it is not sloppy" \
    "code. It reads RFC 6962, implements 2.1.1 correctly, tests it against the" \
    "spec's own vectors, and never asks where the root came from."
fi

if [ "$CONTROL" != "self-check" ]; then
  if [ "$RC" -ne 0 ]; then
    echo "$OUT" >&2
    fail "the offline verification of the artifact's inclusion proof FAILED"
  fi
fi
# Cross-check the two independent computations of the log's identity. Step 4
# derived SHA-256(DER public key) with `openssl pkey`; the verifier derived it
# again in Go, from the same PEM, and matched it against the checkpoint's key
# hint. Nothing compared the two, so a difference between the OpenSSL on this
# machine (LibreSSL on a stock macOS, OpenSSL 3.x under Homebrew and on Linux)
# would show up as a wrong hash printed confidently in 01-log-identity.txt while
# every assertion still passed. Two implementations that agree are worth more
# than either alone, and comparing them costs three lines.
if [ "$CONTROL" != "self-check" ]; then
  HINT_FROM_VERIFIER="$(echo "$OUT" | sed -n 's/^ *\[ *[0-9]*\] log-identity *PASS *key hint \([0-9a-f]*\) .*/\1/p')"
  [ -n "$HINT_FROM_VERIFIER" ] \
    || fail "could not read the log key hint out of the verifier's output; the cross-check below would have passed by having nothing to compare"
  [ "${LOG_KEY_SHA:0:8}" = "$HINT_FROM_VERIFIER" ] \
    || fail "the log key hash disagrees between implementations: openssl says ${LOG_KEY_SHA:0:8}..., the verifier says ${HINT_FROM_VERIFIER}"
  note ""
  note "log identity cross-check: openssl and the Go verifier independently derive"
  note "SHA-256(DER log public key) and agree on ${HINT_FROM_VERIFIER}"
fi

if [ -z "$CONTROL" ]; then
  cp "$ENTRY" "${HERE}/05-entry-and-inclusion-proof.json"
fi
{
  echo "=== the artifact's inclusion proof, verified OFFLINE"
  echo "artifact : work/dist/txl-payments-service-1.4.2.tar.gz"
  echo "sha256   : ${ART_SHA}"
  echo
  echo "$OUT"
  echo "exit ${RC}"
} | ev "04-inclusion-proof-verified.txt"

# CATCH 2 of 3. The forged, self-consistent entry is verified HERE TOO, inside
# the validated run, and must be REFUSED. Executing the negative inside the
# positive run is what keeps the validated run from being a happy path with a
# control bolted on beside it.
note ""
note "The same verifier, inside this run, against a self-consistent forgery"
note "(the unanchored-root control's document):"
UNLOGGED2="${WORK}/dist/txl-never-logged-check.tar.gz"
printf 'txl-artifact-that-was-never-logged-inline-check\n' > "$UNLOGGED2"
"$COSIGN" sign-blob --yes --key "$SIGNER_KEY" --tlog-upload=false \
  --output-signature "${WORK}/unlogged2.sig" "$UNLOGGED2" >/dev/null 2>&1 \
  || fail "could not sign the inline forgery's artifact"
python3 "${HERE}/scripts/forge-unanchored-entry.py" \
  "$UNLOGGED2" "${WORK}/unlogged2.sig" "$SIGNER_PUB" "$ENTRY" "${WORK}/entry-forged-inline.json" >/dev/null \
  || fail "the forge script failed"
FRC=0
FOUT="$("$VERIFY" inclusion --entry "${WORK}/entry-forged-inline.json" --artifact "$UNLOGGED2" \
         --log-pubkey "${WORK}/rekor.pub" --signer-pubkey "$SIGNER_PUB" 2>&1)" || FRC=$?
# Matched on the numbered check lines, not on the bare check NAMES: the VERDICT
# line lists the names of every failed check, so `sed -n '/root-anchor/p'`
# selects it too -- and with three such patterns the same VERDICT line was
# printed three times. Harmless here, and exactly the shape that makes a count
# of "how many checks failed" wrong somewhere it matters.
echo "$FOUT" | grep -E '^ +\[[0-9]+\] +(root-anchor|signed-entry-timestamp)|^ +VERDICT' | sed 's/^/  /' || true
note "exit ${FRC}  (must be non-zero)"
if [ "$FRC" -eq 0 ]; then
  if [ "$CONTROL" = "self-check" ]; then
    CAUGHT_STUB=$((CAUGHT_STUB + 1))
    note "CATCH 2 of 3 FIRED: a self-consistent forgery was accepted, which the"
    note "validated run treats as fatal."
  else
    fail "the verifier ACCEPTED a forged, self-consistent inclusion proof"
  fi
elif [ "$CONTROL" = "self-check" ]; then
  note "CATCH 2 of 3 MISSED."
fi

# =============================================================================
say "11/12  What the LOG adds: suppression, and a history that cannot be rewritten"

note "First: the entry is FINDABLE by anyone who knows the artifact's hash."
SEARCH="$(rget -X POST "${REKOR}/api/v1/index/retrieve" -H 'Content-Type: application/json' \
           -d "{\"hash\":\"sha256:${ART_SHA}\"}")"
N_FOUND="$(echo "$SEARCH" | jq -r 'length')"
note "index search sha256:${ART_SHA:0:24}... -> ${N_FOUND} entry/entries"
note "  $(echo "$SEARCH" | jq -r '.[0] // "<none>"')"
[ "$N_FOUND" -eq 1 ] || fail "expected exactly 1 entry for the artifact, found ${N_FOUND}"
NEVER_SHA="$(printf 'an artifact nobody ever signed\n' | shasum -a 256 | cut -d' ' -f1)"
SEARCH2="$(rget -X POST "${REKOR}/api/v1/index/retrieve" -H 'Content-Type: application/json' \
            -d "{\"hash\":\"sha256:${NEVER_SHA}\"}")"
N_NONE="$(echo "$SEARCH2" | jq -r 'length')"
note "index search for an artifact nobody signed -> ${N_NONE} entries"
[ "$N_NONE" -eq 0 ] || fail "the log returned entries for an artifact that was never signed"
note ""
note "That asymmetry is the suppression property. A signature can be made and"
note "kept private; an entry cannot be made and kept private, and its ABSENCE is"
note "as checkable as its presence. Anyone holding the key's public half can ask"
note "this question and get a countable answer -- which is how a signature the"
note "key's owner never made becomes something somebody could notice."

note ""
note "Second: the log's history, between two moments this run recorded."
PROOF="$(rget "${REKOR}/api/v1/log/proof?firstSize=${SIZE_AT_SIGNING}&lastSize=${FINAL_SIZE}")"
echo "$PROOF" > "${WORK}/consistency.json"
note "consistency proof ${SIZE_AT_SIGNING} -> ${FINAL_SIZE}: $(echo "$PROOF" | jq -r '.hashes | length') node(s)"
CRC=0
COUT="$("$VERIFY" consistency --proof "${WORK}/consistency.json" \
         --first "$SIZE_AT_SIGNING" --first-checkpoint "${WORK}/checkpoint-${SIZE_AT_SIGNING}.txt" \
         --second "$FINAL_SIZE" --second-checkpoint "${WORK}/checkpoint-${FINAL_SIZE}.txt" \
         --log-pubkey "${WORK}/rekor.pub" 2>&1)" || CRC=$?
echo "$COUT"
note "exit ${CRC}"
if [ "$CONTROL" != "self-check" ]; then
  [ "$CRC" -eq 0 ] || fail "the consistency proof did not verify offline"
fi

# CATCH 3 of 3.
python3 - "${WORK}/consistency.json" "${WORK}/consistency-bad.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
h = d["hashes"]
# One hex digit of one node. The proof stays well-formed; it stops being true.
h[0] = ("0" if h[0][0] != "0" else "1") + h[0][1:]
d["hashes"] = h
json.dump(d, open(sys.argv[2], "w"))
PY
CBRC=0
CBOUT="$("$VERIFY" consistency --proof "${WORK}/consistency-bad.json" \
          --first "$SIZE_AT_SIGNING" --first-checkpoint "${WORK}/checkpoint-${SIZE_AT_SIGNING}.txt" \
          --second "$FINAL_SIZE" --second-checkpoint "${WORK}/checkpoint-${FINAL_SIZE}.txt" \
          --log-pubkey "${WORK}/rekor.pub" 2>&1)" || CBRC=$?
note ""
note "the same check against a proof with one hex digit changed: exit ${CBRC} (must be non-zero)"
echo "$CBOUT" | grep -E '^ +\[[0-9]+\] +append-only|^ +VERDICT' | sed 's/^/  /' || true
if [ "$CBRC" -eq 0 ]; then
  if [ "$CONTROL" = "self-check" ]; then
    CAUGHT_STUB=$((CAUGHT_STUB + 1))
    note "CATCH 3 of 3 FIRED: a corrupted consistency proof was accepted."
  else
    fail "the verifier ACCEPTED a corrupted consistency proof"
  fi
elif [ "$CONTROL" = "self-check" ]; then
  note "CATCH 3 of 3 MISSED."
fi
{
  echo "=== consistency: the log's history between two moments in this run"
  echo
  echo "checkpoint at size ${SIZE_AT_SIGNING}, captured when the artifact was integrated:"
  cat "${WORK}/checkpoint-${SIZE_AT_SIGNING}.txt"
  echo "checkpoint at size ${FINAL_SIZE}, captured after ${DECOYS_AFTER} more releases:"
  cat "${WORK}/checkpoint-${FINAL_SIZE}.txt"
  echo "proof nodes: $(echo "$PROOF" | jq -c '.hashes')"
  echo
  echo "$COUT"
  echo "exit ${CRC}"
  echo
  echo "--- the same check, one hex digit of one proof node changed:"
  echo "$CBOUT"
  echo "exit ${CBRC}"
  echo
  echo "--- suppression:"
  echo "index search for the artifact's hash            : ${N_FOUND} entry/entries"
  echo "index search for an artifact nobody ever signed : ${N_NONE} entries"
} | ev "06-consistency-and-suppression.txt"

if [ "$CONTROL" = "self-check" ]; then
  {
    echo "=== CONTROL self-check"
    echo "every verification in this run ran bin/txl-verify-stub, which prints a"
    echo "successful verification and exits 0 without opening a file."
    echo
    echo "catches that FIRED: ${CAUGHT_STUB} of 3"
    echo "  1. step  9  live-log calibration, tampered mutants accepted : ${CAL_MUT_ACCEPTED}"
    echo "  2. step 10  forged self-consistent proof, exit              : ${FRC}"
    echo "  3. step 11  corrupted consistency proof, exit               : ${CBRC}"
  } > "${HERE}/12-negative-self-check.txt"
  [ "$CAUGHT_STUB" -eq 3 ] \
    || fail "only ${CAUGHT_STUB} of 3 assertions noticed a verifier that exits 0 unconditionally; the other $((3 - CAUGHT_STUB)) are decoration and the validated run's green is worth less than it looks"
  notproven "that this artifact is in the log." \
    "That was never this run's job. Every verification above ran" \
    "bin/txl-verify-stub, which prints a successful verification and exits 0" \
    "without opening a single file." \
    "" \
    "What this run DID prove is that the validated run's success assertions are" \
    "load-bearing. A verifier substituted with \`return 0\` was caught in" \
    "${CAUGHT_STUB} of 3 places:" \
    "" \
    "  1. step  9  the live-log calibration: 8 tampered entries must be REFUSED" \
    "  2. step 10  a forged, self-consistent inclusion proof must be REFUSED" \
    "  3. step 11  a corrupted consistency proof must be REFUSED" \
    "" \
    "This run exits 1 because a demo whose green depends only on a program" \
    "having been INVOKED is a demo that proves a program exists. Asserting that" \
    "a check is load-bearing is not the same as substituting \`return 0\` and" \
    "watching the gate notice. This is the second one."
fi

# =============================================================================
say "12/12  The gate: a reference artifact-provenance row, and its non-vacuity"

# The row AS SHIPPED, executed. The claim "the upstream row would pass this" is
# a claim about a gate, and this collection does not accept those from itself.
# The two load-bearing lines of scripts/upstream-row-as-shipped.sh are copied
# character for character out of _shared/probes/verify-standard.sh.
UP_RC=0
UP_OUT="$(bash "${HERE}/scripts/upstream-row-as-shipped.sh" 2>&1)" || UP_RC=$?
echo "$UP_OUT" | sed -n '/^fixtures:/p'
[ "$UP_RC" -eq 0 ] || { echo "$UP_OUT" >&2; fail "could not run the upstream row as shipped"; }

ROW_RC=0
ROW_OUT="$(bash "${HERE}/scripts/gate.sh" 2>&1)" || ROW_RC=$?
echo "$ROW_OUT" | tail -3
{
  echo "=== PART 1: the artifact-provenance row as verify-standard.sh SHIPS it,"
  echo "===         reproduced verbatim and executed against this repo's fixtures"
  echo
  echo "$UP_OUT"
  echo
  echo "=== PART 2: the reference row proposed by this demo, over the same fixtures"
  echo
  echo "$ROW_OUT"
} | ev "07-gate-artifact-provenance-row.txt"
if [ "$ROW_RC" -ne 0 ]; then
  echo "$ROW_OUT" >&2
  fail "the row self-check failed"
fi

NV_RC=0
NV_OUT="$(bash "${HERE}/scripts/gate-non-vacuity.sh" 2>&1)" || NV_RC=$?
echo "$NV_OUT" | tail -2
echo "$NV_OUT" | ev "08-gate-non-vacuity.txt"
if [ "$NV_RC" -ne 0 ]; then
  echo "$NV_OUT" >&2
  fail "the row's predicates are not load-bearing"
fi

note ""
note "$(echo "$UP_OUT" | sed -n '/^fixtures:/p')  -- and exactly ONE of the eight"
note "actually signs, logs, and verifies the inclusion proof offline."
note ""
note "The sharpest of the seven is release-permissions-only.yml, which contains no"
note "signing step of any kind. The row as shipped matches its pattern's"
note "'attestations:' alternative against the 'attestations: write' entry of a"
note "GitHub permissions block -- a declaration of intent, not a step. That was"
note "found by mutation-testing this demo's own row, not by reading the probe, and"
note "07-gate-artifact-provenance-row.txt shows the shipped code producing it."

# =============================================================================
say "What this run proved"
INTEG="$(jq -r '.[].integratedTime' "$ENTRY")"
cat <<EOF
   artifact              work/dist/txl-payments-service-1.4.2.tar.gz
   sha256                ${ART_SHA}
   log index             $(jq -r '.[].logIndex' "$ENTRY")
   integrated time       ${INTEG}  ($(python3 -c "import datetime,sys;print(datetime.datetime.fromtimestamp(int(sys.argv[1]),datetime.timezone.utc).isoformat())" "$INTEG"))
   audit path length     $(jq -r '.[].verification.inclusionProof.hashes | length' "$ENTRY") sibling hashes
   tree size at proof    $(jq -r '.[].verification.inclusionProof.treeSize' "$ENTRY")
   recomputed root       $(echo "$OUT" | sed -n 's/^ *recomputed root *: *//p')
   root the log SIGNED   $(echo "$OUT" | sed -n 's/^ *root the log SIGNED: *//p')

   RFC 6962 calibration  ${CAL_VERIFIED} valid proofs accepted, ${CAL_REJECTED} mutants rejected, ${CAL_ACCEPTED} accepted
   live-log calibration  ${CAL_OK}/${FINAL_SIZE} entries verified, ${CAL_MUT_REFUSED} tampered mutants refused
   forged self-consistent proof   refused (exit ${FRC})
   corrupted consistency proof    refused (exit ${CBRC})
   reference row         $(echo "$ROW_OUT" | sed -n 's/^cases: /cases /p')
   row non-vacuity       $(echo "$NV_OUT" | sed -n 's/^mutations: /mutations /p')

   Evidence: 01..12 in this directory.
   Controls, each a full run, each exiting non-zero:
     TXL_CONTROL=tampered-entry    ./run-demo.sh
     TXL_CONTROL=never-uploaded    ./run-demo.sh
     TXL_CONTROL=unanchored-root   ./run-demo.sh
     TXL_CONTROL=self-check        ./run-demo.sh

   Tear down with: ./teardown.sh
EOF
