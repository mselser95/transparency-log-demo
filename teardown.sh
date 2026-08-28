#!/usr/bin/env bash
# Removes everything run-demo.sh creates. Safe to run more than once, and safe
# on a machine that never ran the demo.
#
# It removes containers BY NAME and one docker network BY NAME. It never runs
# `docker rm -f $(docker ps -aq)`, never `docker system prune`, and never
# touches anything it did not create: other demos are running on this machine
# right now, and several of them are mid-run.
#
# It reports what it ACTUALLY removed, by checking first rather than trusting an
# exit code. `docker rm -f` exits 0 when there was nothing there, so a teardown
# built on exit codes prints a confident list of removals having removed
# nothing. The last lines are a COUNT of survivors, and that count is the
# evidence.
#
#   ./teardown.sh                     removes containers, network, images, scratch
#   TXL_KEEP_IMAGES=1 ./teardown.sh   keeps the five pinned images (used by
#                                     run-demo.sh's own idempotent pre-clean, so
#                                     a re-run does not re-pull ~500MB)
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"

CONTAINERS=(txl-rekor txl-trillian-log-signer txl-trillian-log-server txl-redis txl-mysql)
NET=txl-net
# Pinned by digest in run-demo.sh; listed here by digest too, so teardown can
# only ever remove the exact images this demo pulled and never a same-named tag
# somebody else is using.
IMAGES=(
  'ghcr.io/sigstore/rekor/rekor-server@sha256:a8052cbed56cdfc6e134c5d405bce83458005cf9f8a9f627bc50b183785f1cbd'
  'gcr.io/trillian-opensource-ci/log_server@sha256:d12a110a578d3ee71f5d9bc5e16b21348b7d57b89fc32b01f367099a5e0016cc'
  'gcr.io/trillian-opensource-ci/log_signer@sha256:195bd72513721db9a4b7e2360834c82d1979005d95e430b5a4a309d0e458369c'
  'gcr.io/trillian-opensource-ci/db_server@sha256:c3d5e243a2995e6bd83479c59cf5f586244f0988f97429f44e3334da0a95a5d0'
)
KEEP_IMAGES="${TXL_KEEP_IMAGES:-0}"

for c in "${CONTAINERS[@]}"; do
  # `docker ps -aq --filter name=^c$` rather than a bare name filter: the bare
  # filter is a SUBSTRING match, so `txl-redis` would also select a container
  # called `other-txl-redis-2` belonging to somebody else.
  if [ -n "$(docker ps -aq --filter "name=^${c}\$" 2>/dev/null)" ]; then
    docker rm -f "$c" >/dev/null 2>&1
    echo "container ${c}: removed"
  else
    echo "container ${c}: not present"
  fi
done

# The network is removed only when nothing is attached. It is txl-owned, but a
# half-finished run can leave a container on it and `docker network rm` would
# fail; saying which is more useful than a silent `|| true`.
if [ -n "$(docker network ls -q --filter "name=^${NET}\$" 2>/dev/null)" ]; then
  if docker network rm "$NET" >/dev/null 2>&1; then
    echo "network ${NET}: removed"
  else
    echo "network ${NET}: still in use, NOT removed" >&2
  fi
else
  echo "network ${NET}: not present"
fi

if [ "$KEEP_IMAGES" = "1" ]; then
  echo "images: kept (TXL_KEEP_IMAGES=1)"
else
  for i in "${IMAGES[@]}"; do
    # `docker images -q <repo>@sha256:...` returns EMPTY for an image that is
    # present -- it matches on repository:TAG, and a digest reference has no
    # tag. The first version of this loop used it, reported "not present" for
    # all four images, exited 0 on that branch, and left every one of them on
    # the disk. Nothing about the output said so.
    #
    # The survivor count at the bottom of this file is what caught it, which is
    # the whole reason the count is not a summary of the lines above but an
    # independent measurement. `docker image inspect` resolves a digest
    # reference; `docker rmi` on the resolved image ID removes it.
    id="$(docker image inspect "$i" --format '{{.Id}}' 2>/dev/null || true)"
    if [ -n "$id" ]; then
      docker rmi -f "$id" >/dev/null 2>&1
      echo "image ${i##*/}: removed"
    else
      echo "image ${i##*/}: not present"
    fi
  done
  # redis is deliberately NOT removed. It is a stock image other things on this
  # machine plausibly share, and removing a shared base image to tidy up after a
  # demo is a way to break somebody else's run. Counted below instead.
  echo "image redis:7.4.1-alpine: deliberately kept (shared stock image)"
fi

for d in "${HERE}/work" "${HERE}/bin"; do
  if [ -d "$d" ]; then
    /bin/rm -r "$d"
    echo "${d##*/}/: removed"
  else
    echo "${d##*/}/: not present"
  fi
done

# COUNT the survivors instead of trusting the exit codes above. The `|| true` is
# required and not cosmetic: `grep -c` exits 1 when it selects no lines, which
# here is the SUCCESS case, and under a stricter shell that would abort the
# teardown at exactly the moment it had worked perfectly.
#
# Counting with `grep -c` and not `grep -q`: -q exits at the first match and the
# producer takes SIGPIPE, which under pipefail turns a match into a failure.
# -c consumes all of its input, so nothing is ever signalled.
LEFT_C="$(docker ps -a --format '{{.Names}}' 2>/dev/null | grep -c '^txl-' || true)"
LEFT_N="$(docker network ls --format '{{.Name}}' 2>/dev/null | grep -c '^txl-' || true)"
LEFT_V="$(docker volume ls --format '{{.Name}}' 2>/dev/null | grep -c '^txl-' || true)"
LEFT_I="$(docker images --format '{{.Repository}}' 2>/dev/null | grep -cE '^(ghcr\.io/sigstore/rekor/rekor-server|gcr\.io/trillian-opensource-ci/)' || true)"
LEFT_F="$( { [ -d "${HERE}/work" ] && echo work; [ -d "${HERE}/bin" ] && echo bin; } | grep -c . || true)"
echo "remaining txl-* containers: ${LEFT_C}   networks: ${LEFT_N}   volumes: ${LEFT_V}   scratch dirs: ${LEFT_F}   rekor/trillian images: ${LEFT_I}"

BAD=0
[ "${LEFT_C}" -ne 0 ] && BAD=1
[ "${LEFT_N}" -ne 0 ] && BAD=1
[ "${LEFT_V}" -ne 0 ] && BAD=1
[ "${LEFT_F}" -ne 0 ] && BAD=1
if [ "$KEEP_IMAGES" != "1" ] && [ "${LEFT_I}" -ne 0 ]; then BAD=1; fi
if [ "$BAD" -ne 0 ]; then
  echo "teardown INCOMPLETE" >&2
  exit 1
fi
echo "done"
