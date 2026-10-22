#!/bin/bash
# Build the whole linux/amd64 depot input directory.  NOT run in CI.
#   depot/recipes/build.sh [outdir]      (needs docker and internet, once, in the lab)
# Then pack and sign (offline, on the release machine):
#   phylax depot pack --spec depot/tools.json --src outdir --store dist/depot --key release.key
# Verify reproducibility by running twice on two machines and comparing `sha256sum outdir/*`.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
out=$(realpath -m "${1:-$here/../../build/depot-src}")
mkdir -p "$out"
docker build -t phylax-depot-build "$here"
for t in ${TOOLS:-busybox coreutils procps iproute2 lsof net-tools tcpdump strace curl socat openssh file findutils grep tar gzip xz toybox nmap}; do
  docker run --rm -v "$out:/out" ${SRC_CACHE:+-v "$SRC_CACHE:/srccache:ro"} phylax-depot-build "$t"
done

echo "built into $out"
