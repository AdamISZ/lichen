#!/usr/bin/env bash
# Build the deployment's two images from committed sources:
#   deploy/build.sh            (in a lichen checkout, ln-gap beside it)
# - lichen: the hub's and the sequencer's binaries, BitVMX's verifier
#   ELF, from lichen's HEAD and ln-gap at the commit in LNGAP_REV (both
#   exported with `git archive`: no working-tree changes, no target/);
# - lichen-bitcoind: the node for NETWORK (deploy/.env), from a release
#   tarball checked by SHA-256.
# LNGAP_DIR overrides where ln-gap is (default: ../ln-gap).
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
lichen="$(cd "$here/.." && pwd)"
lngap="${LNGAP_DIR:-$lichen/../ln-gap}"
rev="$(cat "$lichen/LNGAP_REV")"

die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
[ -d "$lngap/.git" ] || die "no ln-gap checkout at $lngap (set LNGAP_DIR, or clone it beside lichen)"
git -C "$lngap" cat-file -e "$rev^{commit}" 2>/dev/null || die "ln-gap has no commit $rev (git -C $lngap fetch)"
if [ -n "$(git -C "$lichen" status --porcelain -- crates Cargo.toml Cargo.lock deploy LNGAP_REV)" ]; then
    echo "note: uncommitted changes in lichen are not in the image (it builds HEAD)" >&2
fi

[ -f "$here/.env" ] || die "no deploy/.env (copy .env.example and set NETWORK)"
# shellcheck disable=SC1091
. "$here/.env"

ctx="$(mktemp -d)"
trap 'rm -rf "$ctx"' EXIT
mkdir -p "$ctx/lichen" "$ctx/ln-gap"
git -C "$lichen" archive HEAD | tar -x -C "$ctx/lichen"
git -C "$lngap" archive "$rev" | tar -x -C "$ctx/ln-gap"
echo "== lichen $(git -C "$lichen" rev-parse --short HEAD), ln-gap ${rev:0:7}"

docker build -t lichen:latest -f "$here/Dockerfile" "$ctx"
docker build -t "lichen-bitcoind:$NETWORK" --build-arg "NETWORK=$NETWORK" "$here/bitcoind"
echo "== built lichen:latest and lichen-bitcoind:$NETWORK"
