# Sourced by deploy/hub/build.sh and deploy/sequencer/build.sh: a Docker
# build context of committed sources only, lichen's HEAD and ln-gap at the
# commit in LNGAP_REV, both exported with `git archive` (no working-tree
# changes, no target/). lichen depends on ln-gap by path, and cargo reads
# the whole workspace, so both images need both trees to build.
#   make_context      sets $ctx: a directory holding lichen/ and ln-gap/
#                     (removed on exit)
# LNGAP_DIR overrides where ln-gap is (default: ../ln-gap).

die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

make_context() {
    local deploy lichen lngap rev
    deploy="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    lichen="$(cd "$deploy/.." && pwd)"
    lngap="${LNGAP_DIR:-$lichen/../ln-gap}"
    rev="$(cat "$lichen/LNGAP_REV")"
    [ -d "$lngap/.git" ] || die "no ln-gap checkout at $lngap (set LNGAP_DIR, or clone it beside lichen)"
    git -C "$lngap" cat-file -e "$rev^{commit}" 2>/dev/null || die "ln-gap has no commit $rev (git -C $lngap fetch)"
    if [ -n "$(git -C "$lichen" status --porcelain -- crates Cargo.toml Cargo.lock deploy LNGAP_REV)" ]; then
        echo "note: uncommitted changes in lichen are not in the image (it builds HEAD)" >&2
    fi
    ctx="$(mktemp -d)"
    trap 'rm -rf "$ctx"' EXIT
    mkdir -p "$ctx/lichen" "$ctx/ln-gap"
    git -C "$lichen" archive HEAD | tar -x -C "$ctx/lichen"
    git -C "$lngap" archive "$rev" | tar -x -C "$ctx/ln-gap"
    echo "== lichen $(git -C "$lichen" rev-parse --short HEAD), ln-gap ${rev:0:7}"
}
