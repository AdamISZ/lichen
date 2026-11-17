# Sourced by deploy/build.sh: a Docker build context of committed sources
# only, lichen's HEAD exported with `git archive` (no working-tree
# changes, no target/). lichen-btc comes by git, at the commit
# Cargo.lock pins.
#   make_context      sets $ctx: a directory holding lichen/ (removed on
#                     exit), and $lichen_commit: lichen's HEAD as `git
#                     describe` names it (its tag, if any)

die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

make_context() {
    local deploy lichen
    deploy="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    lichen="$(cd "$deploy/.." && pwd)"
    if [ -n "$(git -C "$lichen" status --porcelain -- crates Cargo.toml Cargo.lock deploy)" ]; then
        echo "note: uncommitted changes in lichen are not in the image (it builds HEAD)" >&2
    fi
    ctx="$(mktemp -d)"
    trap 'rm -rf "$ctx"' EXIT
    mkdir -p "$ctx/lichen"
    git -C "$lichen" archive HEAD | tar -x -C "$ctx/lichen"
    lichen_commit="$(git -C "$lichen" describe --tags --always)"
    echo "== lichen $lichen_commit"
}
