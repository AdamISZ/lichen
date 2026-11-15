#!/bin/sh
# The hub API's reference page: docs/hub-api.yaml rendered by Redoc into
# one self-contained page (Redoc's script and the spec inline; nothing
# fetched when it's viewed). Writes docs/api/out/{index.html,hub-api.yaml},
# which deploy as they are (static files).
#
#   docs/api/build.sh            # then open docs/api/out/index.html
#
# Needs curl, tar, openssl, and ruby or Python's PyYAML (the spec to
# JSON: Redoc 2 can't take YAML from a local URL). Redoc is pinned by version and checked against
# npm's integrity hash.
set -eu
REDOC_VERSION=2.5.4
REDOC_SHA512=sha512-M6jWhG1qoBnH6TFmzJnstyCZ87HmOY/UzDm78mHiYihEdlV/YcS9ogOo1NlElnJMeLsyxHFe2yFc4sNjHTrABQ==
here=$(cd "$(dirname "$0")" && pwd)
spec="$here/../hub-api.yaml"
out="$here/out"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

curl -fsSL -o "$tmp/redoc.tgz" "https://registry.npmjs.org/redoc/-/redoc-$REDOC_VERSION.tgz"
got=$(openssl dgst -sha512 -binary "$tmp/redoc.tgz" | openssl base64 -A)
[ "sha512-$got" = "$REDOC_SHA512" ] || { echo "redoc $REDOC_VERSION: integrity mismatch" >&2; exit 1; }
mkdir "$tmp/x" && tar -xzf "$tmp/redoc.tgz" -C "$tmp/x" package/bundles/redoc.standalone.js

version=$(sed -n 's/^  version: //p' "$spec" | head -1)
# inline, nothing may close a <script> early
! grep -qi '</script' "$spec" || { echo "the spec holds '</script'" >&2; exit 1; }
mkdir -p "$out"
cp "$spec" "$out/hub-api.yaml"
{
  sed -e "s/@VERSION@/$version/g" -e "s/@REDOC@/$REDOC_VERSION/g" "$here/head.html"
  printf '<script id="spec" type="application/json">\n'
  if command -v ruby >/dev/null; then
    ruby -ryaml -rjson -e 'puts JSON.generate(YAML.safe_load(File.read(ARGV[0])))' "$spec"
  else
    python3 -c 'import json, sys, yaml; print(json.dumps(yaml.safe_load(open(sys.argv[1]))))' "$spec"
  fi
  printf '</script>\n<script>\n'
  # '</script' in Redoc's strings, escaped ('<\/' is '</' to JavaScript)
  sed 's#</script#<\\/script#g' "$tmp/x/package/bundles/redoc.standalone.js"
  printf '\n</script>\n'
  cat "$here/tail.html"
} > "$out/index.html"
echo "built $out/index.html (spec $version, Redoc $REDOC_VERSION)"
