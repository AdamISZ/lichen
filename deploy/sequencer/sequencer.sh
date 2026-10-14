#!/usr/bin/env bash
# The sequencer operator's commands for a running sequencer
# (deploy/sequencer/.env, or ENV_FILE):
#   deploy/sequencer/sequencer.sh info     the deployment: its key, the hub's, the deployment id
#   deploy/sequencer/sequencer.sh heights  the sealed heights so far, and the notes
#   deploy/sequencer/sequencer.sh logs     follow its log
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
env_file="${ENV_FILE:-$here/.env}"
# shellcheck disable=SC1090
. "$env_file"
dc() { docker compose --env-file "$env_file" -f "$here/docker-compose.yml" "$@"; }
url="http://127.0.0.1:${SEQUENCER_PORT:-18300}"

case "${1:-}" in
    info)
        curl -fsS "$url/info" | tr -d '{}"' | tr ',' '\n' | sed 's/:/ key:  /'; echo
        dc logs sequencer 2>/dev/null | grep -o 'deployment [0-9a-f]*' | tail -1
        ;;
    heights)
        curl -fsS "$url/state" | python3 -c 'import json,sys; s=json.load(sys.stdin); h=s["sealed"]; print(f"{len(h)} heights sealed, the last {h[-1]["height"] if h else "-"}; {len(s["notes"])} notes, {len(s["nullifiers"])} spent")'
        ;;
    logs) dc logs -f sequencer ;;
    *) sed -n '2,7p' "$0"; exit 1 ;;
esac
