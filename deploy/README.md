# Deploying lichen

Two components, set up separately, normally on different machines, each
with its own image, compose project, settings and data:

| component | guide | here |
|---|---|---|
| the sequencer | [docs/RUN_A_SEQUENCER.md](../docs/RUN_A_SEQUENCER.md) | `sequencer/` |
| the hub, with its node | [docs/RUN_A_HUB.md](../docs/RUN_A_HUB.md) | `hub/` |
| a user's tower, for one dispute | [docs/RUN_A_TOWER.md](../docs/RUN_A_TOWER.md) | `tower/` |

Testers run only the `lichen` wallet, with no node (RUN_A_HUB.md,
"Testers").

## Layout

| path | what |
|---|---|
| `context.sh` | shared by both `build.sh`: a build context of committed sources (lichen's HEAD, ln-gap at `LNGAP_REV`) |
| `sequencer/Dockerfile` | the `lichen-sequencer` image: the sequencer alone |
| `sequencer/docker-compose.yml`, `.env.example` | the sequencer's deployment |
| `sequencer/build.sh`, `sequencer.sh` | its build, its operator's commands |
| `hub/Dockerfile`, `entry.sh` | the `lichen-hub` image (`lichen-hub`, BitVMX's verifier ELF, the `lichen` wallet) and its roles, `key` and `hub` |
| `hub/bitcoind/` | the node image (`lichen-bitcoind:<network>`) and its `bitcoin.conf` per network |
| `hub/docker-compose.yml`, `.env.example` | the hub's deployment: node, hub, and on regtest a miner |
| `hub/build.sh`, `hub.sh`, `smoke.sh` | its build, its operator's commands, a regtest smoke test |
| `*/data/<network>/` | everything kept (not in git) |

## Moving from the single deployment

Until 2026-10-14 one compose project (`lichen-<network>`) ran the node, the
sequencer and the hub, from `deploy/docker-compose.yml`, with data in
`deploy/data/<network>/`. Each data directory moves unchanged, so a
deployment keeps its keys, its ledger and its contracts. For
`NETWORK=mutinynet`, on the same machine:

```sh
docker compose -p lichen-mutinynet down       # the old project (its compose file is gone)
mkdir -p deploy/hub/data/mutinynet deploy/sequencer/data
mv deploy/data/mutinynet/bitcoind deploy/data/mutinynet/hub deploy/hub/data/mutinynet/
mv deploy/data/mutinynet/sequencer deploy/sequencer/data/mutinynet
cp deploy/hub/.env.example deploy/hub/.env
cp deploy/sequencer/.env.example deploy/sequencer/.env
```

Then the settings, from the old `deploy/.env`:

- **`deploy/sequencer/.env`:** `NETWORK`, `SEAL_EVERY`, `SEQUENCER_PORT`,
  and `ISSUER=$(cat deploy/data/mutinynet/shared/hub.pub)`.
- **`deploy/hub/.env`:** `NETWORK`, `STATEMENT`, `RESERVE_PPM`, `MAX_BITS`,
  `DURATION`, `HUB_PORT`, `MINE_EVERY`, and
  `SEQUENCER_URL=http://host.docker.internal:18300`, with the sequencer's
  port.

Then build and start both, as in the guides. The ports stay as they were,
so wallets need no change. The old `deploy/.env` and
`deploy/data/<network>/shared/` are no longer used.
