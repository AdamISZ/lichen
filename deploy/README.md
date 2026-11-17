# Deploying lichen

One deployment per network, run by the hub's operator: the node and
the hub, in one Docker Compose project
([docs/RUN_A_HUB.md](../docs/RUN_A_HUB.md)). Users run only the
`lichen` wallet, with no node ([docs/USE_A_WALLET.md](../docs/USE_A_WALLET.md)).

## Layout

| path | what |
|---|---|
| `.env.example` | the settings; copy to `.env` |
| `docker-compose.yml` | the deployment: `bitcoind`, `hub`, and on regtest `miner` |
| `Dockerfile`, `entry.sh` | the `lichen` image (the hub, `lichen-r0`, the wallet) and its roles: `key`, `hub` |
| `bitcoind/` | the node's image (`lichen-bitcoind:<network>`), whose entry writes `bitcoin.conf` for the network |
| `build.sh` | builds both images |
| `context.sh` | a build context of committed sources (lichen's HEAD), for `build.sh` |
| `lichen.sh` | the operator's commands: `up`, `down`, `info`, `address`, `balance`, `coins`, `fund`, `logs`, `cli` |
| `smoke.sh` | a regtest smoke test: a deposit and a cooperative withdrawal |
| `state/<network>/` | everything kept: `bitcoind/`, `hub/` (not in git) |
