# Deploying lichen

One deployment per network, run by the hub's operator: the node, the
L2's sequencer, its chain prover and the hub, in one Docker Compose
project ([docs/RUN_A_HUB.md](../docs/RUN_A_HUB.md)). Users run only the
`lichen` wallet, with no node ([docs/USE_A_WALLET.md](../docs/USE_A_WALLET.md)).
A user's tower, for one dispute, is separate
([docs/RUN_A_TOWER.md](../docs/RUN_A_TOWER.md), `tower/`).

## Layout

| path | what |
|---|---|
| `.env.example` | the settings; copy to `.env` |
| `docker-compose.yml` | the deployment: `bitcoind`, `sequencer`, `chain-prover`, `hub`, and on regtest `miner` |
| `Dockerfile`, `entry.sh` | the `lichen` image (the hub, the sequencer, `lichen-r0`, BitVMX's verifier ELF, the wallet) and its roles: `key`, `sequencer`, `chain-prover`, `hub` |
| `bitcoind/` | the node's image (`lichen-bitcoind:<network>`) and its `bitcoin.conf` per network |
| `build.sh` | builds both images |
| `context.sh` | a build context of committed sources (lichen's HEAD, ln-gap at `LNGAP_REV`), for `build.sh` and `tower/build.sh` |
| `lichen.sh` | the operator's commands: `up`, `down`, `info`, `address`, `balance`, `coins`, `fund`, `logs`, `cli` |
| `smoke.sh` | a regtest smoke test: a deposit and a cooperative withdrawal |
| `tower/` | a user's tower |
| `state/<network>/` | everything kept: `bitcoind/`, `hub/`, `sequencer/` (not in git) |

Moving a deployment from the earlier layout, two compose projects in
`hub/` and `sequencer/`: [docs/RUN_A_HUB.md](../docs/RUN_A_HUB.md),
"Moving from the two-project layout".
