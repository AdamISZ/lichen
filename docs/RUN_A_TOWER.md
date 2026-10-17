# Running a tower

A tower plays one contract's dispute for you on a machine you rent, so
that your laptop or phone can be away (the plan: [TOWER_PLAN.md](TOWER_PLAN.md)).
It proves your withdrawal, wraps the proof, runs your side of the search,
escalates and answers each of the hub's moves, to the payout. It holds
this contract's one-time secrets and its fee budget's key, never your
wallet's key: at worst it can lose this one dispute (which is the hub's
gain), not take your money.

You need an x86_64 Linux machine with Docker, 16 GB of memory and about
20 GB of disk (the Groth16 wrap runs RISC Zero's prover image, x86 only).

## 1. Your wallet: refused, then export

On your own device, once the hub has refused a cooperative withdrawal
(`lichen withdraw <contract> <amount>` returned the amount on the L2 and
then failed):

```sh
lichen --network mutinynet --wallet alice.json --statement groth16 \
  export-dispute <contract> --out package.json
```

`package.json` holds the contract and its one-time secrets. Treat it as a
secret for this contract: whoever has it can play (or throw) this one
dispute.

## 2. The machine

By hand, on a fresh x86 Linux box with Docker:

```sh
git clone https://github.com/AdamISZ/lichen && git clone https://github.com/AdamISZ/ln-gap
git -C ln-gap checkout "$(cat lichen/LNGAP_REV)"
cd lichen
deploy/tower/build.sh                      # 20 minutes or more the first time
cp deploy/tower/.env.example deploy/tower/.env   # NETWORK, ESPLORA, R0WORK
sudo mkdir -p /srv/lichen-tower/r0work && sudo chown "$USER" /srv/lichen-tower/r0work
mkdir -p deploy/tower/data && cp ~/package.json deploy/tower/data/package.json
docker compose -f deploy/tower/docker-compose.yml up -d
docker compose -f deploy/tower/docker-compose.yml logs -f tower
```

Or in one go at the VPS provider: paste `deploy/tower/cloud-init.yaml`
as the machine's user data. It installs Docker, builds the image and
waits for `/srv/lichen-tower/package.json`; copy the package there
(`scp package.json root@<host>:/srv/lichen-tower/`) and it starts.

The settings (`deploy/tower/.env`):

| setting | what |
|---|---|
| `NETWORK` | the contract's network |
| `ESPLORA` | two Esplora servers, comma-separated. A move is answered only once both report it confirmed, in the same block, with the same witness; a disagreement is logged as `chain: ALARM`. On Mutinynet, `https://mutinynet.com/api` twice will do for a trial |
| `STATEMENT` | `groth16` (the tower proves) or `mock` |
| `R0WORK` | an absolute path on the machine for the wrap's working files, mounted at the same path in the container |

The tower logs each step: the proof, the escalation, each move. It
survives a restart (`restart: on-failure`; its state is
`deploy/tower/data/package.state.json`). It posts each of your links at
its floor of 1 sat/vB (fee bumps need a separate anchor key: not yet).

## 3. After: sweep on your own device

The tower stops at the payout: your bit outputs and the reserves wait
for your own key. Copy its state back and sweep:

```sh
scp root@<host>:/srv/lichen-tower/lichen/deploy/tower/data/package.state.json .
lichen --network mutinynet --wallet alice.json --statement groth16 \
  sweep-dispute <contract> --tower-state package.state.json
```

Then delete the machine.
