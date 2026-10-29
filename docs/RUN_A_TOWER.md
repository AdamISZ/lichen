# Running a tower

A tower plays one contract's dispute for you on a machine you rent, so
that your laptop or phone can be away. What it holds depends on the
contract's verification gadget:

- **BABE** (`--statement babe`): your signatures (on the amount, on
  your proof, and, made when the contract opened, on the transaction
  that answers a wrong challenge) and the fee budget's key, none of the
  dispute's keys. You prove first; the
  tower asserts your proof, waits for the hub, and answers a challenge
  from the contract's kept garbled circuits. At worst it stays silent,
  so several can run at once.
- **BitVMX** (`--statement bitvmx`): the contract's one-time secrets
  and its fee budget's key, never your wallet's key. It proves your
  withdrawal, wraps the proof, runs your side of the search, escalates
  and answers each of the hub's moves, to the payout. At worst it can
  lose this one dispute (which is the hub's gain), not take your money.

This is the manual route, on a machine outside your own network (a VPS).
Both have been run on Mutinynet: BitVMX's from a GCE `n2-highmem-4`,
BABE's from a 4-vCPU x86 VPS
([BABE's other endings](explainers/babe-endings.md)).

## The machine

| | needed | measured (4 vCPUs) |
|---|---|---|
| CPU | x86_64 (the image is `linux/amd64`; BitVMX's Groth16 wrap is x86 only); 4 vCPUs will do | BABE: next to nothing, it waits on blocks. BitVMX: proof 349 s, wrap 263 s, the traced run about 2 min: escalated about 12 minutes after start |
| memory | 16 GB for BitVMX (the wrap at 7.8 GB or more); BABE, little | |
| disk | 15 GB | the images 6 GB (the tower's 0.8 GB, RISC Zero's prover 5.2 GB, which BitVMX's wrap needs); the build's cache 6 GB more; a BABE package's kept instances 243 MB; BitVMX's working files 0.5 GB |
| network | outbound only: GitHub, Docker Hub, RISC Zero's installer, the Esplora servers | |

Under BABE the tower only waits on blocks. Under BitVMX, proving and the
wrap take all the cores for about 10 minutes, so other services on a
shared machine slow down meanwhile.

### Docker

The machine needs Docker with compose v2, and your user in the `docker`
group:

```sh
uname -m                                      # x86_64
curl -fsSL https://get.docker.com | sudo sh   # if Docker is not installed (Debian's own packages are older)
sudo usermod -aG docker "$USER"               # then log out and in again
docker ps                                     # works without sudo
```

The new group reaches new logins only. A tmux (or screen) server that
was already running keeps the groups it started with, and so do the
shells inside it, even in a session made after you logged in again:
`tmux kill-server` and start afresh, or `newgrp docker` in that shell.

## 1. The image

On the machine (the build takes 30 to 50 minutes on 4 vCPUs, so run it
in tmux):

```sh
git clone https://github.com/AdamISZ/lichen && git clone https://github.com/AdamISZ/ln-gap
git -C ln-gap checkout "$(cat lichen/LNGAP_REV)"
cd lichen
deploy/tower/build.sh
cp deploy/tower/.env.example deploy/tower/.env
mkdir -p deploy/tower/data
```

`build.sh` also pulls RISC Zero's Groth16 prover image, by its digest:
BitVMX's wrap runs it as a container of its own. The build's cache can
be deleted once the image is built (`docker builder prune`).

The settings, `deploy/tower/.env`:

| setting | what |
|---|---|
| `NETWORK` | the contract's network |
| `ESPLORA` | two Esplora servers, comma-separated. A move is answered only once both report it confirmed, in the same block, with the same witness; a disagreement is logged as `chain: ALARM`. On Mutinynet, `https://mutinynet.com/api` twice will do for a trial |
| `STATEMENT` | the contract's: `babe`, `bitvmx` (the tower proves), or a mock (`babe-mock`, `bitvmx-mock`) |
| `R0WORK` | an absolute path on the machine for BitVMX's wrap's working files, such as `/home/<you>/r0work` (set it under BABE too) |

`R0WORK` is mounted at the same path in the tower's container because
the prover's container is started through the machine's Docker, which
reads the path as the machine's.

## 2. Your wallet: refused, then export

On your own device, once the hub has refused a cooperative withdrawal
(`lichen withdraw <contract> <amount>` returned the amount on the L2 and
then failed).

### Under BABE

The tower can't sign a proof, so you prove first. Run `lichen dispute
<contract> <amount>` yourself until the hub responds and the proof falls
due, then prove as it tells you, on x86 Linux with Docker
([the README](../README.md#under-babe): about 15 minutes on 4 cores; the
tower's machine will do). Then export with the proof:

```sh
lichen --network mutinynet --wallet alice.json --statement babe \
  export-dispute <contract> --input claim.hex --out package.json
scp -r package.json package.d <you>@<machine>:lichen/deploy/tower/data/
```

`package.json` (under 1 MB) holds your signatures, the claim and the fee
budget's key; `package.d` the contract's kept garbled circuits (about
240 MB), which the tower needs to answer a challenge. The proof is due
by `T_A`, shortly before the contract closes (on Mutinynet, a week after
it opened), so there is time to get the machine ready. The tower never contacts the sequencer.

### Under BitVMX

```sh
lichen --network mutinynet --wallet alice.json --statement bitvmx \
  export-dispute <contract> --out package.json
scp package.json <you>@<machine>:lichen/deploy/tower/data/package.json
```

`package.json` (a few MB) holds the contract and its one-time secrets.
Treat it as a secret for this contract: whoever has it can play (or
throw) this one dispute. Copy it straight to your own user on the
machine, not through another account.

Nothing forces you to export at once: the dispute has to be under way
well before the contract closes (on Mutinynet a week after it opened),
so get the machine ready first.

The package carries what the tower proves from: the return's note, its
path, the signed root and the chain receipt at its height, as your
wallet kept them (it keeps each as soon as the sequencer has it; a
cooperative withdrawal that was refused waited for both). Then the
tower never contacts the sequencer.

If the export happened before the sequencer proved the return's
height, the package lacks the chain receipt and the tower fetches it
from the sequencer named in the package while it proves (the first few
minutes). A public sequencer needs nothing. If the package names one on
your own device (`http://127.0.0.1:18300`), either export again once
`lichen chain-receipt <contract> /dev/null` succeeds, or open a
tunnel to the machine from your device before you start the tower, and
keep it open until the log says `wrapped in Groth16`:

```sh
ssh -N -R 18300:127.0.0.1:18300 <you>@<machine>
```

The tower runs on the machine's own network, so its 127.0.0.1 is the
tunnel's end.

## 3. Start

```sh
docker compose -f deploy/tower/docker-compose.yml up -d
docker compose -f deploy/tower/docker-compose.yml logs -f tower
```

The log of a BABE dispute on Mutinynet (2026-10-29), a hub that refused
but didn't challenge: the tower finds your `request` and the hub's
`respond` on chain, asserts, and after the hub's window posts
`success`:

```
requesting 300000 sats, 02af03c8…
waiting for the hub's response: its window ends at block 3544053
the hub responded: asserting the proof, 3475a989…
asserted at 3544085: the hub may challenge until block 3544325
no challenge came: success pays the user, d1e01390…
Unchallenged(d1e01390…): the payout is d1e01390….
```

Had the hub challenged, the log would go on `challenged: opening the
kept instances with π1's secrets`, then `kept instance <k> opens:
answering with its msg`.

Under BitVMX (the Mutinynet run):

```
proving the withdrawal of 22000 sats (note 21) with lngap-r0
proved in 348.9s (444648 user cycles, 1 segments)
wrapped in Groth16 in 262.7s
/tower/package.d/proof/claim.hex: the claim's input for the BitVMX verifier, 204 bytes
escalating: the claim of 22000 sats and move 1 of 21, <txid>
escalated, confirmed at <height>
publishing the rest of the claim's input, <txid>
published, confirmed at <height>
waiting for the hub's move 2: its window ends at block <height>
the hub chose a segment (move 2)
move 3: the trace's hashes at the seven boundaries inside that segment
...
```

and so on to the payout. Either survives a restart (`restart:
on-failure`; its state is `deploy/tower/data/package.state.json`, its
working files `deploy/tower/data/package.d/`). It posts each of your
links at its floor of 1 sat/vB (fee bumps need a separate anchor key:
not yet).

### A trial against your own hub

On a test network, start your hub (rebuild its image first,
`deploy/hub/build.sh`) with one of:

- `REFUSE_FOLDS=1` in `deploy/hub/.env`: it refuses every withdrawal,
  but disputes only false claims, so a true claim ends unchallenged;
- `HOSTILE=1`: it refuses every withdrawal and disputes every claim,
  true ones too, so the tower plays the longest honest dispute (under
  BitVMX the whole search, and the hub takes the output by its timeout
  if the tower's proof of the last step comes late).

The hub is the tower's other side, so keep it and its node running
throughout (on a Mac, `caffeinate -i`); what is tested is that your
wallet stays idle.

## 4. After: sweep on your own device

The tower stops at the payout: your bit outputs and the reserves wait
for your own key. Its state file is the container's, so root's: copy it
out with Docker, bring it back and sweep:

```sh
# on the machine
docker compose -f deploy/tower/docker-compose.yml cp tower:/tower/package.state.json .
# on your device
scp <you>@<machine>:lichen/package.state.json .
lichen --network mutinynet --wallet alice.json --statement babe \
  sweep-dispute <contract> --tower-state package.state.json
```

(`--statement bitvmx` for a BitVMX contract.) Your outputs can be swept
`δ` blocks after the payout confirms (40 on Mutinynet); the command
waits for that. Then delete the package and its working files from the
machine (`deploy/tower/data/`, `R0WORK`), or the machine itself.

`deploy/tower/cloud-init.yaml` sketches a one-step launch on a fresh
VPS: untested, and it builds `master`.
