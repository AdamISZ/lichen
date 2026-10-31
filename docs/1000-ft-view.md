## How Lichen works, without the details

The root idea is this: generic proving of L2 state in a totally permissionless way on Bitcoin is possible, with advanced cryptography, but severely hampered by Bitcoin's scripting constraints (lack of covenants, lack of big integer arithmetic, and several others). **Lichen's idea** - some of these constraints are simply bypassed if you make one tradeoff: have the redemption be settled within a 2 party contract, whose outcome is adjudicated on Bitcoin, rather than have the actual contract be in Bitcoin directly.

This trades off *liquidity* but not *trustlessness*, if carefully designed. That is, it means that a user can trustlessly withdraw the funds they are owed by forcing that withdrawal in a presigned contract with a "hub" counterparty, during the time for which the contract is live (imagined as a multi-month contract, or in any case a long time). Why a liquidity tradeoff? Because the user can only withdraw up to however much bitcoin was locked into that 2 party contract (so here "liquidity" in exactly the same sense as Lightning; indeed, this contract can be embedded as an output in a Lightning channel).

This tradeoff is, we claim, easily worth it: users get to transact in pure bitcoin, with arbitrary L2 rule sets like the shielded (highly private) transfer case, or a smart contracting case, with no hub involvement, safe that they can get their funds out without intermediaries. More costly, yes, and more limited in scale than a completely disconnected blockchain (mostly), but a much better model.

**An example of what a user does**: the user requests a new contract with the hub. They say "here, I'll deposit 10M sats, and I also want 10M sats inbound". Here 'inbound' is conceptually *almost* identical to what you already understand as liquidity in a Lightning channel, with a nuance mentioned later.

The contract is setup with 20M sats plus some reserve from both parties to cover fees - which will be returned to them unconditionally whenever the contract closes. The user's initial balance on L2 is 10M sats, of course, and they can safely receive up to 10M more, in that contract. They might pay for this inbound, just like you might today with an LSP.

### Instantiating a particular L2 with the lowest trust requirements we can engineer

So what is this "L2"? There's flexibility here; you could just have a signing quorum, or a smart contract on another blockchain, but in this repo we do instantiate a specific design: a "sequencer" is an entity run by the hub: it takes people's transactions and includes them into a new block every short while. Every transaction is included in a ZKP which is recursive so fixed size at every proceeding block. (Reminder: this doc is non-technical! The implemented ZKP tech is described [here](explainers/pipeline.md)).

So how does a user Alice get her money out; the right amount, at any time she wants? For concreteness imagine she took her 10M sat deposit, then paid 2M sats to Bob, then received 7M sats from Charlie.

OK, so she has 15M sats in the L2 and wants to withdraw it. The first version is overwhelmingly likely: she sends a ZKP to the hub that the current state of the L2 contains a note that she owns whose value is 15M sats. The hub can verify this trivially, and there is a cooperative "fold" event in the 2-of-2 contract, paying Alice back her 15M sats plus reserve. (The default way for this to happen is for Alice to actually send a special withdrawal transaction on L2 to the hub).

But then, what happens if the hub just dies and disappears? Even worse if the sequencer dies too (which makes sense; here we're assuming they're the same entity). In this case you can't do more transactions on L2 because the sequencer that advances the L2 state is not responding. And you can't get the hub to agree to a withdrawal in your 2-of-2 contract either. But it's no problem; the contract has a clause "claim" that lets you post "here's the nullifier of my note and here's how much money it says I'm owed, and I can prove it". If the hub literally does nothing your claim stands, and after a timeout you can make that withdrawal (in fact such a hub is of course in danger of you posting an *invalid* proof to claim more than you're actually owed; but that's inevitable if it's dead and won't respond; it's not a failure of the protocol).

So, what if the hub is actually malicious? It stops processing L2; so you want to get out. You post the above "claim" but then it answers: to answer it has to do one of 2 things: (see detail in [the exit explainer](explainers/exit.md)) either prove that your note is invalid because it was spent elsewhere --- that's a "counter-proof", or, prove that your ZKP of inclusion is invalid. We can enforce that who gets the money is the honest party, in every case. The only assumptions are the same ones you have in Lightning, but a bit stronger: you assume you can post transactions enforcing the adjudication successfully to Bitcoin's blockchain.

--------

Now, some explanatory notes justifying some parts of the above:

**Validity proofs** - At every L2 block (which can just be seen as a bundling of some L2 transactions), the sequencer proves *recursively* that the state update is correct: it constructs a proof of "the previous proof validates AND these new transactions validate", which will be fed in as the first input to the next block's proof, etc. These proofs are STARKs and due to the recursion they don't change in size as time progresses. But the size and mechanics are less important --- what really matters is that since every state transition is proved correct, you do not trust the sequencer to not make fake transactions; it can't. All it can do is rewrite  with another *valid* history or stop publishing updates.

**Preventing history rewrites** - this is the reason we *anchor* state roots from the sequencer, on to Bitcoin. Full "finality" of transactions is only considered achieved once that Bitcoin transaction is buried under a reasonable number of blocks, e.g. 10. This makes attempting double-spend attacks on users by a malicious hub vastly expensive to the extent it'd be nearly impossible.

**Mass exit risk** - With the new BABE variant, currently implemented in place of BitVMX, the amount of blockspace needed in the worst case of everyone trying to exit at once, allows a hub to support 10-50k users, assuming it had the necessary liquidity. Cross-hub transactions are eminently possible also, but bear in mind that by the nature of mass exit, it's global; the problem doesn't entirely disappear by spreading responsibility over multiple hubs.

