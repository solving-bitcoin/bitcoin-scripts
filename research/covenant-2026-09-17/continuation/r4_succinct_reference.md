# R4 continuation: selected queries, pinning, and a compact proof verifier

Date: 2026-09-17. Question: can transaction-bound readable subset indices
serve as Fiat–Shamir queries to a transparent proof of the allowed reference
transaction, with the complete native check and verifier below 201 legacy
opcodes and honest total work below `2^64`? Creator state is retained.

**No complete protocol found.** The new result is a quantitative distinction
between a prover-selected native digest and an ordinary random challenge,
including QSB's separate transaction pinning. It rules out applying ordinary
sampling soundness without a native search analysis; it does not rule out a
proof system specifically designed for that search model.

The mathematical audit is `inspected`; the exact finite-model checks are
`locally-reproduced`; deployment is `unclassified`. No Bitcoin Script or
transaction was executed, no rare event was mined, and no byte/opcode/witness
or stack measurements are claimed. There are no Script hint items or stack
metrics for these host-side enumerations. No field tests ran.

## 1. Explicit candidate, with even the openings granted for free

Let `c` bind one PCP proof or computation trace `pi` for the statement
`x=(funding_context, O*, D)`. Consider

```
Pin(T_actual)
AND NativeRound(T_actual,D)
AND OpenAndVerify(c, q(D), answers, x).
```

For now grant correct binding openings, input binding, and a constant-time
local verifier. Also grant that `c` is fixed before the native challenges.
Those are generous concessions, not implemented Script features. A proposed
PCP verifier says that for every false `x` and committed `pi`, at most an
epsilon fraction of *uniform random* query strings accept.

The substitution `q=q(D)` is not automatically that experiment. In Binohash
and QSB the prover selects candidate subsets and tests the native puzzle;
the selected subset is not a deterministic uniformly sampled function of T.
The prover can first choose an accepting query and then search only subsets
mapped to it. A constraint that D names genuine native context deletions
does not enforce a distribution over the selected D.

This does not make the native puzzle free. It changes the soundness question
to **how many eligible subsets remain, and which native puzzles have to be
repeated when this restricted set is exhausted**.

## 2. A one-gate counterexample, and the essential QSB qualification

For a single gate `Native(T,D)` with per-candidate success p and no independent
pin, suppose the creator can efficiently find `D0` whose local proof query
accepts a false fixed trace. Fix D0 and vary transaction metadata. Expected
native work is `1/p`, independent of the fraction of all queries accepting
that trace. The proof constraint has provided no additional native work.

The deterministic fixture uses a fixed bit `x=0` committed before the search
and four inconsistent constraints `x=0, x=1, x=1, x=1`. Exactly one of four
queries accepts this trace. Exhaustively enumerating every random native
relation on three transaction candidates and four queries at `p=1/2` gives
success `7/8` when targeting the accepting query, versus `169/512` when the
query is separately uniform each time. This demonstrates the sampler
distinction, not a concrete Bitcoin attack or a claimed PCP construction.
The fixed trace's accepting fraction is 1/4; the maximum accepting fraction
over all traces for this toy constraint system is 3/4.

**This is not an attack costing `1/p` on published QSB.** QSB separately pins
T before searching two digest rounds. Holding all their subsets fixed forces
independent rare events on the same T. In the ideal independent model,
pinning plus one fixed round costs `(1+p)/p^2`; pinning plus two fixed rounds
costs `(1+p+p^2)/p^3`. For the SHA256 DER parameter used in Search 1,
`p=780555/2^65`, these are approximately `2^90.85` and `2^136.28` native
predicate queries. QSB's published RIPEMD160 gate has a different p.

Neither number includes EC recovery, transaction hashing, setup, or mining
infrastructure. They cannot be reported as total concrete work.

## 3. Exact accounting for restricted query fibers after pinning

Suppose that after pinning each digest round has exactly m admissible
subsets whose query passes the false-proof check. For now require Cartesian
round restrictions and independent native gates, and grant cheap enumeration
of the admissible subsets. Let

```
s(m) = 1-(1-p)^m.
```

Search pin first, then each digest round sequentially; abandon a pinned
transaction after exhausting a round. Expected primitive native-query counts
for this explicit strategy are

```
pin + one round:  E1(m) = (1 + 1/s(m))/p
pin + two rounds: E2(m) = (1 + 1/s(m) + 1/s(m)^2)/p.
```

A round tested up to m candidates uses `s(m)/p` queries on average. Dividing
the per-cycle cost by cycle success gives these expressions, including all
discarded pinned transactions. The fixture independently exhausts the toy
case p=1/2, m=1..4, one/two rounds, and checks the exact rational results.
For unequal m1,m2, the second expression is
`1/(p*s1*s2) + 1/(p*s2) + 1/p` in the specified round order.

Consequences for an epsilon-fraction accepting query set over total domain M:

- If its efficiently enumerable preimage has `m≈epsilon*M` and `p*m >> 1`,
  the extra proof constraint adds essentially no native search cost. Spare
  subset entropy absorbs the sampling condition.
- If `p*m << 1`, pinning plus one round costs approximately `1/(p^2*m)`;
  two independently restricted rounds cost approximately `1/(p^3*m^2)`.
  The pinning mechanism can therefore preserve a real amplification.
- A bound on the *fraction of uniform queries* alone does not determine m.
  The implemented q(D), its nonuniform fibers, bonus selections, every
  canonical encoding, and the correlation between the two rounds matter.
- Restricting honest subsets to encode a desired reference proof can impose
  exactly the same exhaustion penalty. This must be charged before claiming
  an honest/attacker separation.

These are costs of one specified strategy, not general lower bounds against
adaptive creators. They do not include cost of finding accepting queries or
constructing/auditing the proof. Statements depending on D, correlated proof
queries across rounds, and native hash reuse need a larger analysis.

## 4. Commit the computation before funding: what becomes auditable?

A circuit's universal wiring and gate tables can be fixed and audited before
funding. That validates the *program*. A proof/trace of its evaluation on the
final funding context is another object. Embedding its commitment in the
locking script changes the funding outpoint it has to compute. Calling the
universal table a proof of this particular evaluation conflates these two
objects.

For a fixed trace whose input is independent of funding, an exhaustive audit
can reject false traces before funding. That is useful but it does not
establish the input linkage to the actual funding instance or readable D.
For an instance-specific trace committed after funding, the root must be
bound to the native query generation by a concrete mandatory check. Supplying
the same root in two witness descriptions does not do this.

Thus the toy false-trace example does not assume an honestly audited *false
computation* would be accepted during setup. It shows why merely auditing
commitments or a universal program is not enough to invoke PCP soundness.
An audit that checks every actual reference-computation constraint and binds
its immutable commitment would remove that example, but still needs a
funding chronology with total setup/audit/retry cost below `2^64`.

## 5. Root-as-signature: a real binding idea, still missing a verifier

A distinct post-funding idea is `alpha=H(pi)` and use alpha itself as a DER
ECDSA signature. For its encoded `(r,s,flag)` and native transaction digest z,
recovery produces

```
P(T,alpha) = r^-1 (s*R - z_flag(T)*G).
```

Requiring `CHECKSIG(alpha,P)` and a native hash-to-DER gate on P makes changing
alpha change the rare-event instance. Alpha need not have been a constant
deleted from the locking script. This algebraic coupling avoids the simple
"post-funding root is absent from every challenge" objection. It deserves
separate investigation.

It does not yet give the requested protocol:

1. A hash-derived signature's trailing sighash byte is not automatically ALL.
   An honest offchain choice of ALL does not enforce it against the creator;
   NONE/SINGLE/ANYONECANPAY cases require explicit analysis or exclusion.
2. It remains necessary to commit all proof data *before* the effective
   challenge, specify pinning and digest gates with alpha bound in each, and
   bound the search over alternative roots and recovery branches. A native
   recovery formula alone supplies no uniform readable query.
3. Hashing a whole short proof could bind it in one opcode, but Script still
   needs to read the committed components. Hashing a separately supplied
   serialized proof and checking unconstrained answer items is insufficient.
4. A DER root chosen by hashing arbitrary pi must satisfy syntax as well.
   Its rarity is setup/proof-generation work, not free entropy. If the root
   length or format compresses its available space, collision binding must
   be reassessed for that restricted distribution.

No full bytecode, adversarial flag proof, or affordable complete verifier is
claimed for this root-as-signature option.

## 6. Opening and arithmetic costs still cannot be suppressed

A conventional Merkle opening requires verifying each parent against a hash
of both ordered children. Native Script cannot concatenate two witness items.
Supplying a 64-byte parent preimage and separately supplying its two claimed
children does not authenticate those children without another linkage check.
Counting one native hash per level presumes that missing operation.

A direct table avoids Merkle concatenation but has its own concrete budget:
M independent 32-byte commitments take `33*M` locking-script bytes before
any code or other data. Bare legacy's 10,000-byte limit bounds this particular
representation to at most 303 commitments; P2SH's 520-byte redeemscript cap
bounds it to at most 15. This is not a lower bound on compressed or structured
commitments. The table's live items and all opening/index/operand items still
share the 1,000-item combined stack bound. A future implementation must report
their exact coexistence and hint counts; none is constructed here.

Small query complexity also does not imply a small arithmetic verifier. The
statement needs reference transaction serialization, hash/recovery semantics,
and authenticated matching input/output data. An arbitrary native hash call
proves a relation on one opaque item; it does not make its byte fields readable.
Search 1's 199-opcode native fragment leaves two counted operations, so this
route requires redesigning that fragment, not just appending a named PCP.

## Sources and reproducibility

- [QSB, immutable source commit
  2c9172051d5c150ef0a994ca6b988a08a3ef9e85](https://raw.githubusercontent.com/avihu28/Quantum-Safe-Bitcoin-Transactions/2c9172051d5c150ef0a994ca6b988a08a3ef9e85/paper/QSB.tex):
  pinning, two digest rounds, subset choices, and bonus keys. The local copy
  fingerprint is recorded in `seven/search6_sources.json`; it is not asserted
  to equal the immutable source unless independently checked.
- [Fiat–Shamir Transformation, draft-irtf-cfrg-fiat-shamir-03,
  August 2026](https://datatracker.ietf.org/doc/draft-irtf-cfrg-fiat-shamir/03/):
  work-in-progress primary specification for deriving verifier messages from
  the encoded instance and prover transcript. It is not a proof for the
  Binohash substitution analyzed here.
- `seven/search4_public_bridge.md`, `search6_related_work.md`, and
  `search7_synthesis.md` supply the prior funding, garbling, and mandatory
  verification obligations; this note narrows the sampled-proof route.

Run `python3 research/covenant-2026-09-17/continuation/r4_succinct_reference.py`.
No network, wallets, or external transactions are used by this reproduction.

Next falsifiable target: give q(D), a commitment representation, actual opening
and local-check bytecode, and an alpha/funding chronology; demonstrate a full
honest witness and an explicit adaptive false-proof search bound. Count the
entire native-plus-proof script, all hints and stack items, all preprocessing,
auditing, proof generation, and every discarded pinned transaction.
