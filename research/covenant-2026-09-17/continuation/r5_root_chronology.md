# R5: proof-root chronology and the exact price of reusable roots

Date: 2026-09-17. Question: can `alpha=H(proof)` act as a DER signature and
bind a transparent exact-output proof to a native recovery-key puzzle, with
honest **total** setup, audit, proof and search work below `2^64`?

**No complete construction is obtained.** A useful refinement is that the two
rare events need not always multiply: they become additive if one valid root
really supports sufficiently many later transaction candidates. This note
specifies that missing condition, counts both digest rounds, and identifies
which proposed proof objects do and do not provide it. It does not establish
a general impossibility or an attacker lower bound.

The derivations are `inspected`; six exhaustive finite-model checks and one
small commitment-timing counterexample are `locally-reproduced`. Deployment
is `unclassified`. No Bitcoin Script was compiled or executed. There are no
locking-script, witness, opcode, hint-item or stack metrics for these host
models; no complete witness or rare-event hit was generated. No field tests
ran.

## 1. A concrete dependency graph before any probability estimate

Let `F` denote the concrete funding outpoint, `O*` the required ordered output
vector including amounts and scripts, `v` a proposed transaction nonce, and
`T_v` a spending transaction. Let `pi` initially mean the committed proof
oracle, rather than challenge-dependent openings or final Fiat–Shamir
responses. The native signature interpretation is

```
alpha = H(pi) = DER(r,s,flag)
z_v   = LegacySignatureHash(T_v, scriptCode, flag)
P_v   = r^-1 (s R - z_v G), where x(R) mod n = r
Pin   = IsDER(H(P_v)).
```

This note gives the signature flag check, readable query `q(D)`, authentic
openings, and a complete output verifier as **unimplemented requirements**.
Their absence is not absorbed into a probability estimate. All possible
recovery points must be counted. The known public 32-byte DER hash used in
the other R5 experiment needs the `x=r+n` recovery branch; recovery cannot be
approximated by testing only `x=r`.

For an ordinary instance-specific computation trace, the dependencies are

```
F, O*, v, D1, D2 -> T_v and its reference native computation -> pi
pi -> alpha -> native recovered keys and their rare predicates
native results -> selected D1, D2 -> proof queries -> openings
```

If the trace computes the native digest rounds for the *selected* subsets,
this graph is cyclic: `D -> pi -> alpha -> native search -> D`. One cannot
first mine alpha and then silently replace the trace with one for the chosen
D. Fixing D in advance removes that cycle but incurs the small-subset-domain
costs below. A function commitment that genuinely supports later inputs could
remove the cycle too, but it needs an actual evaluation verifier.

There is a second, distinct cycle if the committed trace includes its own
reference recovered key:

```
pi -> alpha -> (r,s,R) -> P_reference -> pi.
```

Moving EC recovery out of the initial trace leaves a well-formed chronology,
provided an authenticated later calculation links the committed reference
sighash to the native key. Calling that calculation part of the already
committed trace does not implement it. This is a concrete dependency problem,
not a claim that every argument with a hash-derived challenge is circular.

A usable multi-round proof commits an initial oracle, derives a challenge,
then provides answers whose openings are checked against that earlier
commitment. If `H(proof)` instead hashes the *whole* final transcript including
answers to a challenge derived from that same hash, a fixed-point obligation
has been introduced. Ordinary Fiat–Shamir chronology does not justify it.

## 2. The exact model that allows root amortization

Here is a favorable, acyclic candidate interface. It is precise enough to
test a future proof system against:

1. After F is fixed, construct an oracle `pi` for a family of L distinct
   transactions `T_1,...,T_L`, all with outputs exactly O*. Its semantic
   validity survives choosing any of those transactions later.
2. Mint a usable root signature alpha without changing this family or its
   committed truth. Suppose the expected root-mining cost is `1/a` root
   trials. This generously allows cheap padding or an equivalent authenticated
   commitment transformation. Such a transformation still needs Script code.
3. For each family member, test a native pin. If it hits, search m1 eligible
   subsets in digest round 1 and then m2 in round 2. Eligibility must preserve
   validity of the *same* committed oracle. If any stage is exhausted, move
   to the next family member without replacing pi or alpha.
4. After all L members fail, mint a new alpha and try another independent
   family of native outcomes. Charge any necessary reconstruction or audit.
5. Supply authentically opened answers. The full verifier must enforce the
   allowed-output relation, not just accept an authorization held by the
   creator.

Assume independent ideal native gates with probability p and efficiently
enumerable Cartesian restrictions in the two digest rounds. Define

```
s1 = 1-(1-p)^m1
s2 = 1-(1-p)^m2
b  = p*s1*s2                    # one transaction succeeds at all three stages
t  = 1-(1-b)^L                  # one minted root has a successful family member
```

The expected native-query cost of a single attempted transaction is
`c=1+s1+s1*s2`: one pin query, `s1/p` round-1 queries conditional on the pin,
and `s2/p` round-2 queries conditional on both preceding successes. Truncating
at the first successful transaction gives `t/b` attempted transactions per
root in expectation. Restarting roots therefore gives

```
E_queries = 1/(a*t) + (1+s1+s1*s2)/(p*s1*s2)
          = 1/(a*t) + 1/(p*s1*s2) + 1/(p*s2) + 1/p.
```

The first term is the new root-renewal charge. The remaining terms recover
R4's pin-plus-two-round result. This is the exact expectation of this
specified strategy in its independent model. It is neither a universal lower
bound nor a claim that real hash schedules have that independence.

For example, setting the hashed proof blob literally equal to P would make
`alpha=H(pi)` and `H(P)` the same hash value: the two DER events coincide.
But the successful native signature would then require
`r(H(P))*P + z*G = s(H(P))*R(H(P))`. Choosing P by ordinary recovery changes
H(P) and therefore changes that equation again. This proposal has traded
independent rare gates for a coupled fixed-point problem and still has to
explain how a single key blob commits a valid opened proof. The renewal model
does not establish its cost or exclude a distinct construction solving it.

The model script exhaustively enumerates all native outcome tables for
`a=p=1/2`, `L=1,2,3`, and `m1=m2=1,2`. All six exact rational expectations
match the formula. The largest configuration enumerates 32,768 tables.

## 3. What the honest cost would have to achieve

Take the prior 32-byte DER predicate's `p=780555/2^65`, approximately
`2^-45.425859`. Setting `a=p` here grants nonzero scalars, a valid recovery
point, and an enforced output-binding flag for free. Thus a is an optimistic
root probability, not a measured rate of usable root signatures.

With ample digest freedom, `s1≈s2≈1`:

- One transaction per root (`L=1`) costs about `2^90.8517` root/native queries.
  Minting DER first does not make the later independent pin free.
- A reusable family of `L=2^27` transactions brings this model to about
  `2^63.8517` queries. That leaves less than a factor 1.11 below `2^64` and
  cannot support a total-work claim after ignored costs are restored.
- `L=2^32` gives about `2^58.8522` queries, leaving a possible arithmetic and
  proof-work margin in this model. This is a concrete amortization target:
  billions of actual statement-preserving transaction choices per root.
- If each digest round has only `m=2^40` eligible subsets, the `L=2^32`
  estimate is instead about `2^69.7371`. Root reuse does not eliminate
  exhaustion of the two later rounds.

Exact canonical flag `0x01` would cost another factor 256 in root mining if
it were imposed solely by conditioning a random root. That is not the only
output-binding legacy flag choice: the legacy algorithm treats base values
other than NONE and SINGLE as ALL, giving 240 of 256 bytes that commit all
outputs. An honest choice from this set is still **not native enforcement**
that an adversary uses it. The costs above grant that enforcement for free.

Recovery availability also changes a. Depending on r, both `r` and `r+n`
can be eligible x-coordinates. Zero r or s is syntactically DER but unusable
for verification. These issues can be included in an exact a once a concrete
root distribution and flag check exist; assigning all DER roots a uniform
one-half recovery penalty would be unjustified.

The complete work, even within this model, has the form

```
W = C_once + C_root/t
    + c_pin/(p*s1*s2) + c_round1/(p*s2) + c_round2/p + C_final.
```

`C_root` includes every proof reconstruction, root-format trial, and audit
that repeats at root renewal. If one audited proof body truly persists,
charge its construction in `C_once`, and only its authenticated root variant
in `C_root`. Native per-query costs include transaction hashing and EC
recovery. Subset enumeration, root hash blocks, and opening generation are
not automatically unit operations. The numerical examples are query counts,
not measured complete work.

## 4. Which apparent free nonces actually support L?

Changing a legacy scriptSig can leave the signature message unchanged. Such a
change supplies no fresh native pin instance and does not contribute to L.
Changing a field that really changes an ALL sighash, or changing a genuinely
distinct authenticated FAD context, supplies a fresh candidate only if the
same oracle and its enforced public-input binding remain valid for it.

Three plausible reuse proposals have different obligations:

| Root commits | What may be varied after alpha | Remaining obligation |
| --- | --- | --- |
| A trace of one final transaction and selected subsets | Only representation changes proven irrelevant to the statement | Show that they nevertheless change the native rare event; ordinary ignored scriptSig bytes do not |
| The universal circuit/program | Public inputs and execution witness | Bind the input-dependent wire values before their effective queries; program correctness alone does not do that |
| A function/table of correct evaluations for a family | The family index and inputs actually covered by the commitment | Authenticate selection and evaluation; count table construction, openings, and all native-to-readable value links |

For the second row, the fixture fixes the program constraints `a=x` and
`y=a`, public input `x=0`, and false claimed output `y=1`. A fixed trace a
satisfies exactly one of the two checks. If only the program is committed
and a may be selected after the queried constraint is known, choose a=0 for
the first query and a=1 for the second; every query accepts. This proves only
the timing distinction. It is not an attack on a specified universal proof
system, whose additional commitments may prevent the choice.

The third row is the most concrete remaining route within this family:
commit a reference function with enough genuine input freedom, then verify
its later evaluation. A table of all desired SHA/sighash evaluations is
independent of alpha where alpha is absent from the legacy scriptCode. But
the EC recovery depends on alpha, so it needs a later authenticated
evaluation too. A bare root or retained HORS authorization supplies neither
calculation. Plain Merkle openings still need the missing child-to-parent
byte binding; a polynomial/function commitment needs an actual verifier that
fits the mandatory native execution path.

Precomputing all table rows is not automatically above `2^64`; a modest row
cost and an approximately `2^32`-row family can fit that abstract budget.
The problem is to state the function, all input dimensions including digest
subsets, the authenticated opening, and the Script cost. Counting only the
transaction dimension while omitting roughly `2^45` or more digest choices
would undercount the proposed full table drastically: a literal table with
`2^32` transactions and `2^45` digest choices already has `2^77` entries for
one round. A compact functional
representation could avoid a full table, but must be supplied and verified.

## 5. Result and next falsifiable target

There is no valid shortcut from `H(proof)` to a once-only `2^45` setup charge
for an ordinary final-transaction trace. There is also no general argument
that two such gates always cost `2^90`: genuine proof reuse can change the
cost substantially. The decisive constructive target is now quantitative:

Give an authenticated reusable oracle that supports at least roughly `2^32`
distinct allowed transactions per root and enough eligible subsets in both
rounds, while keeping its initial statement independent of its derived alpha.
Specify the later reference EC evaluation and exact query-opening checks.
Then measure all setup, audit, hash, curve, enumeration and verification
costs and analyze adaptive false-output choices and retained creator state.

Alternatively, eliminate one rare event with a different native commitment
interpretation and provide its full Script binding. No such implementation
is claimed here.

Sources: the pinned primary-source references in
[R4's QSB/Fiat–Shamir analysis](r4_succinct_reference.md) and
[the seven-direction report](../seven/README.md). This continuation introduces
a derived strategy model, not a newly reported protocol. Reproduce with
`python3 research/covenant-2026-09-17/continuation/r5_root_chronology.py`.
