# Search 7: force the verifier, and audit the fixed-nonce construction

Date: 2026-09-17. Question: can the new 199-opcode native two-hit fragment be
completed by a large Taproot verifier, or by a public relation between its
indices, while enforcing exact outputs with retained creator state and honest
total work below `2^64`?

**No complete construction found.** This attempt supplies an explicit hybrid
replacement algorithm, a narrower missing lemma, and a finite-oracle caveat
with a deterministic exhaustive fixture. It does not reinstate the obsolete
27-bit/pair-only nonce exclusion. The 56.084697-bit semantic nonce domain in
[Search 1](search1_nonce_encoding.md) is real progress at its stated boundary.

Evidence: the reduced-model fixture is `locally-reproduced`; the construction
audit is `inspected`. Deployment is `unclassified`. No Bitcoin Script was
executed, no rare witness was mined, and no compiler measurement, complete
witness size, hint count, or stack peak is newly claimed. No field tests ran.
The fixture uses no transaction or witness inputs; its host state is not a
Bitcoin stack metric.

## 1. An explicit hybrid, and its missing implication

Try a spend with two inputs:

```
input 0: legacy output C, running Search 1 on native key A and nonce d
input 1: Taproot output V, running an unlimited-opcode arithmetic verifier
```

For the fixed legacy signature `(r,s,h)=(1,1,ALL)`, choose a recovery branch
`R=+lift(1)` or `-lift(1)` and write

```
z(T) = BE256(SHA256d(M_legacy(T,C,ALL))) mod n
A(T) = R - z(T)G
Q_C(T,d) = DER(SHA256(encode(A(T))))
           AND DER(H_d(encode(A(T))))
           AND SHA256(encode(A(T))) != H_d(encode(A(T))).
```

The proposed Taproot program proves a statement such as

```
B = encode(R - H256(M_legacy(T_ref,C,ALL))*G)
outputs(T_ref) = O*
metadata(T_ref) = metadata(T_actual)
P_V(T_actual,B,d) = valid proof of these equations and the matching B gates.
```

There are two independent connections to enforce:

1. Every spend accepted by C must also execute this exact V program.
2. That V execution must use the same B/nonce data as C, with B linked to A
   through the intended bridge. Equal variable names in the witness
   description do not establish cross-input equality.

The native ALL check in C commits to the actual input outpoints. It does
**not** prove that one outpoint's spent script is V. In this hybrid A remains a
witness key recovered after choosing the transaction; changing an outpoint
changes A rather than failing a fixed-key authorization.

Concrete retained-state replacement chronology:

1. Fix C, O*, the funding transaction F, and its outpoint `u_C`. No modification
   of the funded script is required for this attack.
2. Select an ordinary spendable extra input U in place of V, or remove the
   second input if value and fees permit. Select a different output vector
   `O_bad` within the available value.
3. Recompute the ordinary legacy digest and recover A for each permitted
   metadata candidate until `DER(SHA256(A))` holds.
4. Search the long nonce domain for the second DER hit, exactly as in the
   honest native-side algorithm. Supply its selectors and A to C, and a normal
   authorization for U. No execution of V occurs.

Thus this hybrid has the same native-side search algorithm for disallowed
outputs. This is conditional on C being the stated native fragment: adding a
new actually enforced link could defeat the replacement. It is not a claim
that every conceivable native script allows input replacement. Pricing the
native fragment's EC recoveries remains necessary on both sides.

Making V a later transaction instead of another input does not repair the
missing implication: after an already valid spend of C, validity of a later
transaction cannot retroactively impose an additional predicate on that spend.
Using a prescribed presigned flow can impose such dependencies only if the
retained setup information cannot produce a bypass. Merely retaining a good
presigned transaction proves existence of one path.

## 2. Can one index relation replace the B computation?

A plausible cheap addition is `d_B=f(d_A)`, using a public function f or a
small table, and then checking both native gates on one opaque root.

For fixed f and two independent predicates the paired success probability is
`p^2`, so a sequential trial costs `(1+p)/p^2` expected primitive predicate
queries. If f makes both checks the same effective word, success instead
costs `1/p`, but the native distinct-digest requirement rejects this duplicate.
Both distributions apply to allowed and disallowed output lists. Nothing in
f substitutes O* into the output field of the native sighash serialization.

More interesting would be a deliberately correlated native relation that
becomes identical only when the transaction satisfies the intended predicate.
[Search 2](search2_native_context.md) excludes exact-preimage-coincidence tricks
within its legacy context class. [Search 3](search3_native_algebra.md) supplies
actual digest-scalar equality, but both sides are still native digests of the
actual transaction. Neither provides the reference-context substitution.
A scalar digest equality is also not automatically byte equality: reduction
modulo n must remain explicit.

## 3. New audit: distinct words are only conditionally independent

Search 1 correctly collapses syntactic aliases such as `D=ss`, `T=sr`, and
repeated-symbol subsequences. Distinct remaining primitive words still do
not have **exactly** independent outputs in a finite random-function model.
For example, `s(A)` and `sss(A)` become correlated if an intermediate state
repeats. This is a concrete condition to handle rather than additional nonce
entropy.

The [deterministic fixture](search7_synthesis.py) enumerates all 1,024 choices
of a four-state random function and a uniformly random first output from an
external root. For the gate `output < 2`, each individual uniform sample has
probability 1/2. The pair of words `s` and `sss` passes both gates with
probability **5/16**, rather than the independent prediction 1/4. The first
and second states coincide with probability 1/4. This toy-sized discrepancy
is not an attack estimate for full-width SHA256, SHA1, or RIPEMD160.

There is a useful positive limited lemma. Model each primitive hash as an
independent random function of its input bytes, and start with distinct
canonical **33-byte compressed-key roots**. Evaluate the prefix DAG of the
selected primitive words, identifying equal prefixes. All internal states
are 20 or 32 bytes, so no internal state can equal a root. Until two distinct
internal nodes happen to have equal state bytes, different primitive-word
nodes cannot be the same primitive-hash query merely through routing. Their
new terminal SHA256 outputs can be coupled to fresh uniform samples, hence
their DER flags to independent Bernoulli-p samples. Shared prefixes reduce
work; they do not themselves invalidate this coupling.

For at most q fresh internal hash outputs, a conservative output-collision
union bound is

```
Pr[an internal state collision] <= q(q-1) / 2^161.
```

This uses the shortest 160-bit state and deliberately ignores that many pairs
have different lengths or stronger 256-bit collision bounds. At q=`2^64` it
is below `2^-33`; at q=`2^68` it is below `2^-25`. These are ideal-model upper
bounds, not concrete SHA1 security statements. They include accidental
cross-algorithm equality of same-length states. Semantic prefix identity is
not counted as an accidental collision.

The fixed-nonce setup needs an additional conditioning statement. After the
honest search selects A because `DER(SHA256(A))` passed, that first output is
already known and distributed conditional on DER; it must not be resampled
as an independent Bernoulli event. Future terminal queries for distinct words
remain fresh uniform samples in the closed model until they reuse an exposed
query input or meet an exposed internal state. The exposed transcript includes
**all rejected roots and native transaction-hash/recovery setup work**, not
just the selected root. A complete proof must extend the coupling to that
transcript. The small output-output bound alone does not perform this step,
and no unconditional end-to-end success or forgery bound is claimed here.

Important limits of this lemma:

- It conditions on genuinely distinct roots when roots are meant to differ.
  Duplicate transaction metadata with the same digest gives the same root,
  not another independent candidate.
- It concerns the closed prefix-DAG evaluation. Arbitrary auxiliary oracle
  queries, deliberately targeted states, and the shared SHA256 invocations
  in transaction serialization/recovery need a larger simulation. A new
  state hitting a previously queried arbitrary input must also be charged.
- Counting a terminal DER test while declaring the hash-prefix generation
  free is invalid. One internal SHA256 query may already reveal a useful
  terminal gate for another permitted word; all primitive queries count.
- The concrete SHA1/RIPEMD160 assumptions are stronger than simply assuming
  unrelated Bernoulli cells. This note supplies no cryptanalytic proof.
- The current native fragment permits a 65-byte uncompressed root as well.
  The same length-separation observation holds, but canonical root encoding
  must be enforced wherever a future bridge's semantics requires it.

This gives a reason the long-word construction can approximate the ideal
nonce model, and states what remains to prove. It does not transfer an
adaptive K2,2 lower bound to the full Bitcoin construction by itself.

## 4. Minimal next lemma

The sharp target is now **mandatory reference evaluation**:

> Give a fixed funded script C and an executable relation such that every
> accepting spend of C proves a native digest/key was compared against the
> digest/key of an actually verified transaction with output vector O*, using
> the same nonce word(s) and relevant funding context. The creator retains all
> setup state and may choose both spends before funding.

There are two concrete ways to satisfy this target: an entire verifier in
one applicable execution budget, or an enforced dependency on a specific
verifier execution plus authenticated common inputs. A public root, a second
input, a transcript, or a readable subset digest is not yet that dependency.
An unknown-log signing anchor is not enough unless the honest construction
also supplies its authorization without an uncounted search.

If the target is met, the next checks are the exact funding chronology,
malicious pre-funding alternate preparation, the concrete hash-path security
model, and the full honest cost including script/table generation and audit,
transaction hashing, native EC recovery, hint items, stack coexistence and
consensus limits. The present 199-opcode A fragment leaves only two counted
legacy operations; a complete design should expect to redesign or amortize
it, not assume a large arithmetic verifier fits in the remainder.

Reproduce the new fixture:

```
python3 research/covenant-2026-09-17/seven/search7_synthesis.py
```

Only `seven/search7*` files were changed. Existing source, knowledge pages,
metric baselines, and other agents' artifacts were preserved.
