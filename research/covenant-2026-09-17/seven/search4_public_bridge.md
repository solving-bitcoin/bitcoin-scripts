# Search 4: public tables, garbling, and readable digest relations

Date: 2026-09-17. **No complete secretless exact-output covenant found.**
This search isolates three concrete failures and an outstanding verifier
obligation. It does not prove that such a covenant is impossible.

Question: can a public, independently checkable table or proof connect the
readable Binohash/QSB digest to the computation of a transaction with fixed
outputs, without relying on labels or keys unknown to the creator?
Comparison objective: total honest work, including generation and checking of
all tables and all discarded funding instances, below `2^64`; a creator who
keeps the full setup state and prepares alternatives before funding must still
face greater work to change the outputs.

Sources are `reported`; the reductions and candidate audits below are
`inspected`. The executable counterexample and exhaustive small enumeration
are `locally-reproduced`. All new results are `unclassified`: there is no Core
execution, complete transaction, mined rare event, or covenant security test.

## 1. State the missing relation explicitly

Let `S` be the fixed locking script, `f` its funding outpoint, and `O*` the
agreed output vector. For a transaction `T` and canonical selected subset `D`,
write the QSB-style native test as

```
z(T,D) = LegacySighashALL(T, f, FindAndDelete(S, dummy(D)))
P(T,D) = Recover(sigma0, z(T,D), recovery_branch)
R(T,D) = DER32(SHA256(encode(P(T,D))))
```

The branch and encoding choices belong to the creator and must be included in
search costs. The simplified parser gate accepts syntactic DER; it does not
need the result to be a valid signature under some recovered key. Its
probability, taken from the earlier exact counting result, is
`p = 780555 / 2^65 = 2^-45.4258592336` for a uniform 32-byte string.

A genuine public proof bridge would need to enforce something like

```
NativeDigest(T_actual, D)
and VerifyProof(S, f, O*, D, proof)

where the proof establishes:
  exists T_good:
    outputs(T_good) = O*
    and NativeDigest(T_good, D).
```

All constants defining the native digest, its contexts, canonical indices,
recovery branches and accepted flag choices must match on both sides.
An executable proof verifier for this relation would be useful. Merely
calling a witness a proof or committing to a table is not that verifier.

The primary papers describe selected subsets as readable digests and use
HORS to authorize their release. This note changes their application to the
creator-retains-state model; it is not a claim that the papers promise this
self-binding property. See [Binohash](https://robinlinus.com/binohash.pdf) and
[QSB, sections on digest rounds and HORS](https://raw.githubusercontent.com/avihu28/Quantum-Safe-Bitcoin-Transactions/main/paper/QSB.tex).

## 2. Correct public garbling still permits the creator's output-label attack

Consider the smallest possible circuit: `y = x`. Let the garbler choose the
four wire labels `X0, X1, Y0, Y1`. A correct two-row garbling is

```
C0 = H("identity-gate/" || X0) XOR Y0
C1 = H("identity-gate/" || X1) XOR Y1.
```

Concatenation and XOR here are offchain setup operations. They are not
assumed Script opcodes. Anyone with the labels can verify both rows exactly.
A zero-knowledge proof of correct generation could also establish the same
table correctness without revealing the labels. Either way the creator has
retained all four labels.

Suppose a native digest check has already established input bit `x=0`, and
the remainder of the script authenticates the corresponding input label and
the accepting output label:

```
# stack bottom-to-top: Y1 X0
OP_SHA256 <H(X0)> OP_EQUALVERIFY
OP_SHA256 <H(Y1)> OP_EQUAL
```

Both hashlocks succeed, although the publicly verified table evaluates `X0`
to `Y0`, not `Y1`. The creator supplies the known `Y1` directly. Exhaustively
verifying the table before funding does not alter this attack. Keeping labels
secret from outsiders does not help against the creator; publishing the
setup seed simply makes the same attack available to everyone.

[The deterministic experiment](search4_public_bridge.py) generates labels
from the documented seed, verifies both rows, and reproduces the accepting
false claim. [Its JSON](search4_public_bridge.json) contains every label,
table entry, and the raw explanatory predicate. The four-opcode, 70-byte
predicate is a hand-serialized diagnostic vector, not a policy-compiled
repository primitive or a consensus claim. Boundary: `complete-leaf:` two
label inputs, constants and final predicate; native digest extraction and all
transaction context are excluded. It has two data items, **zero auxiliary
hint items**, and a combined stack peak of three by inspection. No complete
witness serialization or transaction weight is measured.

This is a counterexample to accepting-label authentication alone, not to
garbled circuits with an actual computation-verification protocol. Checking
every gate and its connections onchain would remove this particular attack,
but the claimed compression would then require a separate size proof.

The distinction is visible in [BitVMX's June 24, 2026 implementation
description](https://bitvmx.org/knowledge/implementing-garbled-circuits-for-bitvmx):
setup proves correct garbling and commitment linkage; the application also
uses hidden labels, a challenge/equivocation transaction protocol, and
signatures exchanged by both parties. The garbler's knowledge of the invalid
label is not what its protocol is trying to rule out. Taking only its output
hashlock and setup proofs does not produce a terminal self-binding covenant.
Likewise, [publicly verifiable garbling](https://pse.dev/projects/publicly-verifiable-garbled-circuit)
is not synonymous with publicly enforcing evaluation using only hashlocks.

## 3. Public arithmetic relations between indices do not create output asymmetry

Here is a delimited random-oracle result. Fix a script and funding instance,
and suppose the only extra requirement beyond native rare gates is a public
predicate on the selected indices:

```
R_1(T,D1) = ... = R_r(T,Dr) = 1
F(D1,...,Dr) = 1.
```

Assume distinct native contexts give independent Bernoulli-`p` values, and
`F` has not encoded oracle answers for the finalized funding instance.
Replacing an allowed output vector by a disallowed one only relabels the
oracle rows. The distributions of the entire available search transcript are
the same. This includes adaptive search, permutation tables, small sums,
checksums, and functional relations such as `D2=f(D1)`. The retained creator
can run the same search algorithm for a disallowed output vector. Adding
output-independent pinning puzzles changes both costs in the same way.

This is a conditional statement about this predicate class, not an
impossibility theorem for native signature relations. In particular, a
working intended-transaction verifier from section 1 would violate the
premise and is not excluded by the argument.

For the concrete relation `D2=f(D1)` where `f` is a permutation and the two
contexts are independent, a paired candidate succeeds with probability
`p^2`. Checking the second gate only after the first succeeds gives expected
query count

```
E[queries] = (1+p)/p^2 ~ 2^90.8517184672,
```

in the unlimited independent-candidate model. This cost applies to both
output lists. With a finite index pool, its exhaustion and transaction
resampling need additional accounting; they cannot be omitted as free
attempts. If both checks are the exact same context and `f` is identity,
they instead repeat a single gate and cost approximately `1/p` for both
output lists. The extremes are excessive work or a duplicated predicate,
not a correlation reserved for the intended outputs.

The experiment exhaustively enumerates two independent four-entry Boolean
gate arrays and all 24 permutations. For `p=1/2` every permutation has exactly
`175/256 = 1-(3/4)^4` probability of an available pair. This small enumeration
checks the stated model, not the behavior of real SHA256 or QSB mining.

The most promising escape remains an executable relation that becomes
correlated precisely because an arithmetically established `T_good` equals
the actual transaction. A rule on free indices alone supplies no such fact.

## 4. Where a public lookup table must be committed

Let `L_f` be an exact table of digests or raw recovered keys known to arise
from allowed-output spends of funding outpoint `f`. Three proposed setup
orders have materially different meanings:

1. **Generate the table before choosing the final funding instance.** A
   generic table is easy to audit but does not contain the claimed
   transaction-specific relation. If it is merely a static list of `M`
   curve points, membership of a fresh roughly uniform recovered key costs
   approximately `n/M` trials, up to the small recovery-branch factor. With
   total table generation and candidate queries below `2^64`, a generic
   meet between two independent point lists has probability only of order
   `2^128/n`, not constant success. Passing through a 160-bit native hash
   returns to the already excluded generic `2^80` cross-collision scale.
2. **Choose funding, generate its exact good table, then embed the table or
   root in the locking script.** The new script changes the funding txid and
   hence `f`; the table must now describe another instance. The condition is
   `L = GoodTable(Funding(S(L)), O*)`, not an independent-list collision.
3. **Choose funding, then provide the table/root in the spending witness.**
   This avoids changing funding, but the script needs an actual verifier of
   `L = GoodTable(f,O*)`. Authenticating openings against an arbitrary root
   is not verification of that relation. Offchain checking a particular
   allowed spend does not cause consensus to require the same root later.

These cases do not prohibit a nonuniform or specially structured table. They
identify exactly what such a table must improve. A publicly verifiable
generator whose seed is fixed does help remove malicious table entries, but
it does not give transaction-specific semantics to an otherwise generic
table, nor does it bind a post-funding table without an executable check.

## 5. Transparent proofs and sampled computations

A transparent proof could in principle prove the section 1 relation without
any erased secret. The missing artifact is a verifier for that statement
under the actual execution context and resource budget, not a general
objection to transparent proofs.

For a sampled-trace suggestion, write the required dependency as

```
c = Commit(trace)
q = Challenge(c, native_transaction_digest)
VerifyOpenings(c, q, answers).
```

If `c` is a freely supplied witness item and the readable native digest does
not depend on it, the prover can choose or adapt the trace after seeing the
queries. Local correctness on queried gates does not then establish the
global computation. If an additional signature is proposed to bind `c`, its
sighash must actually include those bytes; unrelated scriptSig/witness items
are not automatically included. A standard Merkle opening also needs the
specified parent hash of concatenated children, not just hashes of
independent stack elements. No native CAT or unchecked root-to-challenge
conversion is supplied here.

Fixing a universal verifier or public parameters before funding is entirely
compatible with the objective. It still leaves the concrete proof
verification, input binding, and Fiat-Shamir/interactive challenge
instantiation to be implemented. Moving the verifier into another Taproot
input additionally requires enforcement of that input and shared data; the
previous pass's replacement attacks still apply.

## 6. Polyglot dummy tables and failed CHECKMULTISIG

Publicly generating dummy signatures with an arithmetic label, special
length, or hash preimage can make a table checkable. The label-to-dummy map
can then be used by `OP_PICK`/`OP_ROLL`. That proves which fixed entry was
selected; it does not evaluate the actual transaction on the arithmetic
side. All-table generation is charged to both algorithms. Producing public
tokens for only the winning indices after searching still gives the creator
the same ability for another output list.

There is an important Core detail: Legacy `CHECKMULTISIG` performs
FindAndDelete for the entire supplied signature list before the verification
loop. Thus a failed check may delete strings that are not DER signatures,
including long strings. It is incorrect to claim that every deleted string
must have passed signature verification.

However, consider using a false result to allow such a long tail while
claiming that an earlier fixed ALL signature was successful. False also
results when that earlier signature fails. Placing an invalid-DER sentinel
later in the list reverses the useful implication: reaching the sentinel
aborts, whereas failing early may return false without reaching it. Neither
outcome certifies successful verification of the desired prefix. A separate
successful `CHECKSIG` has its own FindAndDelete context and does not inherit
the arbitrary deleted list. A successful full `CHECKMULTISIG` does require
all its signature slots to be satisfied and checked under the applicable
encoding rules.

This is inspection of [Bitcoin Core 30.3, commit
`49faec4f87f5cd19c88db01a82e5c68b087c8227`](https://github.com/bitcoin/bitcoin/blob/49faec4f87f5cd19c88db01a82e5c68b087c8227/src/script/interpreter.cpp),
not a new Core test. An alternative way to certify the successful prefix
would be a substantive new primitive; none was found.

## 7. Consequence for the compact two-hit route

Search 1 reports a new native `A`-side pair using a fixed first nonce and a
long three-opcode, two-state routing schedule: 199 opcodes, 273 bytes, roughly
57 bits of semantic nonce capacity, and approximately `2^46.4` ideal
predicate queries for honest construction. This agent did not independently
validate those metrics. The old pair-only 201-opcode barrier therefore must
not be used against this route. This search asks whether public tables
supply its still-missing `B` side; it does not infer independent-oracle
security from the routing schedule.

They do not yet do so: an unauthenticated `B` can be set to `A`; a fixed raw
`B` chosen after finding an intended spend changes the funding commitment;
a generic precommitted `B` table has the lookup cost above; and garbled
acceptance labels can be supplied directly by the creator. A complete
transparent proof verifier could still be a bridge, but no implementation
within the remaining Legacy budget was found.

Falsifiable acceptance criterion for continuing this route: supply a fixed
script and a complete witness that enforce the section 1 proof relation or
an equivalent relation, with every raw/arithmetical value bound, every
creator choice explicit, and no presumed shared state across inputs. Then
count table generation, table auditing, all funding attempts, native hash and
curve work, explicit hint items, complete stack peak, serialized size, and
consensus checks. Neither the accepting-label example nor an index equation
alone meets that criterion.

## Reproduction and source versions

```
python3 research/covenant-2026-09-17/seven/search4_public_bridge.py
```

The run is deterministic, uses only Python's standard library, and does not
start a node or access a wallet/network. Source-file SHA256 fingerprints of
the locally read QSB TeX, Binohash PDF, and ColliderScript PDF are recorded in
the JSON so these source versions remain identifiable even where URLs are
mutable. ColliderScript is the 2024/1802 version dated 2024-11-15 cited in the
handoff; its [Big/Small discussion and tapleaf-table
limitation](https://eprint.iacr.org/2024/1802) informed the table audit.
The short public-garbling literature review was checked on 2026-09-17.

Only `search4*` files were changed. No library primitive, metric baseline,
field-arithmetic test, or shared knowledge page was changed by this agent.
