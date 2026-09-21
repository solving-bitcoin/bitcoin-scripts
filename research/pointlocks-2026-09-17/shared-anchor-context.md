# Sharing the anchor's first signature context

Question: can the anchored candidate retain six distinct short-signature
contexts per label while reducing complete creation-plus-spending cost below
100,000 vB? Sharing the anchor's scriptCode with the first short check lowers
the best sampled six-context row to **103,345 vB**, still above the target.
The five-context row becomes **94,005 vB**. These are full serialization
estimates with placeholder signatures, not funded publication results or
general extraction proofs.

The later [round-major layout](round-major-contexts.md) shares each separator
across selected labels and changes key placement. Its six-context estimate
is 98,334 vB, including creation; the 103,345-vB result here remains scoped
to this earlier layout. Neither size scan is a complete extraction theorem.

[Generator](../../examples/pointlock_anchored_shared_context_size_probe.rs),
[implementation](../../examples/pointlock_anchored_typed_size_probe.rs),
[size report](anchored-shared-context-size.json),
[native harness](typed_selector_core_check.py),
[Core report](shared-context-selector-core-check.json),
[algebra tests](shared_context_algebra.py),
[algebra report](shared-context-algebra.json).

## Context count and extraction

The first short check needs no separator after the compulsory anchor check.
Each later short check still has one: d short checks use d-1 separators per
label while retaining d distinct scriptCode suffixes for that label. This
saves one byte and one charged opcode per selected label in both layouts.
A focused test inspects the policy-compiled bytecode for d=1 through 8,
both layouts, and three labels. It checks the saving, anchor/first suffix
equality and pairwise distinct short suffixes.

The anchor's flag is ALL (raw byte 1). Equal scriptCode implies equal digests
when the full sighash context matches, including that raw flag. Other
consensus-permitted flags remain available. This changes signing contexts;
it neither forces every first-check digest to equal the anchor digest nor
automatically inherits previous heuristic search-work estimates.

The [affine-nonce extractor](nonce-relation-extraction.md) now includes the
anchor row itself. For a verified relation R=a R_anchor+bG, it recovers

```
p = (z - a*s*z_anchor - b*s) / (a*s*r_T - r) mod n,
```

when the denominator is nonzero and checks pG against the dynamic key. The
target scalar is the sign of `r_T*p+z_anchor` that matches T. Twelve added
fixtures cover both anchor signs and all six signed GLV multipliers, with
otherwise unrelated short nonces. The short-only search returns unresolved
on those fixtures; the anchor-aware search extracts.

For the shared ALL context there is a stronger scoped statement. Assume
z=z_anchor is nonzero modulo n and R=a R_anchor for a signed GLV multiplier.
If the denominator vanished, the numerator would also vanish: a*s=1 and
r=r_T. A nontrivial endomorphism cannot do this. The unsigned 32-byte r_T
exceeds p_field-n, so r_T+n cannot be a recovery x; multiplying its nonzero
x by beta or beta^2 cannot preserve it. For a=+/-1, degeneracy instead
requires s=+/-1. Those signature items are 40 or 72 bytes with this r_T,
not the required 60. Thus a matching signed GLV relation under these
assumptions always gives an invertible extraction equation.

Eight synthetic equal-digest fixtures reproduce the nontrivial cases with
both anchor signs; a separate test checks the excluded 40/72-byte encodings.
Digests are assigned algebraically, not realized as Bitcoin hash preimages.
The theorem does not cover zero reduced digests, arbitrary nonce families,
or different first-check flags. No general hardness lower bound follows.

## Complete cost accounting

The bounded scan covers n=3..180, t=1..10, d=5..8 and both layouts, retaining
3,718 feasible rows. A row repeats one pool profile until its binomial
capacity covers all 2^2048 messages. Costs include the initial P2TR input,
first P2TR helper output, every P2WSH output, their complete consumption,
the final P2TR output, framing, and a 72-byte authorization reservation for
every pool. Script sizes use the centralized compilation policy and are
optimized. Repeated placeholder tables do not instantiate the independent
labels required in a real full-size publication.

| Contexts | Layout | Pool | Pools | Script B | Witness B | Charged ops | Create vB | Spend vB | Total vB |
|---:|---|---|---:|---:|---:|---:|---:|---:|---:|
| 5 | inline | 4-of-50 | 115 | 1,365 | 2,970 | 176 | 5,056 | 90,214 | 95,270 |
| 5 | phased | 4-of-50 | 115 | 1,321 | 2,926 | 180 | 5,056 | 88,949 | **94,005** |
| 6 | inline | 4-of-50 | 115 | 1,405 | 3,254 | 200 | 5,056 | 98,379 | 103,435 |
| 6 | phased | 4-of-44 | 121 | 1,224 | 3,073 | 201 | 5,314 | 98,031 | **103,345** |

Five contexts save 115 vB. At six contexts the freed opcode budget also
permits larger tables and fewer inputs: the best sampled total drops 1,694
vB from the prior typed-selector minimum of 105,039 vB. Spending alone fits
100,000 vB; including creation prevents six contexts from meeting the goal.
This is not a lower bound or global optimum, and does not optimize mixtures
of pool profiles.

All four rows require four index hints per input, present at entry together
with all other data. Five-context inputs have 33 entry items and 34 complete
witness items: 460 hints and 3,795 entry items across 115 inputs. Six-context
inputs have 37 entry items and 38 complete witness items: inline totals are
460 hints and 4,255 entry items; phased totals are 484 and 4,477. Combined
main-plus-alt-stack upper bounds are respectively 89, 89, 93 and 87 per input.
Counts across inputs never coexist on one stack. Size evidence:
**locally-reproduced**; deployment: **unclassified**. No full-size native
publication or complete setup benchmark is claimed.

## Native execution

The harness exercises n=4,t=2,d=6 in both layouts. All 12 ordered selections
per layout pass Core 30.3 policy and are mined on isolated,
network/wallet-disabled regtest: **24 positive cases**. All **14 malformed
cases** fail policy and block validation, including zero/negative-zero and
out-of-table hints with their hash equations deliberately satisfied, other
invalid indices, and extra witness data. Order adds no message capacity.

Core commit: `49faec4f87f5cd19c88db01a82e5c68b087c8227`. Compiler commit:
`124b561ed75ac3ec4c6ad99207d8dcdd3bc67180`. The report pins source and binary
hashes. The independent BIP143/curve trace verifies all 15 signature checks
per positive execution, recovers both target scalars, and checks the suffix
relationships used by the native signing path.

| Layout | Script B | Charged ops | Witness B | Hints | Entry items | Complete witness items | Combined stack peak |
|---|---:|---:|---:|---:|---:|---:|---:|
| inline | 251 | 90 | 1,200 | 2 | 19 | 20 | 23 |
| phased | 238 | 91 | 1,187 | 2 | 19 | 20 | 23 |

Both hints coexist at entry. The 24 independent positive executions contain
48 hint occurrences and 456 entry-item occurrences. Peak 23 is an independent
value/height trace, not an instrumented Core counter. Fixture authorizations
use public deterministic keys and 60-byte signatures; full-size estimates
reserve 72 bytes. Native test funding contains test-only outputs and is not
the complete publication cost measurement. The tapscript/stack-unlimited
helper is not used.

Native evidence: **differentially-validated**. Positive fixture deployment:
**policy-validated**. Algebra: **inspected**, with **locally-reproduced**
examples and **unclassified** deployment. Public garbling/translation binding,
all-consensus extraction, mandatory-input binding, and full setup within the
requested time budget remain unresolved. Earlier reports are historical and
are not overwritten by this follow-up.

```sh
cargo test --locked --example pointlock_anchored_typed_size_probe
cargo run --release --locked --example pointlock_anchored_shared_context_size_probe
PYTHONDONTWRITEBYTECODE=1 python3 research/pointlocks-2026-09-17/typed_selector_core_check.py --shared-anchor-context
PYTHONDONTWRITEBYTECODE=1 python3 research/pointlocks-2026-09-17/shared_context_algebra.py -v
```
