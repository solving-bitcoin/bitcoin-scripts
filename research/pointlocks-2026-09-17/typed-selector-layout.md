# Typed selection reduces anchored publication overhead

Question: can the anchored candidate retain its mandatory authorizations and
fit six short-signature contexts below 100,000 combined creation/spending vB?
This change reduces the best sampled six-context layout from 111,372 to
**105,039 vB**, still above the goal. Five contexts have a new **94,120-vB
serialization estimate**, compared with 96,190 vB on the same maximum-length
authorization boundary. These new full-size rows use placeholder signatures;
they are not newly funded publications or extraction proofs.

[Generator](../../examples/pointlock_anchored_typed_size_probe.rs),
[size report](anchored-typed-size.json),
[native selector harness](typed_selector_core_check.py),
[Core report](typed-selector-core-check.json).

The subsequent [shared-anchor-context variant](shared-anchor-context.md)
removes one separator per selected label and lowers the five/six-context
estimates to 94,005/103,345 vB. Its separate Core report exercises six short
checks per label. The measurements below retain the preceding layout.

## Selection by incompatible element types

Let `m=n-j` HASH160 table elements remain at selection slot `j`. The existing
layout pulls a tau and an index above them, destructively selects a table
element, checks its hash, then obtains the dynamic ECDSA key:

```text
<m> ROLL <m+1> ROLL
ROLL OVER HASH160 EQUALVERIFY
<m> ROLL TUCK CHECKSIGVERIFY
```

The explicit index-range predicate is omitted. Public setup must additionally
check that **every table commitment begins with a byte other than `0x30`**.
This sufficient condition makes every nonempty 20-byte table element an
invalid DER signature. It is a public byte check, with no knowledge proof.
The normal target/tau consistency and collision-binding obligations remain.

For the first invalid index, previous successful selections have left the
expected table shape. All numeric encodings that consensus accepts fall into
the following cases; nonminimal encodings do not change the argument.

* A negative index or one outside the entire stack makes `ROLL` fail. A
  greater-than-four-byte ScriptNum also fails.
* An index from `1` through `m` removes exactly one authenticated table item.
* An index greater than `m` removes witness data instead. The subsequent
  fixed-depth key lookup obtains a 20-byte table element. It cannot be an
  ECDSA public key, including the consensus-valid 65-byte encodings.
* Index zero makes the hash comparison use `tau = HASH160(H_last)`. This
  equation can be satisfied without finding a preimage. The subsequent anchor
  nevertheless uses `H_last` as its signature, which the public DER exclusion
  makes invalid. Rejecting this case is essential; rarity of DER-shaped hashes
  would not be a substitute for setup validation.

This establishes the selector's accepted index range for this exact stack
layout. It is not a general justification for deleting bounds from `ROLL`
lookup tables. Reference semantics are pinned to
[Bitcoin Core 30.3](https://github.com/bitcoin/bitcoin/blob/49faec4f87f5cd19c88db01a82e5c68b087c8227/src/script/interpreter.cpp).

## Separate selection from signature checks

The phased variant authenticates all selected taus first, storing each one on
the altstack. It then drops the unselected table and verifies the saved taus
in reverse selection order. Each signature/key frame is now directly on top
of the main stack, eliminating the repeated depth constants used to fetch
short signatures through the table. Moving the taus costs additional opcodes
but reduces serialized script bytes.

The type argument also holds here. Zero saves an invalid 20-byte signature
on the altstack. An oversized index leaves an extra table element: if this is
the final selection, that element becomes the first verification key;
otherwise the next tau lookup obtains a table element. If that next selection
passes its hash comparison, its saved tau is still a 20-byte table element,
including the zero-index case. A later compulsory anchor rejects it. No
successful verification path can silently absorb the displaced table item.

The final short check consumes its key instead of retaining and dropping it
across CODESEPARATOR. A focused test compiles both forms using the centralized
policy and confirms the upstream optimizer does not already perform this
rewrite: it saves one byte and one charged opcode per selected label. Native
checks below cover the consumed-key implementation. All signing contexts are
derived after compilation.

## Complete serialization boundary

The bounded scan covers `n=3..180`, `t=1..10`, and `d=5..8` for both layouts,
retaining 3,630 feasible rows. Each row repeats one pool profile until its
binomial product covers all 2,048-bit values. It includes the initial P2TR
input, first P2TR helper output, every P2WSH output, consumption of every
created output, final P2TR output, framing, and a mandatory authorization on
every pool input. Authorizations reserve 72 bytes. Scripts use the centralized
optimization policy; these sizes are optimized, not unoptimized.
That capacity calculation requires independent labels across pools. Repeated
placeholder tables in this sizing fixture do not instantiate those independent
labels and must not be used as a publication scheme.

| Contexts | Layout | Pool | Pools | Script B | Witness B | Charged ops | Create vB | Spend vB | Total vB |
|---:|---|---|---:|---:|---:|---:|---:|---:|---:|
| 5 | inline | 4-of-50 | 115 | 1,369 | 2,974 | 180 | 5,056 | 90,329 | 95,385 |
| 5 | phased | 4-of-50 | 115 | 1,325 | 2,930 | 184 | 5,056 | 89,064 | **94,120** |
| 6 | inline | 4-of-44 | 121 | 1,280 | 3,129 | 201 | 5,314 | 99,725 | **105,039** |
| 6 | phased | 4-of-36 | 130 | 1,056 | 2,905 | 201 | 5,701 | 99,854 | 105,555 |

All four sized spending transactions fit the 400,000-weight ceiling; this
alone is not policy validation. In particular, the six-context inline spend
is below 100,000 vB while its **creation plus spending** exceeds the goal.

Every row has four index hints per input, all present at script entry. The
five-context rows have 33 entry items and 34 complete witness items; across
115 inputs there are 460 hints and 3,795 entry items. The six-context rows have
37 entry and 38 complete witness items: inline totals are 484 hints and 4,477
entry items, phased totals 520 and 4,810. Combined main-plus-alt stack upper
bounds per input are respectively 89, 89, 87, and 79. Counts summed across
inputs never coexist on one stack; each per-input bound is below 1,000.

Size evidence: **locally-reproduced**. Deployment: **unclassified**. There is
no full-size native run, mixed-profile optimum, new setup benchmark, full
garbling integration, or general extraction theorem in this report.

## Native selection validation

Two small `n=4,t=2,d=1` fixtures test the exact policy-compiled layouts on
isolated, network/wallet-disabled Core 30.3, commit
`49faec4f87f5cd19c88db01a82e5c68b087c8227`.

All 12 ordered selections per layout pass policy and are mined under
consensus: **24 positive cases**. Ordering is not credited as extra message
capacity; there are only six selected sets per layout. The independent
BIP143/curve trace recovers both selected scalar occurrences in every case.
All **14 negative cases** are rejected by policy and block validation:
zero and negative-zero indices with the hash equation deliberately satisfied,
out-of-table witness hashes deliberately satisfying the lookup, negative and
beyond-stack indices, five-byte indices, and extra witness entries. The two
type-confusion cases reach the intended DER/key rejection in the independent
trace; they do not merely fail an unrelated hash comparison.

| Layout | Script B | Charged ops | Witness B | Hints | Entry items | Complete witness items | Combined stack peak |
|---|---:|---:|---:|---:|---:|---:|---:|
| inline | 163 | 32 | 502 | 2 | 9 | 10 | 13 |
| phased | 160 | 33 | 499 | 2 | 9 | 10 | 13 |

The peak is an independent exact value/height trace of the Core-tested
bytecode, including all entry data, constant pushes and altstack transfers;
it is not an instrumented Core peak. All two hints coexist at entry. The 24
positive executions use 48 hint occurrences and 216 entry-item occurrences
across independent input executions. Test authorizations use public fixture
secrets and are 60 bytes; the full-size scan above conservatively reserves
72-byte ordinary authorizations. These helpers are not production key handling.
The native funding also contains test-only helper/change outputs and is not a
measurement of complete BitVM3 publication overhead.

Evidence: **differentially-validated**. Positive fixture deployment:
**policy-validated**. The local tapscript/stack-unlimited execution helper is
not used. The general unknown-nonce extraction and malicious offchain-table
binding problems of the anchored candidate remain open.

```sh
cargo test --locked --example pointlock_anchored_typed_size_probe final_key_consumption_is_not_already_optimized
cargo run --release --locked --example pointlock_anchored_typed_size_probe
PYTHONDONTWRITEBYTECODE=1 python3 research/pointlocks-2026-09-17/typed_selector_core_check.py
```
