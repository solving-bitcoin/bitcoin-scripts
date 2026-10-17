# Exact u4 sorting with destructive selection

## Research framing

- **Question:** can bounded destructive stack selection certify an exact u4
  sort using linear locking-script bytes and fewer combined bytes than a
  zero-hint selection network built from the existing two-item sorter?
- **Hypothesis:** `n-1` deletion-index hints replace the repeated min/max scans;
  script savings repay hint bytes for sufficiently large `n`, with a higher
  entry item count and stack peak.
- **Comparison objective:** minimize script plus serialized data-witness bytes
  at an identical canonical-nibble-input, sorted-nibble-output boundary. Also
  report each component, hints, executed operations and combined stack peak.
- **Threat model:** hostile operands, hostile hints, numeric aliases, missing
  or extra inputs, wrong selection order, duplicates, and selectors aimed at
  other hints or preserved state. Original operand authentication belongs to
  the caller. There is no cryptographic-security assertion.
- **Constraints:** generation-time `1 <= n <= 499`, four-byte arithmetic,
  1,000 combined main/alt-stack items, repository compilation policy, no new
  opcodes, and all hints present at entry. No hint scheduling assumption hides
  an initially oversized witness.
- **Evidence:** `locally-reproduced`; execution `unclassified`. This is a local
  stack-enforced tapscript experiment, without Core consensus or relay tests.

## Construction and soundness boundary

Entry is `preserved | h[n-2] ... h[0] | x[0] ... x[n-1]`, bottom to top.
At each step with `r` operands remaining, a fixed-depth roll retrieves the
next hint; the script checks its canonical encoding and `0 <= hint < r`,
then dynamically rolls that operand out of the pool. Every selected operand
is checked as a canonical nibble. Selected values must be nonincreasing and
are stored on the altstack. The last operand needs no hint. Popping the `n`
outputs gives ascending main-stack order and restores previous altstack state.

The pool bound confines selection to remaining original operands. Destructive
removal makes these selections a permutation without a separate uniqueness
bitmap or permutation-product hash. Monotonicity therefore proves an exact
sort with duplicate multiplicity intact. A test removes the first pool bound:
an out-of-pool selector then replaces preserved state with an operand while
all nibble and ordering checks pass. The public fragment rejects it.

`OP_ROLL` semantics are from [Bitcoin Core v30.3's pinned interpreter](https://github.com/bitcoin/bitcoin/blob/49faec4f87f5cd19c88db01a82e5c68b087c8227/src/script/interpreter.cpp).
This construction is a repository-local experiment; no worldwide novelty or
best-known claim follows from the catalog search. The constant-composition
Winternitz verifier already uses destructive selection for hash-chain slots;
this experiment applies that mechanism to exact sorting of arbitrary operands.

The [bounded permutation decoder](factoradic-permutation.md) now also uses
bounded deletion indices, but starts from a trusted compile-time alphabet and
returns a witness-selected permutation. It does not sort hostile runtime
operands or enforce their order. This sorter's extra obligations are canonical
runtime-operand validation, monotonicity and multiset preservation. Packing its
selection choices into a factoradic rank is a plausible lower-entry-item
consumer of that existing decoder, not a feature measured here.

## Measurements

Boundary: `fragment-only:` includes canonical validation of all operands/hints,
pool bounds, ordering, selection, and restoration; excludes input pushes,
terminal predicates and transaction context. Data-witness bytes include the
complete operand-plus-hint vector serialization, not a complete Taproot
witness. Both sides use the same deterministic operands `(7*i+3)%16` and
output order. The zero-hint baseline repeatedly extracts a maximum using
`logic::u4_sort()` and retains its remaining minima. It includes the same
canonical input checks. No resident table setup or cleanup is omitted.

| n | Hinted script / data witness | Hints / total entry items | Hinted peak / executed non-push ops | Zero-hint script / witness | Zero-hint peak / executed non-push ops |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 10 / 3 | 0 / 1 | 4 / 7 | 12 / 3 | 5 / 9 |
| 2 | 37 / 6 | 1 / 3 | 6 / 28 | 30 / 5 | 6 / 24 |
| 4 | 97 / 14 | 3 / 7 | 10 / 74 | 88 / 9 | 8 / 73 |
| 8 | 217 / 30 | 7 / 15 | 18 / 166 | 266 / 17 | 12 / 231 |
| 16 | 457 / 60 | 15 / 31 | 34 / 350 | 862 / 32 | 20 / 787 |
| 32 | 969 / 122 | 31 / 63 | 66 / 718 | 3,044 / 63 | 36 / 2,859 |

All are final policy-produced, optimized serializations below 32 KiB. Pins
reported from the binary's embedded lockfile are interpreter
`a09e87af444034698697f0a2267e755cf72f9aed` and compiler
`124b561ed75ac3ec4c6ad99207d8dcdd3bc67180`. The strict raw probe enables the
stack limit and default minimal-data/minimal-if checks. Separate tests disable
minimal-data to demonstrate script-enforced canonical encodings. All scripts
are straight-line: the test checks that the interpreter reached exactly every
compiled instruction, then removes pushes from that count. Thus these are
executed non-push counts, not counts of potentially skipped instructions.
Signature validation budget is not measured; there are no signature opcodes.

The width-32 fragment's SHA256 is
`5b0b6821a9753690979e4af66dc35e46c911044ed0c5d64de99ed4dd3f7befea`.
The 32-input data witness includes 31 hints contributing 59 encoded bytes
with length prefixes, or 60 bytes as a standalone hint vector. The complete
data vector is 122 representative / 127 maximum bytes. For width 8 these
figures are 7 hints, 13 incremental bytes / 14 standalone hint-vector bytes,
and 30 representative / 31 maximum full-data bytes. Hints are public and
nonunique for equal values.

At width 32 the combined cost falls from 3,107 to 1,091 bytes; the entry item
count rises from 32 to 63. At widths 2 and 4 the hinted form is dominated in
combined bytes. Width 1 is simply canonical validation; the baseline's two
extra bytes are its generic in-place input-copy lifecycle, not a sorting gain.
No comparison against an optimized Batcher or bitonic network is measured.
Linear script and instruction growth does not imply linear interpreter CPU
time: `OP_ROLL` moves a selected item through a vector-backed stack, and those
underlying moves may total quadratic work. No wall-time advantage is claimed.

The existing [nondecreasing predicate](u4-nondecreasing.md) answers whether an
input vector is already sorted; it neither sorts nor proves that an unrelated
sorted witness retains the original multiset. It is not a substitute with the
same semantics. Hashing sorted outputs would also deliberately erase original
order and must not silently replace an order-sensitive message binding.

## Composition and reproduction

Standalone combined peak is `4` at `n=1`, otherwise `2*n+2`; add all unrelated
main/alt-stack state. The 499-input case has 499 operands and 498 hints, with
997 entry items and a 1,000-item peak. There is no room for other live state
at that width. One extra preserved item rejects. Tests also place smaller
vectors beside exactly enough preserved state to reach the same boundary.

Two preloaded width-32 batches contain **62 hint items plus 64 operands**;
all 126 items coexist at entry. Consuming the first 32 outputs before sorting
the second peaks at 129 combined items.
The policy-compiled two-batch fragment uses 1,954 script bytes and 1,452
executed non-push opcodes. It consumes a 243-byte representative / 253-byte
maximum serialized data witness. The boundary includes the first output's
32-item cleanup: `969 + 32 + 969 - 16 = 1,954`, with 16 bytes attributed to
cross-component whole-script optimization. The second output remains live;
terminal predicates and transaction context are excluded.

Retaining outputs changes subsequent
pool depths and requires explicit routing; the sequential batch test does
not claim that scheduling cost for free.

```sh
cargo test --locked arithmetic::u4::sort --lib -- --nocapture
cargo test --locked --test primitive_metrics u4_sort_metrics_are_current
python3 tools/kb.py validate
cargo test --locked -- --skip fields::
```

Tests exhaust all 4,096 nibble triples, use larger deterministic ChaCha20
vectors with seed `0x534f525420261017`, and compare against host sorting.
They cover raw aliases, negative zero, overflow, oversized items, missing and
extra data, out-of-pool hints at each stage, wrong multiplicity, alternate tie
orders, the pool-bound mutant, and surrounding main/alt-stack preservation.

See the [implementation README](../../src/arithmetic/u4/README.md#exact-sorting-with-destructive-selection-hints),
[comparison](../comparisons/arithmetic.md),
[negative result](../negative-results/index.md#nr-087-hinted-u4-sorting-loses-at-small-widths),
and [OP-043](../open-problems.md#op-043-exact-sorting-certificate-frontier).
