# Ternary mixed-hash integer path

Authenticates fixed-width base-3 digits with three fixed-length SHA-256/
RIPEMD-160 codewords and reconstructs a 1–31-bit non-negative Script integer.

## Question and hypothesis

Can a canonical three-valued hash path provide a useful middle point for
protocol state that is naturally ternary, while remaining within Bitcoin
Script's per-item and combined-stack limits? The hypothesis was that explicit
trit validation would make the representation composable even if its ordinary
31-bit integer cost lost to the existing binary and four-way paths.

## Construction

Let `S` be SHA-256 and `R` be RIPEMD-160. Each trit selects exactly two hashes:

```text
0 -> SS    1 -> SR    2 -> RS
```

`RR` is deliberately unused. The path processes least-significant trits
first, finishes with `R`, and compares the resulting 20-byte commitment. The
integer adapter uses the smallest fixed number of base-3 digits covering the
requested width; 31 bits require 20 trits. Witness order is
`tritN-1 ... trit0 preimage`, with zero encoded as the empty vector and the
other trits as exactly `[01]` or `[02]`.

The Script fragment explicitly rejects padded, negative-zero, and out-of-range
trit encodings. It then reconstructs the committed value as
`3*acc + trit` while draining the saved trits from the altstack.

## Evidence and representative cost

Evidence is `locally-reproduced`: all three codewords, integer boundaries,
wrong openings, non-canonical encodings, and out-of-range trits pass focused
tests. The local tests use the strict tapscript-context executor; no Bitcoin
Core consensus or relay-policy comparison has been performed, so deployment is
`unclassified`.

For a 32-byte preimage and a 31-bit value:

| Fragment | Script bytes | Serialized witness | Witness items | Peak items |
| --- | ---: | ---: | ---: | ---: |
| `verify_ternary_hash_path_to_integer` | 924 | 63 | 21 | 24 |

The benchmark reports zero auxiliary hint items. These are fragment-only
measurements: the verifier and integer reconstruction are included, while
input pushes, terminal predicates, and transaction framing are excluded.
The strict local tapscript benchmark's legacy `opcode_count` reports `0`, so
executed-opcode count remains unavailable rather than being inferred from the
static script.

The construction is larger than the measured four-way path (438 bytes, 61
witness bytes, 19 peak items) for ordinary 31-bit integers. Its value is the
native three-way selector, not a claim of Pareto improvement.

## Security and deployment

The final RIPEMD-160 digest gives the usual generic 80-bit collision bound and
the mixed schedule is not independently cryptanalysed. Hiding still requires
min-entropy in the unrevealed preimage/trit pair. Exact byte canonicality is
enforced by the fragment, but protocol callers must still bind the path length,
bit width, commitment, participant/round context, and terminal predicate.

All trits are present at script entry and there are no hint items. The 20-trit
representative stays below the 1,000-item combined stack limit in the strict
local test, but composition with surrounding protocol state must be measured.

See the [implementation README](../../src/commitments/README.md), the
[commitment comparison](../comparisons/commitments.md), and catalog record
`commitment/ternary-hash-path-integer`.
