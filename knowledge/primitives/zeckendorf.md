# Canonical Zeckendorf decoding

`arithmetic::zeckendorf::decode_zeckendorf(width)` converts a fixed-width,
canonical, non-adjacent binary vector into one nonnegative ScriptNum using
weights `1, 2, 3, 5, …`. No proposed scalar or auxiliary hint is consumed:
the bits are ordinary witness data. Every input is range-checked and restated
against its minimal ScriptNum encoding before conditional weight addition.
Adjacent ones reject before reconstruction. The generator rejects width 0 and
widths above 43 rather than allowing an unsafe intermediate sum.

## Research question and objective

What is the cost of enforcing the canonical Zeckendorf system in Script,
with no lookup table, and of retaining an exact decoded value for a caller?
The hypothesis is a two-phase schedule: inspect every raw bit and every pair,
then consume each already checked flag with `OP_IF` while adding its literal
Fibonacci weight. The measured objective is the complete verifier leaf and its
witness, not an assertion that canonical positional encoding compresses scalar
storage or proves an application-level secret. The comparison is ordinary
power-of-two binary reconstruction at the same witness value and image size.

This is distinct from a factoradic rank decoder and from signed NAF: those
have different input alphabets, meanings and sum contracts. Fibonacci-weighted
subset membership would also be a different problem: it generally does not
bind a value to the unique positional representation accepted here.

## Bounded domain and stack contract

Input is `preserved | bit[0] | … | bit[width-1]`, with bit 0 (weight one)
deepest. The fragment returns `preserved | value`. All unrelated main and
altstack contents survive; the decoder itself does not use the altstack.
`width` is required in `1..=43`, with no default.

The full generated weight sum, not merely the no-adjacent subset, must fit the
four-byte ScriptNum bound `2^31−1`, checked at generation and through the
shared `scriptint::MAX_SCRIPTNUM` helper. At width 43 that sum is 1,836,311,901;
at width 44 it is 2,971,215,071, so the generator stops at the earlier width.
This is a whole-subset-safety choice, not a claimed maximum general Zeckendorf
number. The separately executed width-43 all-alternating maximum is
1,134,903,169, and a single top weight of 701,408,733 also decodes correctly.

Every input is one compact canonical zero or one. There are exactly `width`
input data items and **zero auxiliary hints and zero hint bytes**, including
under batching/composition statements (none measured). They all coexist at
entry. The complete peak is `width + preserved_items + 4`, including copied
pair operands. A concrete two-main/one-alt caller-state test peaks at 19.
The exact combined-limit test reaches 1,000 items; one additional item rejects
with `StackSize`. More caller state must reserve corresponding headroom.
Missing inputs can underflow, while extra items are the caller's preserved
prefix; an exact complete-leaf arity requires a separate depth predicate.
The caller must consume the resulting number, clean preserved state, and
supply its own terminal predicate.

## Matched complete-leaf comparison

Both leaves decode 100, compare the returned number exactly, and leave clean
`OP_TRUE`. They use 12 canonical bit data items: three `01` items, nine empty
items, and thus 16 data-witness bytes including item count and lengths. No
hint, scalar operand, or additional witness item is supplied. Expected 100 is
a locking-script constant on both sides.

- Zeckendorf: `100 = 89 + 8 + 3`, with no adjacent ones.
- Binary: `100 = 64 + 32 + 4`, using the powers `1,2,4,…,2048` and allowing
  adjacent ones. The raw canonical and weighted-addition routines are shared
  at the semantic boundary; only the weights and adjacency pass differ.

| Boundary | Zeckendorf | Matched binary |
| --- | ---: | ---: |
| Policy-compiled complete-leaf bytes | 300 | 196 |
| Data-witness bytes | 16 | 16 |
| Data items / auxiliary hints | 12 / 0 | 12 / 0 |
| Combined main-plus-alt peak | 16 | 16 |
| Static non-push operations | 210 | 133 |
| Executed non-push operations | 201 | 124 |
| Script + data-witness bytes | 316 | 212 |

The boundary includes decoding, exact output checks, and clean terminal truth.
It excludes caller state, script/control-block serialization, full Taproot
witness framing, and transaction context. Static counts contain every branch;
executed counts encounter branch delimiters but exclude unexecuted `OP_ADD`
bodies and all push-only operations. Both scripts use `CompileOptions::ALL`
under the central policy; none exceeds its cutoff. The measured fixed-Zeckendorf
witness has exact 16 serialized bytes; this is not a bound claimed across
other scalar targets without re-parameterizing the terminal predicate.

The Zeckendorf leaf exceeds the 201-opcode legacy/P2SH/P2WSH limit; the binary
row does not imply compatibility under those forms either. Each has 300 or
196 leaf bytes respectively, below the 520-byte P2SH element-size limit, but
opcode and other policy limits remain independent. No deployment or economic
claim follows. Evidence is local only.

## Proof and hostile-input coverage

The independent harness enumerates all 4,096 width-12 masks. Only the 377
masks with no adjacent set bits pass, and their weighted outputs are a
bijection onto every value `0..=376`. Nonzero canonical aliases are also
checked under local `Consensus` and `Policy` profiles. Negative zero, alias
zeros/ones, out-of-range digits, negative digits, and five-byte forms reject
at every input position. A 520-byte malformed operand rejects for numeric
operand size, while a 521-byte item fails at the 520-byte witness-element
limit instead. A fixed-arity harness rejects 0, 11, and 13 records against an
expected 12. Width-43 and constructor-width failures exercise both accepted
maximum and rejected over-bound shapes.

A canonical 100 and an equal-weight 100 encoding with adjacent ones are
distinguished, not silently both accepted. Flipping weight one produces the
wrong decoded value and fails its terminal comparison. The pair-selection test
covers the first-copy source-depth correction from `offset+1` to `offset+2`;
valid sparse masks catch reselecting the first copied bit. The exact opcode
costs are policy-compiled measurements, never source-derived estimates.

## Evidence and provenance

Evidence: `locally-reproduced`. Execution: `unclassified`. Local tapscript
execution enforces the combined stack limit and 520-byte element cap under the
checked profiles. Canonical rejection is exercised with global numeric
minimality disabled. No Bitcoin Core transaction, relay-policy, validation
weight, or cryptographic-security claim is made; the ordinary parsed-instruction
counter is not mislabelled as executed work.

The standard definition is inspected in
[MathWorld's Zeckendorf representation and theorem pages](https://mathworld.wolfram.com/ZeckendorfsTheorem.html),
which constrain epsilon products for adjacent positions to zero. The bibliographic
reference is Fraenkel,
[*Systems of Numeration*, *American Mathematical Monthly* 92(2), 1985,
pages 105–114](https://www.jstor.org/stable/2322638). Original JSTOR text was
not locally retrievable, so no quotation or implementation is attributed to it.
[OEIS A035517](https://oeis.org/A035517) gives greedy expansions and the
independent example `100 = 3 + 8 + 89`. The Script scheduler, custom no-adjacent
validation routine, bounded-width choice, and measured costs are local.

Metric tests resolve compiler `124b561ed75ac3ec4c6ad99207d8dcdd3bc67180` and
interpreter `a09e87af444034698697f0a2267e755cf72f9aed` through
`support::provenance` over the embedded lockfile. Reproduce with:

```sh
CARGO_INCREMENTAL=0 cargo test --locked --lib arithmetic::zeckendorf::tests
CARGO_INCREMENTAL=0 cargo test --locked --test primitive_metrics zeckendorf_decoder_metrics_are_current
python3 tools/kb.py validate
```

See the [implementation README](../../src/arithmetic/zeckendorf/README.md),
[arithmetic comparison](../comparisons/arithmetic.md), and record
`arithmetic/zeckendorf`. [NR-113](../negative-results/index.md#nr-113-canonical-zeckendorf-validation-costs-more-than-matched-power-of-two-binary)
records the exact no-adjacency cost and rejected copy-depth prototype.
[OP-068](../open-problems.md#op-068--zeckendorf-consumer-and-composition-cost)
tracks whether an actual consumer benefits from this canonical numeral form.
