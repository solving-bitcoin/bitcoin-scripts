# Retained canonical NAF ScriptNum witnesses

`arithmetic::naf::verify_scriptnum_naf(width)` accepts one canonical nonnegative
ScriptNum and `1..=32` fixed-width signed digits. Each digit must also be a
canonical ScriptNum in `{-1,0,1}`. Consecutive digits cannot both be nonzero,
and `scalar = Σ digit[i]·2^i` holds exactly. The original scalar and digit stack
survive for a downstream consumer. This adds a checked NAF representation to
the local arithmetic library; it does not provide a curve proof or a signature.

## Question, hypothesis, and comparison objective

Can Script validate a hostile NAF opening without a resident table while
retaining it for later use? The hypothesis is that the range check plus pairwise
`abs(d[i]) + abs(d[i+1]) < 2` enforces canonical NAF spacing in linear script
bytes, followed by a small high-to-low Horner reconstruction. The object of
comparison is the complete proof and retained representation, not compression:
one scalar versus the same scalar and its NAF digit stream.

The matched control checks the same canonical nonnegative scalar without asking
for a decomposition. On that boundary, NAF pays for its extra hints,
reconstruction, and uniqueness check. A masked position-index list or dynamic
wNAF scalar-multiplication schedule is outside this experiment.

`scriptnum_naf_stack_bound(width) = width + 5` is conservative. Count every
preserved main- or altstack item in addition, and subtract that total from
1,000 before composing. Each invocation has one scalar data item and `width`
digit hints, all present at script entry. There is no shared table to amortize.

## Measured complete leaves

Both rows are final `CompileOptions::ALL` policy-produced complete leaves. They
include hostile-input validation, exact comparisons of every retained item,
and terminal `OP_TRUE`; input pushes, control-block/script serialization,
Taproot framing, unrelated live state, and transaction context are excluded.
The scalar-only side has the same value validation and retained-scalar check,
but no digit stream. Witness sizes cover only scalar and digits with item count
and CompactSize lengths. These are not complete Taproot witnesses.

- Width 9: scalar 175, digits `[-1,0,0,0,-1,0,-1,0,1]`; nine hints, four
  nonzero, so 13 serialized hint bytes. Data total: 10 items / 17 bytes.
- Width 16: scalar 21845, alternating `1,0` digits; 16 hints, eight nonzero, so
  24 hint bytes. Data total: 17 items / 28 bytes.

| Width / scalar | Complete-leaf bytes | Data-witness bytes | Maximum canonical witness | Data / hint items | Combined peak | Static / executed non-push |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 9 / 175 | 447 | 17 | 18 | 10 / 9 | 14 | 347 / 286 |
| 16 / 21845 | 791 | 28 | 28 | 17 / 16 | 21 | 613 / 493 |

Each scalar-only control instead measures 14 bytes, four data-witness bytes,
one scalar data item, zero hints, a four-item peak, and eight static/executed
non-push operations. NAF is thus 464 versus 18 combined script-plus-data bytes
at width 9, and 819 versus 18 at width 16. The comparison is deliberately about
retaining a canonical NAF stream, not asserting that those bytes are necessary
for an ordinary scalar equality test. [NR-112](../negative-results/index.md#nr-112-naf-openings-cost-more-than-the-plain-scalar-predicate)
records the tradeoff and a rejected copy-depth prototype.

Static counts include every branch body. Executed counts step the exact leaf,
not a separate fragment, and include control delimiters but exclude pushes and
unexecuted bodies. They differ when reconstruction takes the zero or negative
digit branches. Checked output and stack depths use a strict tapscript context
with the combined-stack limit enforced; the metric resolver pins compiler
`124b561ed75ac3ec4c6ad99207d8dcdd3bc67180` and interpreter
`a09e87af444034698697f0a2267e755cf72f9aed` from its embedded lockfile. Local
`Consensus` and `Policy` profiles cover canonical and noncanonical encodings.
The metric execution uses canonical data without relying on global minimal-data enforcement. No transaction-level validation-weight claim is made.

## Security and hard constraints

- Every scalar and digit is hostile until explicitly range- and raw-encoding
  checked. Aliases are rejected even when `require_minimal=false`.
- Only nonnegative four-byte-or-smaller scalar claims are in scope. Negative
  signed NAFs are deliberately rejected, not misreported as canonical.
- The encoding is unique for this nonnegative fixed-width domain; leading
  zeroes merely pad it to `width`. Supported generation rejects width 0 and
  widths above 32. Arithmetic remains in the four-byte operand domain.
- Accepted verification does not consume the certified digit stream. A caller
  must provide output comparisons or cleanup and retain any required predicate.
- At width 32 both the maximum scalar and an alternating NAF for 1431655765 are
  accepted. The maximum scalar's final negative digit uses `a+(a-1)`, avoiding
  the overflowing intermediate `2a`. Its near-limit composition stays within
  1,000 measured main-plus-alt items; one extra runtime item fails with
  `StackSize`. Measured peaks may be smaller than the conservative bound because
  the whole composition is optimized together.
- Bare, P2SH, and P2WSH have a 201-opcode limit: even width 9 has 347 static
  non-push operations. Width 16 is 791 bytes and exceeds P2SH's 520-byte script
  element ceiling; width 9 is 447 bytes but still exceeds the opcode cap.
  Nothing here establishes legacy or Taproot relay compatibility.
- A retained NAF can feed a consumer, but this verifier does not itself verify
  a scalar multiplication, point, message, signature, or cryptographic relation.
  Negabinary and signed-window fragments have different value contracts and do
  not supply an interchangeable cost baseline.

Evidence is `locally-reproduced`; execution is `unclassified`. No Bitcoin Core
differential, relay-policy verdict, or cryptographic-security claim is made.

## Provenance and reproduction

The standard NAF context is [Hankerson, Menezes, and Vanstone, *Guide to
Elliptic Curve Cryptography*, chapter 3](https://doi.org/10.1007/0-387-21846-7_3),
2004. The reference is representation context only. Pairwise absolute-sum
spacing, retained copy/accumulator source depths, validation, and costs are
local. No cost or security claim is imported.

Tests use the host-side standard NAF generator for all values 0 through 255,
enumerate all 81 four-digit ternary vectors, and reject equal-value alternate
encodings, every adjacent nonzero position, out-of-range and oversized inputs,
raw aliases at every input position, negative and incorrect claims, missing or
extra items, and unsupported widths. The original scalar and digits, plus
unrelated caller state, are compared explicitly.

```sh
CARGO_INCREMENTAL=0 cargo test --locked arithmetic::naf --lib
CARGO_INCREMENTAL=0 cargo test --locked --test primitive_metrics scriptnum_naf_metrics_are_current
python3 tools/kb.py validate
```

See the [implementation README](../../src/arithmetic/naf/README.md),
[arithmetic comparison](../comparisons/arithmetic.md), and record
`arithmetic/scriptnum-naf`. [OP-067](../open-problems.md#op-067--naf-consumer-and-representation-frontier)
tracks actual consumer cost rather than assuming that retaining the digits
makes a scalar schedule cheaper.
