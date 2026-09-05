# Ed25519 base field

This field family exposes two exact hinted multiplication backends modulo
`p=2^255-19`. The current locking-script-size winner is
`fields::ed25519::u5_balanced_table`; `fields::ed25519::bigint9` remains the
normalized-Karatsuba factor-8 baseline.

| Backend | Field domain | Product kernel | Certified-input script | Strict peak |
| --- | --- | --- | ---: | ---: |
| `u5_balanced_table` | Ordinary | 663 signed table lookups | <!-- metric:ed25519_field_mul -->9893<!-- /metric:ed25519_field_mul --> bytes | <!-- metric:ed25519_field_mul_stack -->523<!-- /metric:ed25519_field_mul_stack --> items |
| `u5_balanced_table::verify_product_hinted` | Ordinary | quotient-only reverse carry, claimed product | 9,762 bytes | 525 items |
| [`bigint9`](bigint9/) | `E(x)=x/8 mod p` | 646 quarter-square lookups | 19,903 bytes | 719 items |

The rows are exact field multiplications but are not drop-in stack-format
substitutes. The radix-32 backend keeps host values in the ordinary field
domain; its stack encoding is described below. The bigint9 backend requires
factor-8 values throughout the surrounding field circuit and has a much
smaller incremental hint. See the [bigint9 backend README](bigint9/) for its
full retained measurements and contract.

## Parameters

- The modulus is fixed at `p=2^255-19`; there is no modulus parameter.
- The winning backend fixes 51 radix-32 digits, thirteen left limbs, and
  thirteen 32-entry signed tables. These have no runtime defaults or tuning
  knobs.
- `preserved_items` has no default. It is the exact unrelated combined
  main-plus-altstack state and must be in `0..=477`.
- Callers choose the certified-input `mul_mod_hinted` boundary or the raw
  hostile-witness `mul_mod_hinted_from_raw_witness` boundary explicitly.

## Centered radix-32 representation

`u5_balanced_table` represents one ordinary residue by 51 stack digits
`e_i=d_i+16` in `[0,31]`. Arithmetic uses `d_i` in `[-16,15]`. The centered
interval contains exactly `p` integers after removing its top 19-value gap, so
the encoding is unique: the only in-range vectors rejected as noncanonical
have `e_1..e_50=31` and `e_0>=13`.

The left operand is grouped into twelve four-digit limbs and one three-digit
top limb. Script derives thirteen signed 32-entry multiple tables from those
limbs. Each of the 51 certified right digits directly selects one entry from
each table, giving exactly `13*51=663` bound products. Because
`32^51=p+19`, the verifier folds high coefficients by 19 and proves the exact
integer relation with one scalar quotient and 50 carries. The result digits
are derived, range-checked, and checked for the 19-value canonical gap.

### Eight-item packed circuit wires

`u5_packed` losslessly packs the 51 five-bit digits into eight compressed-u32
stack items. Digits are concatenated least-significant first; seven words use
all 32 bits and the top word has one required zero padding bit. Witness order
is `word[7] .. word[0]`, with word zero nearest the top. This is circuit-data
compression, not an arithmetic hint: both codec directions require exactly
**zero auxiliary hint items**, while all eight packed data items coexist at
script entry.

The hostile-input decoder accepts exactly one raw encoding per word. It
normalizes at-most-four-byte ScriptNums and compares their raw bytes, handles
canonical `-2^31` as the sole legal five-byte compressed word, expands through
the shared `u32_uncompress` primitive, rejects the bit-255 padding slot, and
rejects the field's 19-value canonical gap. Conversion streams one byte at a
time and keeps only one cross-byte carry live instead of materializing 256 bit
items.

| Packed codec boundary | Policy-produced script | Strict combined-stack peak |
| --- | ---: | ---: |
| Partial-word consume, return 16 centered `[20,20,20,15 x 13]`-bit limbs | <!-- metric:ed25519_packed_grouped_decode -->3590<!-- /metric:ed25519_packed_grouped_decode --> bytes | <!-- metric:ed25519_packed_grouped_decode_stack -->62<!-- /metric:ed25519_packed_grouped_decode_stack --> items |
| Partial-word consume, return 51 certified digits | <!-- metric:ed25519_packed_digit_decode -->4072<!-- /metric:ed25519_packed_digit_decode --> bytes | <!-- metric:ed25519_packed_digit_decode_stack -->93<!-- /metric:ed25519_packed_digit_decode_stack --> items |
| Fast consume, direct signed-word expansion | 4,644 bytes | 81 items |
| Fast preserve, direct signed-word expansion | 4,678 bytes | 89 items |
| Consume 8 packed items, return 51 certified digits | 6,241 bytes | 58 items |
| Preserve the original 8 items and also return 51 digits | 6,275 bytes | 66 items |
| Consume 51 previously certified digits, return 8 packed items | 3,628 bytes | 61 items |
| Certify 51 hostile digits, then pack | 4,209 bytes | 61 items |

The two partial-word rows are `fragment-with-memory:` measurements including
their threshold-table setup and cleanup. The remaining rows are
`fragment-only:` measurements including conversion, exact encoding checks,
padding/canonical checks where applicable, and output ordering. They
exclude input pushes, witness serialization, a terminal predicate, and all
field arithmetic. Every artifact is below the 32 KiB optimizer cutoff and was
compiled with the repository policy. The deterministic maximum-canonical
fixture's eight packed items serialize as 20 witness bytes; the representation
has an eight-item, <!-- metric:ed25519_packed_decoder_witness_max -->48<!-- /metric:ed25519_packed_decoder_witness_max -->-byte serialized maximum (one item-count byte, eight
one-byte lengths, seven words of at most five payload bytes, and a top word of
at most four because its padding bit is zero).

The retained direct signed-word path maps each
compressed word to its low 31 bits plus sign bit and invokes the shared
31-bit decomposition once. It saves 1,597 bytes but raises the transient peak:
the fast consuming and preserving variants permit 919 and 911 unrelated items,
respectively. The byte-stream decoder permits 942 unrelated preserved items.
Its preserving form permits 934: the 66-item peak includes the original eight
packed items, and its 59-item final state contains those eight items plus all
51 digits. This low-stack form is intended for dense trace verification: a
caller can retain the compact committed wire while passing its expanded copy
to a field gate, without paying the encoder or adding another witness value.
The encoder permits 939 unrelated preserved items. These bounds are
generator-enforced and refer to the combined main plus alt stack.

The fast decoder checks the unique five-byte `-2^31` sentinel exactly. For
at-most-four-byte words it accepts nonminimal ScriptNum aliases when execution
flags allow them. It nevertheless derives the same 256-bit word stream and
independently checks both padding and the semantic field gap, so this is raw
encoding malleability rather than a false-value path. Use the 6,241/6,275-byte
decoder when byte-unique packed commitments are required. The 31-bit splitter
alone is 385 policy-produced bytes per word (3,080 bytes for eight calls), so a
roughly 2 KB decoder is not attainable by repeating that primitive; a smaller
decoder requires a shared decomposition table or a different wire format.

`u5_packed_grouped` adds a partial-word decoder for the slope circuit. It
retains each word's low piece numerically, splits only the remaining high bits,
and streams completed limbs and the cross-word carry through altstack. Sixteen
Script-authored powers `2^15..2^30` replace repeated threshold literals; all
sixteen are removed before return. `decode` directly returns sixteen centered
limbs, avoiding a 51-digit expansion followed by regrouping. `decode_digits`
returns the original certified digits and saves 572 bytes against
`decode_fast`, at a 12-item increase in local peak.

Both boundaries consume exactly **eight coexisting data items** and
<!-- metric:ed25519_packed_decoder_hint_items -->0<!-- /metric:ed25519_packed_decoder_hint_items --> auxiliary hint items per invocation. The G32 schedule invokes direct grouped decoding 46 times
and digit decoding 47 times, with **zero cumulative hints** for either set.
The grouped contract is `preserved | word7..word0 -> preserved | limb15..limb0`;
the digit contract ends in `digit50..digit0`. Their respective 62/93-item peaks
include inputs, outputs, temporary powers, and both stacks. Preserved combined
prefixes of 937/906 items have separately tested strict peaks of 999. Existing
altstack contents are restored, and neither decoder appends a terminal
predicate. Raw ScriptNum alias semantics match `decode_fast`; the padding bit
and semantic 19-value gap are always checked from the decoded value.

## Optimization notes

- Centering makes the stored radix-32 digit itself a signed-table selector, so
  the 663 product lookups need no per-term bias correction.
- A digit is removed with `OP_ROLL` on its thirteenth and final use. A small
  compile-time dynamic program orders each column's terms to minimize the
  serialized selector and table-depth constants.
- Table zero carries a constant affine `+16`; because limb zero occurs once in
  every low column, this deletes the output-bias addition from all 51 carry
  steps.
- The quotient doubles as the omitted final carry. A joint addition chain
  computes `low+19*high`, the preceding carry seeds the low sum, and one shared
  full-limb bias replaces twelve repeated wide constants.

## Radix-32 measurements

Both rows use the `fragment-with-memory` boundary. They include table setup and
drop, all 663 lookups, pseudo-Mersenne folding, the exact quotient/carry
relation, cleanup, and canonical output validation. They exclude input pushes,
a terminal predicate or output comparison, tapleaf/control-block
serialization, transaction context, and every EdDSA layer. The compact row
also excludes operand certification and therefore requires both operands to
have been certified on the same verified path.

The witness sizes are for the deterministic benchmark's opposite-end centered
operands and are representative, not maxima.

| Configuration | Locking script | Data witness | Maximum stack items |
| --- | ---: | ---: | ---: |
| Two previously certified operands | 9,893 bytes | <!-- metric:ed25519_field_mul_hint_witness -->245<!-- /metric:ed25519_field_mul_hint_witness --> bytes / <!-- metric:ed25519_field_mul_hint_items -->51<!-- /metric:ed25519_field_mul_hint_items --> incremental hint items | 523 |
| Two raw operand digit vectors | <!-- metric:ed25519_field_mul_standalone -->11180<!-- /metric:ed25519_field_mul_standalone --> bytes | <!-- metric:ed25519_field_mul_standalone_witness -->398<!-- /metric:ed25519_field_mul_standalone_witness --> bytes / 153 complete data items | <!-- metric:ed25519_field_mul_standalone_stack -->523<!-- /metric:ed25519_field_mul_standalone_stack --> |

The 9,893-byte gate breaks down as follows:

| Component | Bytes |
| --- | ---: |
| Table construction and routing | <!-- metric:ed25519_field_mul_table_setup -->2227<!-- /metric:ed25519_field_mul_table_setup --> |
| Folded product and exact relation | <!-- metric:ed25519_field_mul_relation -->7299<!-- /metric:ed25519_field_mul_relation --> |
| Table cleanup and canonical result restoration | <!-- metric:ed25519_field_mul_cleanup -->367<!-- /metric:ed25519_field_mul_cleanup --> |
| **Total** | **9,893** |

For circuits that already carry a claimed product as a live wire,
`verify_product_hinted` walks the same exact relation from its most-significant
column toward column zero. The final carry is the quotient, so every other
carry is reconstructed as `carry[i-1] = 32*carry[i] - relation[i]`. This
variant is 9,762 policy-produced bytes (9,805 bytes before optimizer
rewrites), uses exactly one auxiliary hint item, and has a 525-item strict
peak. The quotient has at most 22 magnitude bits and therefore at most three
ScriptNum payload bytes.

That one-item figure must not be confused with the complete input footprint.
A standalone call also needs the claimed 51-digit result, for 154 input items
in total: 51 lhs digits, 51 rhs digits, 51 claimed-result digits, and one
quotient. A freshly witnessed result therefore costs 52 new items, one more
than the compute-output gate's quotient-plus-50-carry hint. The reverse gate is
a composition win only when the result is independently required circuit data,
as in a point-transition trace.

The policy-produced gate contains <!-- metric:ed25519_field_mul_opcodes -->6449<!-- /metric:ed25519_field_mul_opcodes --> static non-push opcodes. The table
entries, folded coefficients, quotient/carry operations, and their affine
addition chains have analytic ScriptNum bounds; the largest conservative
intermediate is 1,887,426,272, below `2^31-1`.

## Security

The gate proves an exact integer identity, not merely a collection of modular
checks. Each table entry is derived from the certified left operand; every
right digit is used as a certified table selector; and the quotient and all 50
carries are bound by the same relation. Script derives every result digit,
checks it is in `[0,31]`, and rejects the 19-value encoding gap, leaving one
accepted representation per field residue.

Hints are public prover assistance, not secrets. Non-minimal four-byte-or-less
hint encodings are witness-malleable but do not create a false-proof path;
oversized ScriptNums fail closed when arithmetic consumes them. This primitive
has no standalone classical security level: signature security depends on
point, scalar, hash, key-binding, and subgroup layers outside this field-gate
boundary. A separate experimental custom BLAKE3/Montgomery-slope construction
implements such upper layers for one fixed-key/fixed-message benchmark, but it
is not RFC 8032 Ed25519 and does not turn this atomic gate into a signature
verifier.

## Script compatibility and standardness

The generated opcodes are tapscript-compatible. The 9,893-byte compact core is
below the legacy 10,000-byte script-size ceiling, but its 6,449 static non-push
opcodes exceed the legacy and P2WSH 201-opcode consensus limit; the 11,180-byte
raw wrapper also exceeds their size limit. P2SH additionally cannot carry this
redeem script under its element-size constraints. Bare-script relay templates
do not provide a deployment route for this fragment.

Tapscript removes those script-size and opcode-count limits, and the measured
execution respects its 1,000-item combined stack limit. No complete tapleaf,
transaction, Bitcoin Core consensus validation, or relay/mining-policy check
has been performed, so deployment remains `unclassified`. See
[`docs/script-types.md`](../../../docs/script-types.md) and
[`docs/standardness.md`](../../../docs/standardness.md).

## Witness and stack contract

From bottom to top, `mul_mod_hinted` consumes
`lhs[50..0] | rhs[50..0] | q | carry[49..0]` and returns
`r[50] ... r[0]`, with digit zero nearest the top. `q` and all carries are
hostile hints bound by the exact relation. The compact entry point assumes the
two digit vectors are already certified; use
`mul_mod_hinted_from_raw_witness` when they arrive as raw witness data.

The 523-item combined main-plus-altstack peak is data-independent for this
layout, leaving room for at most 477 unrelated live items. A caller must pass
that unrelated state count through `preserved_items`; the generator rejects a
larger declared layout.

`verify_product_hinted` instead consumes
`lhs[50..0] | rhs[50..0] | claimed_product[50..0] | q`, returns the unchanged
claimed product, and permits at most 475 unrelated live items. Its auxiliary
hint count is one, its complete standalone input count is 154, and both counts
are part of the public composition contract.

## Operational notes and evidence

The evidence level is `locally-reproduced` and the deployment class is
`unclassified`. The policy-compiled compact gate was executed 100 times with
`bitcoin-scriptexec` in tapscript context and the combined 1,000-item stack
limit enabled; the raw-operand wrapper was executed once on the same fixture.
Fast active tests cover encoding uniqueness, host multiplication, analytic
ScriptNum bounds, the 663-lookup schedule, and the stack guard. Generated
Script boundary and adversarial tests are intentionally `#[ignore]` and were
not run in the default suite. Bitcoin Core consensus and relay-policy
validation and a complete transaction remain open.

Reproduce the measurement with `cargo run --locked --release --example
ed25519_u5_balanced_field_benchmark`. On the recorded arm64 macOS 26.6.1 host
with rustc 1.98.0 and cargo 1.98.0, the 100 compact executions had a 0.289 ms
median, 0.427 ms p95, and 0.705 ms maximum; policy compilation took 0.833 s.
These wall times are diagnostic and machine-dependent. The checkout base was
`7c3d38e0cd64a0ee730069eeae4fb7008bb3de70`; the measured implementation had
SHA-256 `86abd9e990ba583bd97600b76622706f2e7a912031f7fd707f379a28512ae382`.

Reproduce the packed-wire rows with `cargo run --locked --release --example
ed25519_u5_packed_codec_benchmark`. That example executes each configuration
once under bitcoin-scriptexec's strict 1,000-item limit. Focused active tests
cover host and Script boundary round trips, byte-for-byte preservation, the
canonical five-byte word, noncanonical word aliases, the padding bit, the
19-value field gap, and out-of-range raw digits. The codec evidence level is
`locally-reproduced`; its deployment class remains `unclassified` because it
has not been exercised in a complete tapleaf or Bitcoin Core transaction.

The bounded `ed25519_packed_grouped_decode_probe` example checks the new
partial-word outputs against host bit extraction on boundary and deterministic
seeded words, rejects every canonical-gap value and malformed word cases, and
tests both 999-item composition frontiers. Those decoder results are
`differentially-validated` against that host implementation and remain
`unclassified`; no complete scalar leaf is executed by the probe.

The quotient-only claimed-product measurement is reproduced separately with
`cargo run --locked --release --example
ed25519_u5_verified_product_benchmark`. Pass `--raw-only` to measure its
unoptimized serialization without executing the generated Script.

This module is only base-field multiplication. It does not itself implement
point decoding, subgroup policy, scalar handling, hashing, or a signature
equation. Those layers now exist separately in the experimental
[custom BLAKE3/Montgomery-slope verifier](../../../knowledge/primitives/ed25519-blake3-montgomery-slope.md)
for one fixed-key/fixed-message benchmark; that construction is not RFC 8032,
does not use the standard SHA-512 transcript, and remains outside this field
primitive's measurement boundary.
The original roughly 2.3 KB 26/25-bit sketch is not a sound verifier: it omits
the shifted-product quotient/carry binding. The radix-32 backend repairs that
gap, but its measured sound gate is 9,893 bytes. See NR-030 in the
[negative-results index](../../../knowledge/negative-results/index.md) and
OP-018 in [open problems](../../../knowledge/open-problems.md).

## Knowledge-base integration

See the [atomic primitive page](../../../knowledge/primitives/ed25519-field.md),
[arithmetic comparison](../../../knowledge/comparisons/arithmetic.md),
[lookup-table technique](../../../knowledge/techniques/lookup-tables.md),
[witness-hint technique](../../../knowledge/techniques/witness-hints.md),
[negative result NR-030](../../../knowledge/negative-results/index.md), and
[open problem OP-018](../../../knowledge/open-problems.md).
