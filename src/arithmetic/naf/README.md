# Retained canonical NAF ScriptNum witnesses

`verify_scriptnum_naf(width)` checks a nonnegative scalar together with a hostile
fixed-width signed-digit opening. It accepts `width` canonical digits in
`{-1,0,1}`, requires every adjacent pair to contain zero, and checks

```text
scalar = sum(digit[i] * 2^i)
```

The scalar and every original digit remain available to a downstream scalar
schedule on success. This is a representation proof, not a signature or curve
proof. Nonnegative integers have the standard unique NAF; leading zeroes are
accepted as fixed-width padding, not as a distinct representation.

## Parameters and threat model

- `width`: required; integer `1..=32`, no default.
- Input: `preserved | scalar | digit[0] | … | digit[width-1]`, with the most
  significant digit on top.
- Output: the exact unchanged stack on success, or interpreter abort otherwise.
- Data: one canonical nonnegative ScriptNum scalar.
- Incremental hints: exactly `width` digit items. All digits coexist with the
  scalar at script entry. They are arithmetic hints, not secrets.
- No tables, cryptographic keys, multiplication, or division opcodes are used.
- `scriptnum_naf_stack_bound(width)` is the conservative bound `width + 5`.
  Every preserved main- or altstack item adds to it. For composition, leave
  `1000 - (width + 5)` combined items for caller-owned state; measured complete
  leaves can use slightly less because whole-script optimization changes the
  final schedule.

The scalar and every digit are re-encoded to reject non-minimal and oversized
ScriptNums independently of global MINIMALDATA settings. A negative scalar is
rejected even when a signed digit expansion matches it. Missing and excess
items fail at the enclosing exact stack/output boundary.

## Research question and construction

Question: what does it cost to expose a checked canonical NAF schedule instead
of checking only the scalar? Hypothesis: an absolute-sum isolation rule costs
linear script bytes, requires no resident table, and preserves a small combined
stack peak. The checked relation is `abs(d[i]) + abs(d[i+1]) < 2`; after the
range check that is exactly “at least one adjacent digit is zero.” The first
copy requires one extra source depth for the second digit, and the accumulator
requires one extra depth for the retained scalar comparison.

The comparison is against a canonical nonnegative scalar-only predicate. NAF
adds a representation constraint and retains its digit stream; the baseline
has no such stream. This is the intended cost boundary, not evidence that NAF
or a different signed-radix representation is universally preferable.

## Measured complete leaves

Each leaf contains either the NAF verifier and exact comparisons of every
retained scalar/digit, or the scalar-only nonnegative/canonical checks and the
exact scalar comparison, followed by `OP_TRUE`. Both sides use the same scalar,
policy compilation, runtime witness data, output semantics, and terminal
predicate. Script-byte counts are final policy-produced serialization.
Witness bytes include only data-item counts and CompactSize item lengths, not
the script, control block, Taproot framing, or transaction context.

`width=9` uses `175 = 256 - 64 - 16 - 1`, digits
`[-1,0,0,0,-1,0,-1,0,1]`. `width=16` uses `21845 = sum(2^i,
i∈{0,2,4,6,8,10,12,14})`, with alternating `1,0` digits.

| Width / scalar | Locking script | Data witness | Data items / hint items | Hint bytes | Combined peak | Static non-push | Executed non-push |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 9 / 175 | <!-- metric:scriptnum_naf_w9_script -->447<!-- /metric:scriptnum_naf_w9_script --> bytes | <!-- metric:scriptnum_naf_w9_witness -->17<!-- /metric:scriptnum_naf_w9_witness --> bytes | 10 / <!-- metric:scriptnum_naf_w9_hints -->9<!-- /metric:scriptnum_naf_w9_hints --> | 13 | <!-- metric:scriptnum_naf_w9_stack -->14<!-- /metric:scriptnum_naf_w9_stack --> | <!-- metric:scriptnum_naf_w9_opcodes -->347<!-- /metric:scriptnum_naf_w9_opcodes --> | <!-- metric:scriptnum_naf_w9_executed -->286<!-- /metric:scriptnum_naf_w9_executed --> |
| 16 / 21845 | <!-- metric:scriptnum_naf_w16_script -->791<!-- /metric:scriptnum_naf_w16_script --> bytes | <!-- metric:scriptnum_naf_w16_witness -->28<!-- /metric:scriptnum_naf_w16_witness --> bytes | 17 / <!-- metric:scriptnum_naf_w16_hints -->16<!-- /metric:scriptnum_naf_w16_hints --> | 24 | <!-- metric:scriptnum_naf_w16_stack -->21<!-- /metric:scriptnum_naf_w16_stack --> | <!-- metric:scriptnum_naf_w16_opcodes -->613<!-- /metric:scriptnum_naf_w16_opcodes --> | <!-- metric:scriptnum_naf_w16_executed -->493<!-- /metric:scriptnum_naf_w16_executed --> |

The maximum canonical NAF data witnesses at these fixed widths are 18 and 28
bytes respectively: one item-count byte, three bytes for the scalar claim, and
one CompactSize byte per hint plus one payload byte per nonzero digit. NAF
spacing permits at most five nonzero digits at width 9 and eight at width 16;
it does not permit every digit to be nonzero. The measured examples need not
maximize nonzero digit count.

The matched scalar-only rows have one data item, zero hints, and four
serialized data-witness bytes:

| Width / scalar | Locking script | Combined peak | Static non-push | Executed non-push |
| --- | ---: | ---: | ---: | ---: |
| 9 / 175 | <!-- metric:scriptnum_naf_w9_plain_script -->14<!-- /metric:scriptnum_naf_w9_plain_script --> bytes | <!-- metric:scriptnum_naf_w9_plain_stack -->4<!-- /metric:scriptnum_naf_w9_plain_stack --> | <!-- metric:scriptnum_naf_w9_plain_opcodes -->8<!-- /metric:scriptnum_naf_w9_plain_opcodes --> | <!-- metric:scriptnum_naf_w9_plain_executed -->8<!-- /metric:scriptnum_naf_w9_plain_executed --> |
| 16 / 21845 | <!-- metric:scriptnum_naf_w16_plain_script -->14<!-- /metric:scriptnum_naf_w16_plain_script --> bytes | <!-- metric:scriptnum_naf_w16_plain_stack -->4<!-- /metric:scriptnum_naf_w16_plain_stack --> | <!-- metric:scriptnum_naf_w16_plain_opcodes -->8<!-- /metric:scriptnum_naf_w16_plain_opcodes --> | <!-- metric:scriptnum_naf_w16_plain_executed -->8<!-- /metric:scriptnum_naf_w16_plain_executed --> |

Peaks are measured combined main-plus-alt-stack items, including all entry
claims and hints. Executed counts come from stepping the exact complete leaf:
active non-push operations and control delimiters are counted, while pushes and
unexecuted bodies are excluded. Opcode counts are not silently substituted with
the interpreter's parsed-instruction statistic. These complete leaves are
locally executed, not complete Taproot spends.

## Correctness and adversarial reproduction

The independent host-side standard NAF generator covers all nonnegative values
`0..=255`. All 81 four-digit ternary vectors are checked against an independent
positional sum model; invalid spacing and negative claims reject. Other tests
check:

- alternative equal-value expansions and every adjacent nonzero position;
- raw positive, zero/negative-zero and negative aliases at every input position,
  under both local `Consensus` and `Policy` profiles;
- out-of-range and five-byte digits at every position;
- incorrect scalar claims, missing items, excess items, and unsupported widths;
- exact preservation of retained inputs and unrelated main/altstack state;
- the maximum scalar `2147483647`, an alternating NAF for `1431655765`, a
  near-limit fixture within the 1,000-item combined-stack limit, and a
  one-item-larger witness rejected with `StackSize`.

Run:

```sh
CARGO_INCREMENTAL=0 cargo test --locked arithmetic::naf --lib
CARGO_INCREMENTAL=0 cargo test --locked --test primitive_metrics scriptnum_naf_metrics_are_current
python3 tools/kb.py validate
```

## Security, compatibility, and evidence

Evidence is `locally-reproduced`; execution is `unclassified`. Local tapscript
stack limits are enforced. The semantic fixtures use explicit local policy and
consensus profiles; canonical rejection is tested with global minimality off.
No Bitcoin Core differential, relay-policy acceptance, deployability, or
cryptographic security claim is made. The repository's pinned Core CI compares
other work, not this new fragment.

The opcodes are available in legacy and tapscript. Bare, P2SH, and P2WSH still
have their 201 non-push-opcode and 520-byte P2SH-element limits; both measured
NAF leaves exceed 201 operations. Width 9 is 447 bytes and fits the P2SH element
ceiling; width 16 is 791 bytes and exceeds it. Neither point establishes legacy
compatibility. The leaves are measured for tapscript research and require a
caller-owned output consumer or cleanup in composition.
See [script types](../../../docs/script-types.md) and
[standardness](../../../docs/standardness.md).

## Provenance and limitations

The standard signed non-adjacent representation is described in Hankerson,
Menezes, and Vanstone, [Guide to Elliptic Curve Cryptography, chapter 3,
DOI 10.1007/0-387-21846-7_3](https://doi.org/10.1007/0-387-21846-7_3), 2004.
That source supplies representation context, not the Script schedule or these
measurements. Pairwise isolation, retained stack scheduling, hostile-input
handling, and measured costs are local. No new scalar-multiplication algorithm
or security bound is asserted.

The fragment validates the digit stream but does not itself consume it as a
scalar-multiplication schedule. Any downstream window/table routing, actual
field relation, gas-like cost target, or complete-transaction binding is outside
this experiment. A canonical NAF is unique for its nonnegative scalar; a
proto-col must still bind the scalar to its intended application and keep this
retained representation distinct from negabinary or the signed radix-32 window
decoder, whose contracts and values differ.
