# Canonical Zeckendorf decoding

`arithmetic::zeckendorf::decode_zeckendorf` decodes a fixed-width Zeckendorf
representation to one nonnegative canonical ScriptNum. The inputs are hostile
raw ScriptNum bytes. The fragment checks numeric range, exact minimal encoding,
and the no-consecutive-ones rule independently of global numeric-minimality
settings. It consumes no claimed scalar and no auxiliary hint, and it uses no
table, multiplication, or division.

The representation uses weights `1, 2, 3, 5, …`. Zeckendorf's theorem gives
existence and uniqueness of a nonnegative integer's finite sum of nonconsecutive
Fibonacci weights under this convention. Local exhaustive width-12 tests treat
the 4,096 possible raw binary masks independently: the 377 masks with no adjacent
ones map bijectively onto `0..=376`; every other mask rejects. Equal weighted
sums with adjacent ones are not alternative accepted encodings.

Stable source anchors are MathWorld's
[Zeckendorf's Theorem](https://mathworld.wolfram.com/ZeckendorfsTheorem.html)
and OEIS [A035517](https://oeis.org/A035517), whose immutable sequence accession
identifies Zeckendorf expansion by these `1, 2, 3, 5, …` weights. Registration
of those sources and knowledge-catalog integration are outside this local
implementation boundary.

## Parameters and generation bound

`decode_zeckendorf(width)` takes a required generation-time width in `1..=43`;
there is no default. `MAX_ZECKENDORF_WIDTH` is 43. Widths zero and 44 panic at
construction, as does every larger width.

Weights are generated locally with a two-variable Fibonacci recurrence and
embedded as literals; there is no resident lookup table. The generator sums the
whole vector, not merely the legal no-adjacent subset, and asserts that this sum
fits a four-byte signed ScriptNum. Width 43 has whole-weight sum
`1,836,311,901`; width 44 would have `2,971,215,071` and exceeds `2^31-1`.
Actual accepted width-43 values are smaller: its all-alternating maximum is
`1,134,903,169`.

## Stack and witness contract

With stack items written bottom-to-top:

```text
before: preserved | bit[0] | … | bit[width-1]
after:  preserved | value
```

`bit[i]` selects the `i`th generated weight, so weight one is deepest and the
largest bit is on top. Each item must be exactly the empty item (zero) or `01`
(one). Aliases such as `00`, `0100`, negative zero `80`, and four-byte zero or
one forms reject even when their numeric value is zero or one. `02`, negative
values, five-byte forms, and elements above 520 bytes also reject. The checks
precede every conditional weight addition and do not rely on tapscript
`MINIMALIF` or global `MINIMALDATA` behavior.

The no-adjacency pass copies each neighboring pair, checks that their numeric
sum is less than two, and drops both retained copies before reconstruction.
The reconstruction then rechecks range and raw reserialization for each bit
before consuming it with `OP_IF`, conditionally adding its literal weight. No
embedded scalar target is read or compared. The returned value remains available
for a caller-selected consumer.

Exactly `width` input items are consumed. All unrelated older main-stack items
and the complete altstack survive; the decoder itself never uses the altstack.
It does not check entry depth: missing items fail through stack underflow, while
extra items belong to the preserved caller prefix by design. A fixed complete
leaf that expects exactly the vector must impose its own depth or clean-stack
boundary. The caller must also consume or verify the result, clean its preserved
state, and supply the terminal predicate.

Every bit is ordinary witness data. There are **zero auxiliary hint items per
invocation and zero hint counts in every measured configuration**, because no
proposed scalar or other claimed answer is supplied. A complete width-12 witness
therefore has exactly twelve data items and zero hints, all present at entry.
Their item count and serialized lengths are witness data bytes, not hint bytes.

For `p` preserved main-plus-alt items, the fragment's exact combined peak is
`width + p + 4`. This covers the two copied adjacent operands and their two
`OP_2DUP` copies. The width-12 caller-state fixture measures 19 with two main
and one alt item. A separate composition accepts at exactly 1,000 combined
items and rejects one additional item with `StackSize`. Callers must also
account for their own consumers and any preloaded future inputs under the same
limit.

## Complete-leaf metrics

Both rows decode integer 100 to a checked terminal value, consume that value,
and leave exactly `OP_TRUE`. The Zeckendorf bits, least significant first, are

```text
0, 0, 1, 0, 1, 0, 0, 0, 0, 1, 0, 0   (89 + 8 + 3 = 100)
```

The matched ordinary power-of-two binary decoder uses the same twelve canonical
bit items, range checks, raw reserialization, conditional additions, and exact
terminal check, but weights `1, 2, 4, …, 2048` and no adjacency pass. Its bits are

```text
0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0   (64 + 32 + 4 = 100)
```

Each complete witness has three `01` items and nine empty items, hence sixteen
serialized data-witness bytes including the item count and every item length.
The expected scalar 100 is a locking-script constant in both rows, never an extra
witness item. There are no input pushes in either locking script beyond its
weights, expected value, and final true.

The `complete-leaf:` boundary includes decoding, exact output comparison, and
clean terminal true; it excludes caller state and any transaction wrapper.
Data-witness serialization excludes the leaf, control block, annex, and
transaction. Hint items and serialized hint bytes are both zero in each row.
Peak is combined main-plus-alt. Static counts include every non-push opcode;
executed counts include encountered branch delimiters and omit unexecuted
conditional `OP_ADD`s. Both leaves compile through `compile_with_policy()` with
`ALL` enabled.

| Configuration | Leaf bytes | Data witness bytes | Data items | Hint items | Combined peak | Static non-push | Executed non-push |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Zeckendorf, width 12, value 100 | <!-- metric:zeckendorf_12_script -->300<!-- /metric:zeckendorf_12_script --> | <!-- metric:zeckendorf_12_witness -->16<!-- /metric:zeckendorf_12_witness --> | <!-- metric:zeckendorf_12_witness_items -->12<!-- /metric:zeckendorf_12_witness_items --> | <!-- metric:zeckendorf_12_hints -->0<!-- /metric:zeckendorf_12_hints --> (0 bytes) | <!-- metric:zeckendorf_12_stack -->16<!-- /metric:zeckendorf_12_stack --> | <!-- metric:zeckendorf_12_static -->210<!-- /metric:zeckendorf_12_static --> | <!-- metric:zeckendorf_12_executed -->201<!-- /metric:zeckendorf_12_executed --> |
| Matched binary, width 12, value 100 | <!-- metric:zeckendorf_binary_12_script -->196<!-- /metric:zeckendorf_binary_12_script --> | <!-- metric:zeckendorf_binary_12_witness -->16<!-- /metric:zeckendorf_binary_12_witness --> | <!-- metric:zeckendorf_binary_12_witness_items -->12<!-- /metric:zeckendorf_binary_12_witness_items --> | <!-- metric:zeckendorf_binary_12_hints -->0<!-- /metric:zeckendorf_binary_12_hints --> (0 bytes) | <!-- metric:zeckendorf_binary_12_stack -->16<!-- /metric:zeckendorf_binary_12_stack --> | <!-- metric:zeckendorf_binary_12_static -->133<!-- /metric:zeckendorf_binary_12_static --> | <!-- metric:zeckendorf_binary_12_executed -->124<!-- /metric:zeckendorf_binary_12_executed --> |

The local fixture executes both leaves under the tapscript Consensus and Policy
profiles, with the 520-byte element and 1,000-item stack limits enforced and no
signature charge. The Consensus profile disables global numeric minimality for
the adversarial tests so aliases reach the fragment itself. These are local
fragment executions, not complete-spend validation.
`support::provenance` resolves compiler commit
124b561ed75ac3ec4c6ad99207d8dcdd3bc67180 and interpreter commit
a09e87af444034698697f0a2267e755cf72f9aed from the embedded lockfile for these
measurements.

## Security, compatibility, and scope

Raw-canonical checks make the encoding byte-unique within these profiles.
They do not authenticate the bits, bind them to a transaction, or provide any
cryptographic security property. No one-time-use or cryptographic assumption is
introduced.

The employed opcodes have legacy, P2SH, P2WSH, and tapscript interpretations,
but resource limits and policy differ by context. In particular, the measured
Zeckendorf complete leaf has 210 static non-push opcodes, exceeding the 201-opcode
legacy/P2SH/P2WSH ceiling; its matched binary row has 133. That opcode comparison
does not establish that the shorter row is valid in any particular script type.
Tapscript has no corresponding legacy static-opcode ceiling, but this work makes
no consensus-validity, relay-standardness, or deployability claim. See
[script types](../../../docs/script-types.md) and
[standardness](../../../docs/standardness.md).

Evidence classification is `locally-reproduced`; deployment classification is
`unclassified`. Correctness and resource tests cover every width-12 mask,
independent uniqueness over `0..=376`, zero, one, canonical and adjacent 100,
width-43 boundaries, raw aliases at every position, wrong values, wrong record
counts, and unrelated main/alt-stack preservation. Consumer-specific result
predicates, exact top-level witness arity, catalog/reference registration,
complete transaction checks, and broader protocol composition remain outside
this implementation.

## Reproduction

```sh
cargo test --locked --lib arithmetic::zeckendorf::tests
cargo test --locked --test primitive_metrics zeckendorf_decoder_metrics_are_current
```
