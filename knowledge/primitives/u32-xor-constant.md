# Checked u32 XOR with an embedded constant

`arithmetic::u32::xor_constant::u32_xor_constant` consumes one canonical
four-byte u32 word and XORs it with a generation-time constant. It returns one
four-byte word in the repository's most-significant-byte-first representation.

## Research question

Can a fixed XOR operand be embedded without a second witness word while
retaining the existing byte-table implementation?

The hypothesis is that embedding the constant removes four witness items and
their serialized bytes. The tradeoff is a larger locking fragment and a
per-call table setup/cleanup cost.

## Boundary and threat model

The fragment checks every witness limb for numeric byte range and canonical
ScriptNum encoding before table addressing. Negative, out-of-range, and
non-minimal limb encodings are rejected. The constant is public and embedded
in the locking script; no terminal predicate or clean-stack guarantee is
provided by the fragment.

The representative configuration is `u32_xor_constant(0x89abcdef)` with four
canonical `0xff` witness limbs and no hints. It measures the generated
fragment, including table setup, four checks, XOR queries, and table cleanup;
it excludes witness pushes, a terminal predicate, unrelated live state, and
transaction context. The local strict tapscript executor measures a 652-byte
fragment, 13 serialized witness bytes, a 272-item combined peak, and 484
static non-push opcodes. Static non-push count is not a dynamic execution
count.

Evidence is `locally-reproduced` and execution is `unclassified`. The
repository's strict local boundary enforces the combined 1,000-item stack
limit, but no Bitcoin Core consensus or relay-policy validation is claimed.

## Comparison

The closest existing construction is the generic `u32_xor()`: its operator is
202 bytes, or 566 bytes when the same 236-byte table setup and 128-byte
cleanup are included. With two canonical all-`0xff` words it uses eight data
items and 25 witness bytes. That operator does not perform this adapter's
hostile-input checks, so the comparison is a cost boundary rather than an
equivalent verifier. The adapter is useful for isolated fixed masks where
four fewer witness items and 12 fewer witness bytes are worth 86 additional
locking bytes over that raw boundary.

The generic form can still be preferable when the mask is already available or
when a surrounding script shares the XOR table.

The output remains a word fragment, not a complete locking script. Callers
must enforce any required terminal predicate and clean-stack behavior.
