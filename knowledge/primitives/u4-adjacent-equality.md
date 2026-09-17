# Checked u4 adjacent-equality mask

## Question

Can a checked u4 fragment expose equality between neighboring nibbles without
expanding the inputs into bits or installing a lookup table?

## Construction

`u4_adjacent_equal_mask(n)` consumes `n` numeric nibbles in input order and
returns `n-1` ScriptNum booleans. Output `i` is true exactly when
`nibble[i] == nibble[i+1]`. Inputs are range-checked as `0..=15`; non-minimal
raw ScriptNum encodings remain a caller-level canonicality concern.

The fragment keeps the original inputs on the main stack while it computes
pairs from the end toward the beginning and stores only the boolean results on
the altstack. It therefore has no hint items or table memory and leaves
unrelated surrounding stack state intact.

## Evidence

- evidence: `locally-reproduced`
- execution: `unclassified`
- representative configuration: 32 hostile nibble items, 31 output bits
- comparison: direct pair equality versus bit expansion or table lookup

The implementation tests ordinary, repeated, alternating, invalid, and
surrounding-stack cases. It is a fragment, not a complete locking script, and
does not provide a terminal predicate or a consensus/policy claim.

## Limitations

The output is a run-boundary mask rather than a packed bitstring. The standalone
batch ceiling is 499 inputs before accounting for unrelated live stack state;
callers must lower it when composing with other values.
