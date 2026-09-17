# Checked u4 transition count

## Question

Can a u4 vector expose its number of unequal neighboring pairs without
materializing an intermediate equality mask?

## Construction

`u4_nibbles_transition_count(n)` consumes `n` numeric nibbles in input order
and returns the number of indices `i` for which `nibble[i] != nibble[i+1]`.
It range-checks every hostile input, compares pairs directly, and folds the
inequality bits into one altstack accumulator. The result is in `0..=n-1`.

## Evidence

- evidence: `inspected`
- execution: `unclassified`
- representative configuration: 32 hostile nibble items, one compact count
- comparison: direct fold versus adjacent-mask materialization

The implementation includes repeated, alternating, singleton, malformed,
boundary, and surrounding-stack cases. It is a fragment, not a complete
locking script, and makes no consensus, policy, or cryptographic-security
claim.

## Limitations

The output discards the locations of individual transitions. The standalone
batch ceiling is 997 inputs before accounting for unrelated live stack state;
callers must lower it when composing with other values.
