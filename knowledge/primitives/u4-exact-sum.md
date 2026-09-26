# Checked u4 exact sum

## Question

Can a checked u4 vector retain its full arithmetic sum without reducing modulo
16 or installing an addition lookup table?

## Construction

`u4_nibbles_sum_exact(n)` consumes `n` numeric nibbles in input order and
returns their exact sum in `0..=15*n`. It range-checks every hostile input,
folds the values with `OP_ADD` through one altstack accumulator, and preserves
unrelated surrounding stack state.

## Evidence

- evidence: `inspected`
- execution: `unclassified`
- representative configuration: 32 hostile nibble items, one exact sum
- comparison: direct fold versus modulo-16 lookup addition

The implementation tests sums above 16, singleton behavior, malformed inputs,
batch bounds, and surrounding-stack preservation. It is a fragment, not a
complete locking script, and makes no consensus, policy, or cryptographic-
security claim.

## Limitations

The output is a ScriptNum whose magnitude grows with the batch size. The
standalone batch ceiling is 997 inputs before accounting for unrelated live
stack state; callers must lower it when composing with other values.
