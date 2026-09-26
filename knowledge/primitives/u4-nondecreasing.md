# Checked u4 nondecreasing predicate

## Question

Can a u4 vector prove nondecreasing order directly, without copying it into a
second vector or expanding every nibble into bits?

## Construction

`u4_nibbles_nondecreasing(n)` consumes `n` numeric nibbles in input order and
returns one ScriptNum boolean. It range-checks every hostile input, compares
each adjacent pair with `OP_LESSTHANOREQUAL`, and folds the results into one
accumulator on the altstack. A singleton is vacuously nondecreasing.

## Evidence

- evidence: `locally-reproduced`
- execution: `unclassified`
- representative configuration: 32 hostile nibble items, one output bit
- comparison: direct adjacent comparisons versus full-vector lexicographic
  comparison or bit expansion

The implementation tests sorted, descending, singleton, malformed, boundary,
and surrounding-stack cases. It is a fragment, not a complete locking script,
and does not make a consensus, policy, or cryptographic-security claim.

## Limitations

The output is one predicate, not the locations of individual descents. The
standalone batch ceiling is 997 inputs before accounting for unrelated live
stack state; callers must lower it when composing with other values.
