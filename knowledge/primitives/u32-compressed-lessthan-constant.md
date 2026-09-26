# Checked compressed u32 less-than with an embedded threshold

`arithmetic::u32::cmp::u32_compressed_lessthan_constant` consumes one
canonical compressed u32 ScriptNum and compares it with a generation-time
threshold. It returns the Boolean result of `input < threshold` and embeds
thresholds at or above `0x80000000` as their signed ScriptNum representation.

## Research question

Can a fixed range gate retain the compressed-u32 wire savings while removing
the second comparison operand from the witness?

The closest baseline is `u32_compressed_lessthan()`, which consumes two
canonical compressed ScriptNums. This adapter keeps the input boundary and
reuses the complete comparator, adding only the embedded constant push.

## Boundary and threat model

The witness input is hostile: non-minimal encodings, negative zero, oversized
values, and malformed five-byte values are rejected by the reused canonical
compressed boundary. The threshold is public locking-script data and is
generated as the canonical signed ScriptNum for the selected u32 value. No
terminal predicate or clean-stack guarantee is supplied beyond the Boolean
result.

The representative configuration uses threshold `0x89abcdef` and input
`0x01020304`, with one data item and zero hints. The measured fragment includes
the embedded threshold push and full compressed comparison, and excludes input
pushes, the terminal predicate, unrelated live state, and transaction context.
Evidence is `locally-reproduced`; execution is `unclassified`. No Bitcoin Core
consensus or relay-policy validation is claimed.

This is a witness-shape adapter for fixed thresholds. Use the generic
two-input comparator when the threshold is already available at runtime or
when one script serves many thresholds.

## Reproduction

```sh
cargo test --locked arithmetic::u32::cmp::tests::test_u32_compressed_lessthan_constant --lib
cargo test --locked --test primitive_metrics u32_compressed_lessthan_constant_metrics_are_current -- --exact
python3 tools/kb.py validate
```
