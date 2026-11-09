# Direct numeric ordering cannot consume wide ScriptNum outputs

Adding `2147483647 + 1` and `2147483647 + 2` produces two valid
five-byte results. Applying numeric less-than directly to those
results fails under the pinned local interpreter. Clamping both sums
to `2147483647` also loses their order because the clamped values
coincide.

The [split sum](../../src/arithmetic/wide_sum/README.md) returns the
canonical pairs `[1, 1]` and `[2, 1]` in residual/class order. The
tested numeric consumer compares classes and then compares
residuals. It returns true for this ordered pair of sums.
Evidence is `locally-reproduced`; execution is `unclassified`.
