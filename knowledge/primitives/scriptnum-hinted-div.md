# Hinted ScriptNum division

Verifies a witness-supplied quotient for division by a positive compile-time
constant and derives the Euclidean remainder without `OP_DIV` or `OP_MOD`.

- **Position:** compact local division when the divisor is public and all
  arithmetic fits ScriptNum.
- **Evidence:** locally reproduced, including wrong-hint rejection.
- **Trust boundary:** the quotient is hostile witness data and is constrained
  by recomposition and remainder bounds.
- **Encoding boundary:** the locally reproduced division tests cover the
  minimal ScriptNum transitions at `127/128`, `255/256`, and `-128/-129`.
- **Representative result:** `hinted_div_rem(8)` is 13 bytes with a 3–11 byte
  serialized witness in the measured range.
- **Limitation:** not a general wide-integer division primitive.

The [bounded direct divider](scriptnum-bounded-div.md) adds a zero-hint option
for canonical nonnegative dividends. Its matched comparison wraps this verifier
with the same dividend checks and quotient normalization. At divisor 31 and
maximum 991, the hinted complete leaf uses 49 bytes, a 6-byte/2-item data
witness including exactly one hint, and an 8-item combined peak. The direct
leaf uses 92 bytes, a 4-byte/1-item witness, zero hints, and a 4-item peak.
Both include identical output comparisons and clean truthy success; neither
includes a transaction. Nonminimal numeric hint aliases may be normalized in
the matched wrapper, giving a 9-byte maximum witness at that bound. The raw
13-byte `hinted_div_rem(8)` fragment above does not include these wrapper checks.

See the [implementation README](../../src/arithmetic/scriptint/README.md) and
catalog record `arithmetic/scriptnum-hinted-div`.
