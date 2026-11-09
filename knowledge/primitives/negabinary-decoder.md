# Checked negabinary decoding

Can a base −2 Horner decoder preserve every representable signed
result at width 32 without reparsing a five-byte temporary?
Compare the same canonical bit witness, signed output and exact
terminal predicate with a multiply-first schedule that explicitly
checks and corrects its final step. The hypothesis is that two
subtractions preserve the valid cancellation with fewer script
bytes than a special final branch.

[Frougny and Lai](https://doi.org/10.46298/dmtcs.538) describe
negative radix representations with unsigned digits. The
[pinned Bitcoin Core ScriptNum definition](https://github.com/bitcoin/bitcoin/blob/49faec4f87f5cd19c88db01a82e5c68b087c8227/src/script/script.h#L211)
supplies the distinction between four-byte numeric operands and
wider arithmetic results.

The decoder consumes exact raw bits, most significant first.
It computes `d-x-x` so the first subtraction always fits for
prefixes through 31 bits. Only the final result of a 32-bit
vector can exceed the four-byte range. A size check rejects
that result without treating it as a numeric operand.

Even powers contribute positive terms and odd powers contribute
negative terms. The 31-bit prefix interval is bounded by setting
all odd bits or all even bits, giving −715,827,882 and
1,431,655,765. Smaller prefixes lie inside those bounds. With
`d` in `{0,1}`, the first difference `d-x` therefore always
fits before the last subtraction.

The existing [signed radix-32 window decoder](signed-radix32-decoder.md)
extracts a sign and magnitude bits from signed digits. Here the
negative radix carries the sign in its positional weights and
the result is one signed ScriptNum. See the
[matched comparison](../comparisons/negabinary-decoder.md),
[implementation README](../../src/arithmetic/negabinary/README.md)
and [multiply-first counterexample](../negative-results/negabinary-decoder.md).
At width 32, the boundary leaf uses 422 bytes versus 444 for
checked multiply-first. Both peak at 35 and use 35 data-witness
bytes. The 16-call fixture saves 352 leaf bytes at the same
515-item peak.
Evidence is `locally-reproduced`. Execution is `unclassified`.
