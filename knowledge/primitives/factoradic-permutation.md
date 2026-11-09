# Canonical bounded permutation decoding

Question: can a single canonical ScriptNum encode and reconstruct a public-alphabet
permutation with no hints, fewer entry items, and a lower combined stack peak than
separate Lehmer digits? The objective is witness/item reduction, with total bytes
reported separately. Hard constraints are current enabled opcodes, four-byte
numeric operands, widths 1..12, strict 1,000-item combined stack checking, and
hostile witness values including raw numeric aliases.

The [implementation](../../src/arithmetic/permutation/README.md) applies
factoradic unranking with bounded binary threshold subtraction. At each stage it
selects and removes a symbol from a trusted descending pool using `OP_ROLL`.
Compared with the existing fixed-composition Winternitz key pool, this pool
contains small public symbols; this decoder actually reconstructs the permutation
on chain. It does not extend that 49-key multiset scheme or authenticate a rank.
Existing hinted ScriptNum division is unnecessary because each quotient is
bounded by the shrinking alphabet and can be computed directly.
That arithmetic is now shared with the [checked bounded divider](scriptnum-bounded-div.md).
The permutation decoder supplies the certified residual bound internally;
the public divider adds canonical-input and explicit range checks. The existing
width-4/8/12 permutation metric snapshots remain unchanged by the extraction.

The hypothesis holds for entry items and stack usage, but fails for total bytes.
At width 8, the equal complete-leaf comparison gives 312 script bytes, 5 data
witness bytes, 1 data item, 0 hints, a 12-item peak, and 178 executed non-push
opcodes. Separate digits give 129/15/7/0/18/85. Widths 4/12 show the same
tradeoff; [NR-084](../negative-results/factoradic-permutation.md) records it.
Input pushes and transaction framing are excluded on both sides; canonical checks,
trusted pool setup/cleanup, every output equality and clean truthy success are
included. The witness figure includes its count and item-length prefixes.

Threat model: every supplied rank or digit is hostile. Canonicality and range
checks precede selection; derived quotients cannot escape the trusted pool.
This provides an exact encoding of a permutation, with no collision-resistance,
signature, hiding, or authorization claim. The first output symbol is on top;
a consumer must respect that layout and budget the expanded output vector.

Evidence is `locally-reproduced`, execution `unclassified`: local tapscript with
stack checking enabled and global minimal-data disabled. Compiler and interpreter
provenance are recorded by the executable metric test from its embedded lockfile.
Neither mathematical enumeration nor strict fragment execution supplies Core or
relay-policy validation. The width-12 packed leaf additionally exceeds P2SH's
redeemScript element limit and P2WSH/legacy's static opcode budget; these facts do
not preclude a tapscript experiment.

The independent lexicographic-successor oracle exhausts all permutations through
width 6; wider boundary checks and malformed witness checks are deterministic.
Exact stack coexistence tests include preserved main and alt items. The unresolved
[OP-041](../open-problems.md#op-041--permutation-decoding-consumer-frontier)
requires a real consumer before advertising a protocol-level advantage.

Mathematical provenance: [Tarau, arXiv:0808.0554v1, §§7.1–7.2](https://arxiv.org/html/0808.0554v1).
The Script construction and measurements are local research contributions.
