# Integer commitments

Each construction has its own implementation, tests, and parameter documentation:

- [Binary hash path](hash_path/README.md): optional SHA-256 followed by
  RIPEMD-160 per bit; consume selectors, retain normalized bits, or return an integer.
- [Four-way hash path](four_way_hash_path/README.md): fixed two-hash codewords
  per base-4 digit, with a tapscript-specific range check.
- [Preimage length](preimage_length/README.md): authenticate a SHA-256 preimage
  and return its length minus an offset.

The binary hash path is unary, not a conventional binary Merkle branch;
`HASH256(left || right)` would require concatenation or a separate 64-byte
compression circuit because `OP_CAT` is disabled. See the [measured negative
result](../../knowledge/negative-results/merkle-branch-composition.md).

These experimental primitives authenticate values; they are not complete
protocols. See the [comparison](../../knowledge/comparisons/commitments.md).
