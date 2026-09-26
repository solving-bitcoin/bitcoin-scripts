# Integer commitments

Each construction has its own implementation, tests, and parameter documentation:

- [Binary hash path](hash_path/README.md): optional SHA-256 followed by
  RIPEMD-160 per bit; consume selectors, retain normalized bits, or return an integer.
- [Four-way hash path](four_way_hash_path/README.md): fixed two-hash codewords
  per base-4 digit, with a tapscript-specific range check.
- [Preimage length](preimage_length/README.md): authenticate a SHA-256 preimage
  and return its length minus an offset.
- **TapBranch u4 hash:** compute BIP341's tagged hash over two already ordered
  32-byte nodes represented as 128 range-checked u4 items. Ordering remains a
  caller precondition; the fragment returns 64 digest nibbles.

These experimental primitives authenticate values; they are not complete
protocols. See the [comparison](../../knowledge/comparisons/commitments.md).

## TapBranch u4 boundary

`tapbranch_hash_u4` inserts the fixed `SHA256("TapBranch") ||
SHA256("TapBranch")` prefix and reuses the u4 SHA-256 circuit. It proves
numeric nibble range, not minimal ScriptNum encoding. The witness contains 128
data items in `left || right` order, with zero as the empty vector and
`1..=15` as one-byte values; there are no hints. The caller must enforce
`left <= right` lexicographically.

| Fragment | Locking script | Unlocking witness | Peak combined stack |
| --- | ---: | ---: | ---: |
| `tapbranch_hash_u4()` | <!-- metric:tapbranch_hash_u4 -->1106723<!-- /metric:tapbranch_hash_u4 --> bytes | <!-- metric:tapbranch_hash_u4_witness -->161<!-- /metric:tapbranch_hash_u4_witness --> bytes (<!-- metric:tapbranch_hash_u4_witness_items -->128<!-- /metric:tapbranch_hash_u4_witness_items --> items) | <!-- metric:tapbranch_hash_u4_stack -->969<!-- /metric:tapbranch_hash_u4_stack --> |

The measured script is above the repository's 32-KiB optimizer cutoff, so its
reported size is unoptimized. Static non-push opcodes are
<!-- metric:tapbranch_hash_u4_opcodes -->671155<!-- /metric:tapbranch_hash_u4_opcodes --> and the fragment uses
<!-- metric:tapbranch_hash_u4_hints -->0<!-- /metric:tapbranch_hash_u4_hints --> hint items. Tapscript does not impose the legacy 10,000-byte or 201-opcode
limits, but standard transaction weight and complete-spend validity remain
unverified; the deployment class is `unclassified`.
