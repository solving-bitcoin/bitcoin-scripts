# u4 popcount experiment

- **Question:** Can a shared 16-entry lookup table count the set bits in
  eight hostile u4 limbs more cheaply than decomposing them to 32 bits and
  summing the result?
- **Hypothesis:** A table that returns nibble Hamming weights will reduce both
  serialized code and live stack items when the caller needs only the count.
- **Comparison:** Eight checked nibbles with `popcount(8)` versus the existing
  checked `u4_nibbles_to_be_bits(8, true)` followed by 31 additions.
- **Threat model:** Every witness nibble is hostile; values outside `0..=15`
  must fail before table indexing. The primitive does not promise canonical
  raw ScriptNum byte encodings.
- **Execution class:** `unclassified`, locally executed in the repository's
  tapscript executor with the strict 1,000-item stack limit.
- **Boundary:** Includes the generated lookup table, range checks, queries,
  altstack accumulation, cleanup, and returned count; excludes witness pushes,
  terminal predicates, and transaction framing.
- **Reproduction:**

  ```sh
  cargo test --locked popcount --lib
  cargo test --locked --test primitive_metrics u4_popcount_metrics_are_current
  python3 tools/kb.py validate
  ```

The representative result is 135 script bytes, 17 witness bytes, zero hints,
27 combined stack items, and an unavailable local executed-opcode count. The
bit-decomposition baseline is 331 bytes and 93 items on the same checked
eight-nibble boundary.
