# BLAKE3 over tracked limbs

Implements BLAKE3 for messages up to one 1,024-byte chunk using tracked-stack
u4 and bigint machinery.

- **Position:** locally used to compress intermediate protocol state; supports a
  bounded single-chunk range rather than the full unbounded tree API.
- **Evidence:** differentially validated against official vectors.
- **Representative result:** a fixed-point-optimized 64-byte, 29-bit-limb
  compute fragment with its table memory is 76,481 bytes, contains 46,691
  static non-push opcodes, and peaks at 644 combined stack items in the
  deterministic helper composition.
- **Boundary:** `fragment-with-memory`; the result includes 383 bytes of full
  table setup and 192 bytes of cleanup, but excludes input encoding and digest
  comparison.
- **Tradeoff:** limb width trades script bytes against retained-message stack
  items. The same 64-byte fragment is 68,287 bytes with 4-bit limbs, while
  larger widths compose with more blocks and unrelated state.
- **Execution:** the local witness-input executor used by differential tests
  and the peak metric disables the stack-limit check. The observed one-block
  peak is below 1,000, but the record remains `research-unlimited` and is not a
  deployment result.
- **Security:** inherited from BLAKE3 for the supported construction range.

Host-known messages and expected outputs are packed directly at generation
time. Actual witness limbs are numerically range-validated, but byte-unique
ScriptNum encoding remains a caller obligation. For a final block of at most 32
bytes, the second 256-bit input group is outside the declared message and is
dropped without validation before zero padding is synthesized; callers must
not rely on that ignored group being bound.

See the [implementation README](../../src/hashes/blake3/README.md) and catalog
record `hash/blake3-limb29`.
