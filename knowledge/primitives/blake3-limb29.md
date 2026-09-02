# BLAKE3 over tracked limbs

Implements BLAKE3 for messages up to one 1,024-byte chunk using tracked-stack
u4 and bigint machinery.

- **Position:** locally used to compress intermediate protocol state; supports a
  bounded single-chunk range rather than the full unbounded tree API.
- **Evidence:** `differentially-validated` against official vectors.
- **Representative result:** a fixed-point-optimized 64-byte, 29-bit-limb
  compute fragment with its table memory is 72,469 bytes, contains 47,624
  static non-push opcodes, and peaks at 692 combined stack items in the
  deterministic helper composition.
- **Boundary:** `fragment-with-memory`; the result includes 458 bytes of lookup
  table setup and 216 bytes of cleanup, but excludes input encoding and digest
  comparison.
- **Tradeoff:** limb width trades script bytes against retained-message stack
  items. The same 64-byte fragment is 64,275 bytes with 4-bit limbs, while
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
record `hash/blake3-limb29`. Messages of at most 32 bytes can instead use the
[sparse direct-u4 profile](blake3-short-u4.md), which removes the selected-limb
input conversion and compile-time-zero message words.
