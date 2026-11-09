# Binohash 10-choose-5 host subset probe

- **Question:** Does the deterministic legacy digest helper distinguish all
  252 canonical 5-of-10 choices on one fixed transaction template, and which
  index aliases remain if a caller does not validate selection shape?
- **Comparison objective:** Enumerate exactly the paper's 10-choose-5 toy
  subset space with unchanged transaction fields, scriptCode, and sighash flag.
- **Execution class:** `locally-reproduced`, `unclassified`. This is a host-side
  `FindAndDelete` plus rust-bitcoin sighash probe. It does not execute Bitcoin
  Script, check ECDSA signatures, or compare with Core.

Run `cargo test --locked --test binohash_ten_choose_five`. The fixture fixes a
version-2 one-input, one-output transaction; an input outpoint with txid
`07` repeated 32 times and vout 1; 1,000 sat sent to `OP_TRUE`; ten distinct
9-byte DER-shaped deletion targets; and `SIGHASH_ALL` (`0x01`) for the measured
digest. The scriptCode is 101 bytes: ten serialized pushes plus `OP_TRUE`.
There is no RNG.

All `C(10,5)=252` ascending subsets have distinct 32-byte digests in this
**one fixed template**. Reversing a subset produces the same digest because
deleting distinct embedded pushes commutes. Selecting index 0 twice has the
same digest as selecting it once; the host helper also accepts selections of
the wrong length. An index outside `0..9` returns `InvalidSelection`.
Therefore a protocol that treats the index vector as a digest must bind a
canonical length, range, uniqueness, order, and encoding in its Script
consumer. This host probe does not upgrade any Core validation result.

The ten DER-shaped byte vectors are deletion targets only; their ECDSA
validity is not asserted. The 101-byte scriptCode is **not** a complete
locking script or transaction cost. Locking-script bytes, serialized witness
bytes, combined stack peak, executed opcodes, validation budget, and complete
transaction weight are unmeasured. There are no witness or hint items in this
host calculation. Distinctness for 252 fixed inputs is not a collision or
security bound for the full protocol.

Primary source: [Binohash §4.5](https://robinlinus.com/binohash.pdf), PDF
SHA-256 `1be2b63034a86db1f9f4a35c7963248d307583723079ff25284a9fc4affee94a`
as reviewed 2026-10-29. The host serializer is rust-bitcoin 0.32.102 as
pinned in `Cargo.lock`.
