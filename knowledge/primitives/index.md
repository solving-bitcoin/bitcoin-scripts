# Primitive entries

Each page describes one construction family or representation. Exact measured
configurations live in `../catalog.json`; implementation details remain beside
the source. Read a page together with its comparison page and evidence record.

## Arithmetic

- [ScriptNum constant multiplication](scriptnum-constant-mul.md)
- [Hinted ScriptNum division](scriptnum-hinted-div.md)
- [u4 digit arithmetic](u4.md)
- [Signed radix-32 window decoder](signed-radix32-decoder.md)
- [Fixed-width u4 lexicographic comparison](u4-lexicographic.md)
- [Checked u4 leading-zero projection](u4-leading-zeros.md)
- [Checked u4 intra-nibble bit-transition projection](u4-bit-transitions.md)
- [Checked u4 trailing-zero projection](u4-trailing-zeros.md)
- [Checked u4 lowest-set-bit projection](u4-lowbit.md)
- [Checked inverse u4 Gray projection](u4-gray-inverse.md)
- [Checked u4 nonzero-power-of-two predicate](u4-power-of-two.md)
- [Checked u4 modulo-three projection](u4-mod3.md)
- [Checked u4 parity projection](u4-parity.md)
- [Checked u4 most-significant-bit projection](u4-msb.md)
- [Checked u4 triplet-to-u12 packing](u4-triplet.md)
- [Checked u4 quad-to-u16 packing](u4-quad.md)
- [Checked u4 XOR reduction](u4-xor-reduction.md)
- [Checked public-constant u4 multiplication modulo 16](u4-mul-constant-mod16.md)
- [Checked u4 squaring modulo 16](u4-square-mod16.md)
- [Checked u4 nondecreasing predicate](u4-nondecreasing.md)
- [Checked u4 exact sum](u4-exact-sum.md)
- [Checked u4 batch nibble packing](u4-batch-pack.md)
- [Checked u4 adjacent forward delta](u4-adjacent-delta.md)
- [Checked u4 cyclic vector rotation](u4-vector-rotation.md)
- [Checked u4 vector interleave](u4-interleave.md)
- [Checked u4 reflected Gray-code projection](u4-gray.md)
- [Checked u4 one-hot mask projection](u4-one-hot.md)
- [Checked u4 centered-signed projection](u4-centered.md)
- [Checked u4 complement-reflection projection](u4-mirror.md)
- [Checked u4 least-significant-bit projection](u4-lsb.md)
- [Checked u4 zero-mask projection](u4-zero-mask.md)
- [Checked u4 modulo-16 sum](u4-sum-mod16.md)
- [Checked u4 packed zero-bitmask projection](u4-zero-bitmask.md)
- [u32 word arithmetic](u32.md)
- [Checked u32 zero-byte mask](u32-zero-byte-mask.md)
- [Fused u32 XNOR adapter](u32-xnor.md)
- [u32 word arithmetic](u32.md) — includes the checked seven-bit rotation boundary
- [Compressed total-domain u32 addition](u32-compressed-add.md)
- [Compressed total-domain u32 equality](u32-compressed-equal.md)
- [Compressed total-domain u32 unsigned less-than](u32-compressed-lessthan.md)
- [Checked compressed u32 less-than with an embedded threshold](u32-compressed-lessthan-constant.md)
- [Checked u32 population count](u32-popcount.md)
- [Checked u32 per-byte population counts](u32-byte-popcounts.md)
- [Checked u32 leading zero-byte count](u32-leading-zero-bytes.md)
- [Checked u32 trailing zero-byte count](u32-trailing-zero-bytes.md)
- [Checked u32 byte extraction](u32-extract-byte.md)
- [Checked u32 bit-plane transpose](u32-bit-planes.md)
- [Checked u32 byte-equality mask](u32-byte-eq-mask.md)
- [Checked u32 byte-less-than mask](u32-byte-less-mask.md)
- [Checked u32 byte high-bit mask](u32-msb-mask.md)
- [u32 byte parity projection](u32-byte-parity.md)
- [Fused u32 NAND](u32-nand.md)
- [Fused u32 NOR](u32-nor.md)
- [Checked u32 zero predicate](u32-zero.md)

- [Compressed total-domain u32 logical right shift](u32-compressed-rshift.md)

- [Compressed total-domain u32 logical left shift](u32-compressed-lshift.md)
- [u31 prime-field arithmetic](u31.md)
- [Native secp256k1 base-field arithmetic](secp256k1-field.md)
- [Ed25519 base-field multiplication](ed25519-field.md)
- [F257 lookup arithmetic](f257.md)
- [F12289 radix arithmetic](f12289.md)
- [Multi-limb big integers](bigint.md)
- [Residue-number arithmetic](rns.md)
- [Prime logarithmic residue-number arithmetic](prime-rns.md)

## Commitments

- [Mixed-hash path commitment](hash-path-integer.md)
- [Four-way mixed-hash integer path](four-way-hash-path-integer.md)
- [Preimage-length integer](preimage-length.md)

## Introspection

- [Binohash transaction digest](binohash.md)
- [Binohash legacy core](binohash-legacy-core.md)

## Hashes and ciphers

- [SHA-1 over u32 bytes](sha1-u32.md)
- [RIPEMD-160 over u32 bytes](ripemd160-u32.md)
- [SHA-256 over u32 bytes](sha256-u32.md)
- [SHA-256 over u4 digits](sha256-u4.md)
- [BLAKE3 over tracked limbs](blake3-limb29.md)
- [BLAKE3 sparse direct-u4 short inputs](blake3-short-u4.md)
- [BLAKE3 Ed25519-style challenge transcripts](blake3-ed25519-challenge.md)
- [SHAKE256 over byte lanes](shake256-byte.md)
- [SHAKE256 byte-lane output prefixes](shake256-prefix.md)
- [AES-128 over u4 digits](aes128-u4.md)
- [Checked AES-128 AddRoundKey boundary](aes128-add-round-key.md)
- [Checked AES-128 SubBytes](aes-subbytes.md)
- [Checked AES-128 MixColumns](aes-mixcolumns.md)
- [PRINCEv2 over u4 digits](princev2-u4.md)

## Signatures and one-time authentication

- [Point locks](point-locks.md)
- [Explicit secp256k1 Schnorr verification](secp256k1-schnorr.md)
- [BLAKE3 Ed25519-style Montgomery slope verifier candidate](ed25519-blake3-montgomery-slope.md) — historical G29 hinted/q-free leaves and the G32 hybrid-u5 zero-hint successor
- [Lamport 2-bit commitment](lamport-2bit.md)
- [HORS-like HASH160 authentication](hors-hash160.md)
- [Base-16 Winternitz signatures](winternitz-base16.md)
- [Fast base-16 Winternitz signatures](winternitz-fast-base16.md)
- [Constant-composition Winternitz for 20-byte messages](winternitz-constant-composition20.md)
- [Constant-sum Winternitz for 20-byte messages](winternitz-constant-sum20.md)
- [Mixed-stage constant-sum Winternitz for 20-byte messages](winternitz-constant-sum-mixed20.md)

## Curves and pairings

- [Ed25519 fixed-base scalar multiplication](ed25519-fixed-base-scalar.md)
- [BN254 fields](bn254-fields.md)
- [BN254 groups and MSM](bn254-groups.md)
- [BN254 pairing verifier](bn254-pairing.md)
