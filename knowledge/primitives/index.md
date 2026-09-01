# Primitive entries

Each page describes one construction family or representation. Exact measured
configurations live in `../catalog.json`; implementation details remain beside
the source. Read a page together with its comparison page and evidence record.

## Arithmetic

- [ScriptNum constant multiplication](scriptnum-constant-mul.md)
- [Hinted ScriptNum division](scriptnum-hinted-div.md)
- [u4 digit arithmetic](u4.md)
- [u32 word arithmetic](u32.md)
- [u31 prime-field arithmetic](u31.md)
- [F257 lookup arithmetic](f257.md)
- [F12289 radix arithmetic](f12289.md)
- [Multi-limb big integers](bigint.md)
- [Residue-number arithmetic](rns.md)
- [Prime logarithmic residue-number arithmetic](prime-rns.md)

## Commitments

- [Mixed-hash integer path](hash-path-integer.md)
- [Preimage-length integer](preimage-length.md)
- [Binohash transaction digest](binohash.md)

## Hashes and ciphers

- [SHA-1 over u32 bytes](sha1-u32.md)
- [RIPEMD-160 over u32 bytes](ripemd160-u32.md)
- [SHA-256 over u32 bytes](sha256-u32.md)
- [SHA-256 over u4 digits](sha256-u4.md)
- [BLAKE3 over tracked limbs](blake3-limb29.md)
- [SHAKE256 over byte lanes](shake256-byte.md)
- [AES-128 over u4 digits](aes128-u4.md)
- [PRINCEv2 over u4 digits](princev2-u4.md)

## One-time authentication

- [Lamport 2-bit commitment](lamport-2bit.md)
- [HORS-like HASH160 authentication](hors-hash160.md)
- [Base-16 Winternitz signatures](winternitz-base16.md)

## Curves and pairings

- [BN254 fields](bn254-fields.md)
- [BN254 groups and MSM](bn254-groups.md)
- [BN254 pairing verifier](bn254-pairing.md)
