# BLAKE3 keyed-mode boundary

The local BLAKE3 generators implement unkeyed 32-byte hashing only. A
deterministic probe over the 32-byte message `00 01 ... 1f` and a 32-byte
`0x42` key confirms that the standard keyed digest differs from the unkeyed
digest, while the current generator exposes no key input or keyed-mode flag.

This is an interface boundary, not an impossibility proof. Supporting keyed
mode requires pricing the key's eight words, the `KEYED_HASH` flags, witness
shape, and the resulting stack/routing changes. Evidence is
`locally-reproduced`; see [the probe](../../examples/blake3_keyed_boundary.rs)
and [OP-023](../open-problems.md#op-023--blake3-keyed-mode-frontier).
