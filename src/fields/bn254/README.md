# BN254 fields

The currently recorded implementation is [`bigint29`](bigint29/), containing
`Fq`, `Fr`, and the `Fq2`/`Fq6`/`Fq12` extension tower over nine little-endian
limbs. The BN254 group and pairing modules consume this field backend from
[`../../curves/bn254`](../../curves/bn254/).

The backend name is intentionally present in the public path. A future RNS or
different-limb implementation can be added beside `bigint29` with separate
documentation and metrics instead of being mixed into one module.
