# secp256k1 base field

Two implementations share the modulus
`p = 2^256 - 2^32 - 977` but use incompatible certificates and stack layouts.

| Backend | Representation | Certified multiplication | Use when |
| --- | --- | ---: | --- |
| [`bigint9`](bigint9/) | 29 balanced radix-512 digits, ordinary domain | 20,500 bytes | values stay in the native digit representation |
| [`bigint9::factor16`](bigint9/factor16/) | 29 balanced radix-512 digits, `x/16` domain | 20,447 bytes | an entire multiplication region stays factor-16 encoded |
| [`rns`](rns/) | 46 canonical prime residues | 31,257 bytes | an RNS certificate can be reused across a larger residue circuit |

The sizes are orientation only. Conversion, certificate fan-out, setup,
cleanup, and circuit routing must be included before treating them as a
like-for-like system comparison. Neither backend is re-exported at the field
root; callers must select one explicitly. The two bigint9 profiles share a
product core but have different hint and semantic contracts, so their detailed
documentation is kept separate.
