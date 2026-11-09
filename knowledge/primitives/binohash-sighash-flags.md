# Binohash raw legacy sighash-byte census

The Binohash paper treats the ECDSA sighash byte as an additional degree of
freedom. The [checked Core fixture](../../research/binohash-sighash-flags/README.md)
isolates that premise: a fixed host-side transaction template yields 256
distinct local digests for byte values `0x00..0xff`. Separately, 256
independently funded one-input P2SH spends, one signed for each flag byte, are
accepted together in a pinned Bitcoin Core v30.3 block. A signature made for
`0x01` fails consensus if only its trailing byte is changed to `0x21`.

Default relay policy accepts exactly the six canonical flags `01`, `02`,
`03`, `81`, `82`, and `83`; the other 250 are rejected under `STRICTENC` as
`Signature hash type missing or not understood`. The complete locking
scriptPubKey is 23 bytes, the redeemScript is 35 bytes, and the 256 complete
spends weigh 804–812 WU. The canonical `01` representative weighs 808 WU.
There are zero witness and hint items. Combined stack peak and executed
opcodes are not measured.

The result is `differentially-validated` and `consensus-validated` for all 256
spends; only the six canonical configurations are `policy-validated` under
the documented node options. The fixture uses a plain `OP_CHECKSIG`, with no
embedded-signature deletion, subset grind, pinning puzzle, or downstream
digest consumer. Distinct digests for a fixed template do not imply
independent or usable entropy in a full Binohash construction. The
[reported full protocol](binohash.md) and `OP-011` remain open.
