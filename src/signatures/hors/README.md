# HORS-like one-time signatures

Hash-to-Obtain-Random-Subset-style one-time signatures using HASH160
commitments and explicit witness indices.

## Parameters

- `n`: number of committed preimages (`public_keys.len()`).
- `t`: revealed indices, with `t <= n`.
- Preimage length is caller-selected. No protocol-wide defaults exist; the
  documented benchmark uses `n=32`, `t=8`, and 32-byte preimages.

## Script metrics

Serialized witness size includes the witness count and item-length prefixes.

| Configuration | Locking script | Unlocking witness |
| --- | ---: | ---: |
| `n=32`, `t=8`, 32-byte preimages | <!-- metric:hors_lock_n32_t8 -->809<!-- /metric:hors_lock_n32_t8 --> bytes | <!-- metric:hors_witness_n32_t8 -->280<!-- /metric:hors_witness_n32_t8 --> bytes |

Maximum depth scales approximately with `n + 2t`; the executable tests include
the documented `n=32,t=8` case and boundary/malformed cases.

## Security

One-time only. Concrete forgery probability depends on `n`, `t`, the message-to-
subset procedure used by the caller, and prior disclosures. HASH160 bounds each
commitment to at most 80-bit collision and 160-bit preimage resistance. The
module does not itself derive indices from a message.

## Script compatibility and standardness

Opcode-compatible with legacy script and tapscript. Size grows linearly in `n`
and work grows with `t`; larger choices can exceed P2SH/P2WSH/bare policy or
legacy opcode limits. The locking helper cleans up commitments and leaves true
for the exact documented witness.

## Witness and hints

No hints beyond the required signature data. The witness contains `t`
`(index, preimage)` pairs in reverse pair order so pair zero is nearest the top;
see `hors_unlocking_witness` for canonical construction.
