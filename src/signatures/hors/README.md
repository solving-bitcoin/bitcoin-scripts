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
| `n=32`, `t=8`, 32-byte preimages | <!-- metric:hors_lock_n32_t8 -->809<!-- /metric:hors_lock_n32_t8 --> bytes | <!-- metric:hors_witness_n32_t8 -->280<!-- /metric:hors_witness_n32_t8 --> bytes representative; <!-- metric:hors_witness_n32_t8_max -->281<!-- /metric:hors_witness_n32_t8_max --> bytes maximum for canonical indices `1..=8`; 16 data items, 0 hints; <!-- metric:hors_stack_n32_t8 -->50<!-- /metric:hors_stack_n32_t8 -->-item strict peak |
| `n=129`, `t=1`, index 127/128 boundary | <!-- metric:hors_lock_n129_t1 -->2792<!-- /metric:hors_lock_n129_t1 --> bytes | <!-- metric:hors_witness_n129_t1_index127 -->36<!-- /metric:hors_witness_n129_t1_index127 --> / <!-- metric:hors_witness_n129_t1_index128 -->37<!-- /metric:hors_witness_n129_t1_index128 --> bytes; 2 data items, 0 hints; <!-- metric:hors_stack_n129_t1 -->133<!-- /metric:hors_stack_n129_t1 -->-item peak |

Maximum depth scales approximately with `n + 2t`; the executable tests include
the documented `n=32,t=8` case and boundary/malformed cases. The 32 commitment
hashes are created after the 16 witness data items are present, so they do not
all coexist at script entry.

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

No hints beyond the required signature data. The witness contains `2t` data
items—`t` indices and `t` preimages—and no hints. It contains `t`
`(index, preimage)` pairs in reverse pair order so pair zero is nearest the top;
see `hors_unlocking_witness` for canonical construction.

The host serializer crosses a byte boundary at index 128: `[7f]` becomes
`[80,00]`. The verifier upper-clamps an oversized index with `OP_MIN` and does
not independently enforce canonical index bytes; message binding and one-time
key obligations remain caller responsibilities.
