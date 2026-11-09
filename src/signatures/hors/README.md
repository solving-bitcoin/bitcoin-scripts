# HORS-like one-time signatures

Hash-to-Obtain-Random-Subset-style one-time signatures using HASH160
commitments and explicit witness indices.

## Parameters

- `n`: number of committed preimages (`public_keys.len()`).
- `t`: revealed indices, with `t <= n`.
- Preimage length is caller-selected. No protocol-wide defaults exist; the
  documented benchmark uses `n=32`, `t=8`, and 32-byte preimages.
- `hors_locking_script` retains the original upper-clamping behavior.
  `hors_exact_index_locking_script` requires `t >= 1`, canonical ScriptNum
  bytes, indices in `0..n`, and strictly increasing order. Thus duplicates
  and reordered subsets fail. The two APIs use the same witness layout.

## Script metrics

Serialized witness size includes the witness count and item-length prefixes.

| Configuration | Locking script | Unlocking witness |
| --- | ---: | ---: |
| `n=32`, `t=8`, 32-byte preimages | <!-- metric:hors_lock_n32_t8 -->809<!-- /metric:hors_lock_n32_t8 --> bytes | <!-- metric:hors_witness_n32_t8 -->280<!-- /metric:hors_witness_n32_t8 --> bytes representative; <!-- metric:hors_witness_n32_t8_max -->281<!-- /metric:hors_witness_n32_t8_max --> bytes maximum for canonical indices `1..=8`; 16 data items, 0 hints; <!-- metric:hors_stack_n32_t8 -->50<!-- /metric:hors_stack_n32_t8 -->-item strict peak |
| `n=129`, `t=1`, index 127/128 boundary | <!-- metric:hors_lock_n129_t1 -->2792<!-- /metric:hors_lock_n129_t1 --> bytes | <!-- metric:hors_witness_n129_t1_index127 -->36<!-- /metric:hors_witness_n129_t1_index127 --> / <!-- metric:hors_witness_n129_t1_index128 -->37<!-- /metric:hors_witness_n129_t1_index128 --> bytes; 2 data items, 0 hints; <!-- metric:hors_stack_n129_t1 -->133<!-- /metric:hors_stack_n129_t1 -->-item peak |

The exact-index variant uses the same 16-item canonical opening for the
`n=32,t=8` comparison below. Every index and preimage coexist at entry; the
32 commitments are pushed afterward. Both scripts include input checks,
commitment checks, cleanup, and the terminal true. Counts use the final
policy-produced script; neither script crosses the 32 KiB optimizer cutoff.

| `n=32,t=8` index rule | Locking bytes | Serialized data witness | Combined stack peak | Executed non-push opcodes |
| --- | ---: | ---: | ---: | ---: |
| Clamped | 809 | 280 (281 max) | 50 | <!-- metric:hors_clamped_ops_n32_t8 -->145<!-- /metric:hors_clamped_ops_n32_t8 --> |
| Exact ascending | <!-- metric:hors_exact_lock_n32_t8 -->914<!-- /metric:hors_exact_lock_n32_t8 --> | <!-- metric:hors_exact_witness_n32_t8 -->280<!-- /metric:hors_exact_witness_n32_t8 --> (<!-- metric:hors_exact_witness_max_n32_t8 -->281<!-- /metric:hors_exact_witness_max_n32_t8 --> max) | <!-- metric:hors_exact_stack_n32_t8 -->51<!-- /metric:hors_exact_stack_n32_t8 --> | <!-- metric:hors_exact_ops_n32_t8 -->250<!-- /metric:hors_exact_ops_n32_t8 --> |

The comparison runs one strict local tapscript execution per script with
indices `0,4,9,13,17,21,25,31` and 32-byte preimages. Both have 16 data
items and **zero hint items** per invocation. The local result is
`locally-reproduced` and `unclassified`; it is not a Bitcoin Core spend or a
default relay policy verdict. Larger `n,t` can cross Script size, opcode, or
combined stack limits, so this row is not a bound for the full protocol.

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
`[80,00]`. The original verifier upper-clamps an oversized index with `OP_MIN`
and does not independently enforce canonical index bytes. The exact variant
checks raw bytes against their minimally re-serialized numeric value, then
checks range and increasing order. Focused tests reject nonminimal one, zero,
negative zero, and 128 even with `MINIMALDATA` disabled. Message-to-index
binding and one-time key obligations remain caller responsibilities.

The focused [alias boundary](../../../knowledge/negative-results/index.md#nr-110-clamped-hors-openings-do-not-bind-raw-binohash-indices)
test uses the same `n=32,t=8`, 32-byte-preimage configuration as the first
metric row: replacing the deepest index 31 with 32 leaves the 16-item witness
length and the successful clamped opening unchanged. The strict local
tapscript executor rejects nonminimal index encodings with `MinimalData`, but
the same bytes authenticate when that policy check is disabled. Both runs
enforce the combined 1,000-item stack limit and remain `unclassified` for
deployment, rather than consensus or relay validation. A consumer that treats
the *raw* indices as a Binohash digest must not use this clamped relation as
exact-index binding.

The exact variant closes this local alias boundary for canonical ordered
subsets. A funded Bitcoin Core spend, signed message-to-subset transform, and
complete transaction costs remain open under OP-009 and OP-011.
