# Preimage-length commitments

Authenticate a SHA-256 preimage and return its byte length minus a public offset.

## Parameters

The digest is 32 bytes. `offset` is in `0..=520`, defaults to 16 with
`verify_preimage_length`, and is explicit with `verify_preimage_length_with_offset`.
The opening length must be in `offset..=520`.

## Script metrics

Metrics are fragment-only: input pushes and the caller's output predicate are
excluded; witness bytes include CompactSize item counts and lengths. Sizes use
`compile_with_policy()` with optimization enabled. Stack peaks combine main
and alt stacks. Metric execution uses bitcoin-scriptexec
`702544c9a045ac4fc14846da6da6559e2b7cd9d1` in tapscript mode with the stack
limit disabled (`research-unlimited`). The offset-boundary rows use strict local
stack checks (`unclassified`); neither row is Core consensus or relay-policy
validation.

| Fragment | Locking script | Unlocking witness | Maximum stack items |
| --- | ---: | ---: | ---: |
| `verify_preimage_length(commitment)` | <!-- metric:preimage_length_default -->44<!-- /metric:preimage_length_default --> bytes | <!-- metric:preimage_length_witness_min -->18<!-- /metric:preimage_length_witness_min -->–<!-- metric:preimage_length_witness_max -->524<!-- /metric:preimage_length_witness_max --> bytes (16–520-byte preimage) | <!-- metric:preimage_length_stack -->3<!-- /metric:preimage_length_stack --> |
| `verify_preimage_length_with_offset(commitment, 0)` | <!-- metric:preimage_length_offset0 -->42<!-- /metric:preimage_length_offset0 --> bytes | <!-- metric:preimage_length_offset0_witness -->2<!-- /metric:preimage_length_offset0_witness --> bytes, 1 empty preimage item, 0 hints | <!-- metric:preimage_length_offset0_stack -->3<!-- /metric:preimage_length_offset0_stack --> |
| `verify_preimage_length_with_offset(commitment, 520)` | <!-- metric:preimage_length_offset520 -->46<!-- /metric:preimage_length_offset520 --> bytes | <!-- metric:preimage_length_offset520_witness -->524<!-- /metric:preimage_length_offset520_witness --> bytes, 1 data item, 0 hints | <!-- metric:preimage_length_offset520_stack -->3<!-- /metric:preimage_length_offset520_stack --> |

## Security

SHA-256 gives generic bounds of 128-bit collision and 256-bit preimage
resistance. Hiding depends on unpredictable preimage bytes; length is revealed
when opening. No one-time key is required.

## Script compatibility and standardness

The fragment uses opcodes available in bare script, P2SH, P2WSH and tapscript
and fits their size/opcode limits. A full spending predicate is still needed;
custom bare outputs are non-standard. The 520-byte preimage boundary is a
consensus stack-item limit, not a relay policy claim; policy profiles may impose
an 80-byte witness-item limit. See [script types](../../../docs/script-types.md) and
[standardness](../../../docs/standardness.md).

## Witness and hints

One preimage data item, present at entry; **0 hint items**. The measured peak
is three combined stack items; unrelated live protocol state also counts
toward 1,000.

## Stack contract

`... preimage -> ... length_minus_offset`. Consumes the preimage and leaves a
non-negative integer; append an application predicate for clean truthy success.
No altstack use.

## Operational notes

Tests include offset boundaries, too-short preimages, wrong openings and zero
results. The encoded integer range is coupled to the 520-byte item limit.

## Knowledge-base integration

See [the knowledge page](../../../knowledge/primitives/preimage-length.md),
[comparison](../../../knowledge/comparisons/commitments.md), and catalog record
`commitment/preimage-length`.
