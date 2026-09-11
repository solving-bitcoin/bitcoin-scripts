# SHA-256

SHA-256 compression exposed through u32 and u4 stack representations. The
`sha2_*` prefix names the SHA-2 family implementation while this directory fixes
the concrete algorithm to SHA-256.

## Parameters

- Message length is supplied at script-generation time.
- `sha2_u32`: one byte per stack item internally; optimized paths exist for 32
  and 80 bytes. The documented default is 32 bytes.
- `sha2_u4`: two nibbles per input byte and optional addition-table use chosen
  from the block count. The documented default is 32 bytes.
- `sha256_80bytes_from_midstate`: one fixed 64-byte prefix is represented by a
  caller-supplied chaining state; the fragment consumes the remaining 16 bytes
  as 32 u4 witness items.
- `sha2_u4_stack`: the tracked-stack generator additionally selects addition
  tables and full/half XOR tables; defaults in its size tests are enabled.

## Script metrics

Sizes are hashing fragments only. They exclude message pushes/witness bytes and
output comparison.

| Implementation | 32-byte input script |
| --- | ---: |
| `sha2_u32` | <!-- metric:sha2_u32_32 -->512428<!-- /metric:sha2_u32_32 --> bytes |
| `sha2_u4` | <!-- metric:sha2_u4_32 -->332942<!-- /metric:sha2_u4_32 --> bytes |

The u4 midstate continuation has a separate fixed-shape boundary:

| Configuration | Locking script | Unlocking witness | Combined peak | Static non-push opcodes |
| --- | ---: | ---: | ---: | ---: |
| 64-byte prefix midstate + 16-byte suffix | <!-- metric:sha2_u4_80_midstate -->332830<!-- /metric:sha2_u4_80_midstate --> bytes | <!-- metric:sha2_u4_80_midstate_witness -->48<!-- /metric:sha2_u4_80_midstate_witness --> bytes | <!-- metric:sha2_u4_80_midstate_stack -->969<!-- /metric:sha2_u4_80_midstate_stack --> items | <!-- metric:sha2_u4_80_midstate_opcodes -->195219<!-- /metric:sha2_u4_80_midstate_opcodes --> |

All reported hashing fragments exceed the repository optimizer's 32 KiB input
cutoff and are reported unoptimized. The midstate row is a research boundary:
its state is not authenticated against the fixed prefix by the fragment.
Strict local execution passes at the measured 969-item peak; complete
deployment remains unclassified because the fragment exceeds ordinary script
size and policy limits.

Maximum stack depth depends on input length and implementation. The
`sha2_u4_stack` generator records it with `StackTracker`; executable hash tests
cover the u32 and u4 layouts.

## Security

SHA-256 provides a 256-bit output, with generic 128-bit collision resistance
and 256-bit preimage/second-preimage resistance. These claims assume canonical
SHA-256 use; they do not authenticate witness data by themselves.

## Script compatibility and standardness

The opcode vocabulary is shared by legacy script and tapscript, but the
generated scripts are large and operation-heavy. Practical use is tapscript or
research execution; many configurations exceed P2SH/P2WSH/bare policy or
legacy limits. The caller must append output verification and cleanstack logic.

## Witness and hints

No hints are required. `sha2_u32` consumes one stack item per byte;
`sha2_u4` consumes two canonical nibbles per byte in the order documented by
the push helpers. The midstate continuation consumes 32 canonical nibble items,
and the caller must bind its eight-word state to the intended 64-byte prefix.
