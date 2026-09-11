# SHA-256

SHA-256 compression exposed through u32 and u4 stack representations. The
`sha2_*` prefix names the SHA-2 family implementation while this directory fixes
the concrete algorithm to SHA-256.

## Parameters

- Message length is supplied at script-generation time.
- `sha2_u32`: one byte per stack item internally; optimized paths exist for 32
  and 80 bytes. `sha256_80bytes_from_midstate` continues a fixed 64-byte
  prefix from its caller-supplied midstate using a 16-byte suffix. The
  documented default is 32 bytes.
- `sha2_u4`: two nibbles per input byte and optional addition-table use chosen
  from the block count. The documented default is 32 bytes.
- `sha2_u4_stack`: the tracked-stack generator additionally selects addition
  tables and full/half XOR tables; defaults in its size tests are enabled.

## Script metrics

Sizes are hashing fragments only. They exclude message pushes/witness bytes and
output comparison.

| Implementation | 32-byte input script |
| --- | ---: |
| `sha2_u32` | <!-- metric:sha2_u32_32 -->512428<!-- /metric:sha2_u32_32 --> bytes |
| `sha2_u4` | <!-- metric:sha2_u4_32 -->332942<!-- /metric:sha2_u4_32 --> bytes |

The midstate continuation is a separate fixed-shape fragment:

| Configuration | Locking script | Unlocking witness | Maximum stack items |
| --- | ---: | ---: | ---: |
| 64-byte prefix midstate + 16-byte suffix | <!-- metric:sha2_u32_80_midstate -->530631<!-- /metric:sha2_u32_80_midstate --> bytes | <!-- metric:sha2_u32_80_midstate_witness -->33<!-- /metric:sha2_u32_80_midstate_witness --> bytes | <!-- metric:sha2_u32_80_midstate_stack -->856<!-- /metric:sha2_u32_80_midstate_stack --> |

The reported hashing fragments exceed the repository optimizer's 32 KiB input
cutoff and are unoptimized. The midstate stack figure includes the 32-item
digest cleanup and terminal predicate shown in the composition wrapper.

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
the push helpers. The midstate continuation consumes exactly 16 byte-valued
suffix items. Its midstate must be bound by the caller to the intended fixed
64-byte prefix; the fragment does not prove that relationship.
