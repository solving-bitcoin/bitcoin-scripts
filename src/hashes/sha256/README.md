# SHA-256

SHA-256 compression exposed through u32 and u4 stack representations. The
`sha2_*` prefix names the SHA-2 family implementation while this directory fixes
the concrete algorithm to SHA-256.

## Parameters

- Message length is supplied at script-generation time.
- `sha2_u32`: one byte per stack item internally; optimized paths exist for 32
  and 80 bytes. `sha256_80bytes_from_midstate` continues a fixed 64-byte
  prefix from its caller-supplied chaining state using a 16-byte suffix and a
  final SHA-256 length field of 640 bits. `sha256_tagged_hash_32bytes` provides
  BIP340-style tagged hashing for a fixed 32-byte message. The documented
  default is 32 bytes.
- `sha2_u4`: two nibbles per input byte and optional addition-table use chosen
  from the block count. The documented default is 32 bytes.
- `sha256_80bytes_from_midstate`: one fixed 64-byte prefix is represented by a
  caller-supplied chaining state; the u4 fragment consumes the remaining 16
  bytes as 32 nibble witness items. Both backends require exactly the 16-byte
  suffix; the fragment does not authenticate the supplied state.
- `sha2_u4_stack`: the tracked-stack generator additionally selects addition
  tables and full/half XOR tables; defaults in its size tests are enabled.

## Script metrics

Sizes are hashing fragments only. They exclude message pushes/witness bytes and
output comparison.

| Implementation | 32-byte input script |
| --- | ---: |
| `sha2_u32` | <!-- metric:sha2_u32_32 -->512428<!-- /metric:sha2_u32_32 --> bytes |
| `sha2_u4` | <!-- metric:sha2_u4_32 -->332942<!-- /metric:sha2_u4_32 --> bytes |

The tagged-hash fragment precomputes the constant 64-byte `tag_hash ||
tag_hash` block and measures the final whole continuation fragment:

| Configuration | Locking script | Unlocking witness | Strict stack peak |
| --- | ---: | ---: | ---: |
| BIP340 challenge tag + 32-byte message | <!-- metric:sha2_u32_tagged_32 -->530755<!-- /metric:sha2_u32_tagged_32 --> bytes | <!-- metric:sha2_u32_tagged_32_witness -->65<!-- /metric:sha2_u32_tagged_32_witness --> bytes | <!-- metric:sha2_u32_tagged_32_stack -->856<!-- /metric:sha2_u32_tagged_32_stack --> items |

The representative witness has 32 byte-valued message items (65 serialized
bytes); the canonical numeric-byte maximum is 97 bytes. The fragment uses no
auxiliary hint items, consumes exactly those 32 message items, and encodes the
final 768-bit SHA-256 length. It is BIP340-style tagged hashing of a payload,
not the complete BIP340 challenge computation.

The `sha2_u4` multi-chunk path reuses its 16-entry row-offset lookup table
while replacing the 136-entry XOR/AND table between chunks. For an 80-byte
two-chunk message this saves 11 bytes over reloading the unchanged lookup
table:

| Profile | Script bytes | Witness bytes | Hints | Strict peak | Fragment opcodes |
| --- | ---: | ---: | ---: | ---: | ---: |
| `sha2_u4(80)` with shared lookup | <!-- metric:sha2_u4_80_shared_lookup -->736595<!-- /metric:sha2_u4_80_shared_lookup --> | <!-- metric:sha2_u4_80_shared_lookup_witness -->161<!-- /metric:sha2_u4_80_shared_lookup_witness --> | <!-- metric:sha2_u4_80_shared_lookup_hints -->0<!-- /metric:sha2_u4_80_shared_lookup_hints --> | <!-- metric:sha2_u4_80_shared_lookup_stack -->905<!-- /metric:sha2_u4_80_shared_lookup_stack --> | <!-- metric:sha2_u4_80_shared_lookup_opcodes -->594466<!-- /metric:sha2_u4_80_shared_lookup_opcodes --> |

The profile uses 160 complete data items for the 80 message nibbles and no
auxiliary hints; padding, output cleanup, and the terminal predicate are
outside the fragment byte count. The strict run is local `bitcoin-scriptexec`
evidence only and does not establish consensus or relay-policy deployment.

Both fragments exceed the repository optimizer's 32 KiB input cutoff and are
reported unoptimized.

The SHA-256 midstate continuation is a separate fixed-shape fragment:

| Configuration | Locking script | Unlocking witness | Maximum stack items |
| --- | ---: | ---: | ---: |
| 64-byte prefix midstate + 16-byte suffix | <!-- metric:sha2_u32_80_midstate -->530686<!-- /metric:sha2_u32_80_midstate --> bytes | <!-- metric:sha2_u32_80_midstate_witness -->33<!-- /metric:sha2_u32_80_midstate_witness --> bytes | <!-- metric:sha2_u32_80_midstate_stack -->856<!-- /metric:sha2_u32_80_midstate_stack --> |

The representative u32 witness is 16 one-byte items (33 serialized bytes); the
canonical maximum is 49 bytes when each byte uses a two-byte ScriptNum. The
stack figure uses empty zero-value suffix items in the composition wrapper. The
caller must bind the supplied chaining state to the fixed prefix; the fragment
does not prove that relation.

The u4 midstate continuation has a separate fixed-shape boundary:

| Configuration | Locking script | Unlocking witness | Combined peak | Static non-push opcodes |
| --- | ---: | ---: | ---: | ---: |
| 64-byte prefix midstate + 16-byte suffix | <!-- metric:sha2_u4_80_midstate -->332830<!-- /metric:sha2_u4_80_midstate --> bytes | <!-- metric:sha2_u4_80_midstate_witness -->48<!-- /metric:sha2_u4_80_midstate_witness --> bytes | <!-- metric:sha2_u4_80_midstate_stack -->969<!-- /metric:sha2_u4_80_midstate_stack --> items | <!-- metric:sha2_u4_80_midstate_opcodes -->195219<!-- /metric:sha2_u4_80_midstate_opcodes --> |

The representative u4 witness is 32 nibble items (48 serialized bytes); the
canonical maximum is 65 bytes. The stack figure uses empty zero-value suffix
items in the strict composition wrapper. No auxiliary hint items are used.
The row is a research boundary: its state is not authenticated against the
fixed prefix by the fragment, and complete deployment remains unclassified.

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
the push helpers. The u32 midstate continuation consumes exactly 16 byte-valued
suffix items; the u4 continuation consumes 32 canonical nibble items. Tagged
hashing supplies its tag block as generation-time script data.
