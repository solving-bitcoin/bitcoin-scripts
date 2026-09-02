# BLAKE3

BLAKE3 hashing implemented with tracked-stack u4/bigint machinery. Generated
compute scripts are run through the pinned `bitcoin-script-stack` peephole
optimizer to a fixed point.

Two input profiles are public:

- `blake3_short_compute_script` is the script-minimized profile for a
  witness-backed message of `0..=32` bytes. It consumes exactly two numeric u4
  items per byte and synthesizes all padding internally.
- `blake3_compute_script_with_limb` supports `0..=1024` bytes with two
  selected-limb 256-bit groups per block. Limb width is `4..=31`; the
  compatibility wrapper uses 29-bit limbs.

Both profiles implement unkeyed 32-byte hashing only. Keyed mode, derive-key
mode, XOF output, and the multi-chunk tree API are not implemented.

## Short-input specialization

The short profile keeps only message words that overlap the declared input.
Absent zero words are omitted from every round instead of being materialized on
the stack. In the first round, entirely constant column calls are evaluated by
the Rust generator, while active columns combine literal initial-state words
with the live input and fixed XOR-table rows. Addition queries reuse one
absolute index against an interleaved modulo/carry table; a separate
modulo-only table handles the discarded most-significant carry. Constant
first-column additions fold literal nibbles into the table address. G-call
order is selected at generation time, and the 32-byte layout permutes physical
input words to match the final consuming round.

These are generator transformations: they do not change BLAKE3's seven-round
compression function or remove validation from witness-backed digits.

## Script metrics

The compute metrics are `fragment-with-memory`. They include input range
validation and any representation conversion, 458 bytes of lookup-table setup,
hashing, 216 bytes of table cleanup, and digest restoration. They exclude
input pushes or witness serialization and digest comparison.

| Configuration | Compute script |
| --- | ---: |
| Empty message, 29-bit API | <!-- metric:blake3_empty_limb29 -->64<!-- /metric:blake3_empty_limb29 --> bytes |
| 1 byte, direct checked u4 | <!-- metric:blake3_short_1 -->56292<!-- /metric:blake3_short_1 --> bytes |
| 32 bytes, direct checked u4 | <!-- metric:blake3_short_32 -->61074<!-- /metric:blake3_short_32 --> bytes |
| 32 bytes, selected 4-bit limbs | <!-- metric:blake3_32_limb4 -->61383<!-- /metric:blake3_32_limb4 --> bytes |
| 64 bytes, 4-bit limbs | <!-- metric:blake3_64_limb4 -->64275<!-- /metric:blake3_64_limb4 --> bytes |
| 64 bytes, 29-bit limbs | <!-- metric:blake3_64_limb29 -->72469<!-- /metric:blake3_64_limb29 --> bytes |

For the deterministic 32-byte message `00 01 ... 1f`, direct host-side message
pushes are <!-- metric:blake3_push_short_32 -->64<!-- /metric:blake3_push_short_32 -->
bytes. The push, compute fragment, and 128-byte digest comparison compose to
<!-- metric:blake3_complete_short_32 -->61266<!-- /metric:blake3_complete_short_32 -->
bytes. Encoding the same nibbles as canonical witness items takes
<!-- metric:blake3_witness_short_32 -->111<!-- /metric:blake3_witness_short_32 -->
serialized bytes; the valid 64-item maximum is
<!-- metric:blake3_witness_short_32_max -->129<!-- /metric:blake3_witness_short_32_max -->
bytes. The compute fragment contains
<!-- metric:blake3_opcodes_short_32 -->41190<!-- /metric:blake3_opcodes_short_32 -->
static non-push opcodes, and the executable composition peaks at
<!-- metric:blake3_stack_short_32 -->628<!-- /metric:blake3_stack_short_32 -->
combined main/altstack items.

The corresponding 32-byte selected-limb helper composition peaks at
<!-- metric:blake3_stack_32_limb4 -->628<!-- /metric:blake3_stack_32_limb4 -->
items. Direct u4 therefore saves 309 compute bytes on the final shared core and
uses 64 rather than 128 host-push bytes.

For the deterministic 64-byte message `00 01 ... 3f`, host-side 29-bit message
packing is <!-- metric:blake3_push_64_limb29 -->87<!-- /metric:blake3_push_64_limb29 -->
bytes and digest comparison is
<!-- metric:blake3_verify_output -->128<!-- /metric:blake3_verify_output -->
bytes. Their executable composition with the 64-byte compute fragment is
<!-- metric:blake3_complete_64_limb29 -->72684<!-- /metric:blake3_complete_64_limb29 -->
bytes. The compute fragment contains
<!-- metric:blake3_opcodes_64_limb29 -->47624<!-- /metric:blake3_opcodes_64_limb29 -->
static non-push opcodes; the composition peaks at
<!-- metric:blake3_stack_64_limb29 -->692<!-- /metric:blake3_stack_64_limb29 -->
items.

The helper compositions embed messages and expected digests in the script;
they are deterministic regression fixtures rather than proof-boundary cost
claims. The local strict-stack test executes every direct-input length from 0
through 32 and enforces the 1,000-item limit. This is not a Bitcoin Core
consensus or policy reproduction, so both profiles remain
`research-unlimited`.

## Direct u4 witness layout

`blake3_short_compute_script(n)` requires exactly `2*n` numeric items and
rejects extra main-stack state. Each byte is represented by its high nibble and
then low nibble. Within each four-byte BLAKE3 word, bytes are supplied in reverse
order. For lengths below 32 bytes, words remain in semantic order.

For exactly 32 bytes, let `w0..w7` be the consecutive four-byte words. Their
physical push order is `w2,w4,w3,w7,w6,w1,w0,w5`; this is an internal
stack-routing optimization. `blake3_short_message_witness` emits minimally
encoded witness items, and `blake3_push_short_message_script` emits the same
layout as script constants; either helper should be preferred over hand
encoding.

Every supplied item is checked as a ScriptNum in `[0, 16)` before it can address
lookup memory. This establishes numeric bounds, not a protocol-level byte
serialization rule; callers that commit to raw encodings must enforce their
own canonicality boundary. The message length is fixed when the script is
generated and must be bound by the surrounding protocol when it is selected
dynamically.

The selected-limb profile range-validates every witness limb that overlaps the
declared message. When the final block has at most 32 message bytes, its second
256-bit group is wholly padding: that profile drops the group without
validation and synthesizes zeros, so callers must not treat ignored values as
bound data. The direct profile has no ignored padding input.

## Security and compatibility

The 256-bit BLAKE3 output has generic 128-bit collision resistance and 256-bit
preimage/second-preimage resistance. Only the single-chunk-tree range supported
by this implementation is in scope.

Generated scripts are far beyond ordinary standard output templates. Treat
them as tapscript research fragments. A complete caller must compare the digest
and leave a clean truthy result; P2SH, P2WSH, and bare deployment are generally
unsuitable.
