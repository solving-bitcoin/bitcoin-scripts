# u32 arithmetic

Unsigned 32-bit arithmetic represented as four 8-bit Script integers, most
significant byte first. Operations use Script integer opcodes on each byte;
they do not use BN254 or any other field modulus.

## Parameters

- Word width is fixed at 32 bits and limb width is fixed at 8 bits.
- Word offsets are zero-based stack depths: `0` is the top u32 word, `1` is
  the word below it, and so on.
- `u32_add[_drop](a, b)` accepts two distinct word offsets and wraps modulo
  `2^32`. The non-`drop` form preserves the word selected by `a`.
- `u32_sub[_drop](a, b)` computes `a - b` modulo `2^32` for either ordering of
  two distinct offsets. The non-`drop` form preserves the minuend.
- `u32_{less,greater}than[orequal]()` compares the top two words as unsigned
  integers and consumes both.
- `u32_or(a, b, stack_size)`, like XOR and AND, takes distinct word offsets.
  `stack_size` is one plus the number of u32 words above the shared byte-logic
  table. With exactly two working words, the usual value is `3`.
- Stack helpers use whole-word offsets. Rotation helpers additionally take a
  rotation count. There are no implicit parameter defaults.

## Script metrics

These are serialized locking-script fragment sizes. The maximum stack column
is measured by executing the fragment with its two input words; OR also
includes the required 256-item shared logic table. Strict greater-than has the
same metrics as strict less-than, and greater-than-or-equal has the same metrics
as less-than-or-equal.

| Fragment | Locking script | Auxiliary unlocking hints | Maximum main-stack depth |
| --- | ---: | ---: | ---: |
| `u32_add_drop(0, 1)` | <!-- metric:u32_add_drop -->78<!-- /metric:u32_add_drop --> bytes | 0 bytes | <!-- metric:u32_add_drop_stack -->10<!-- /metric:u32_add_drop_stack --> items |
| `u32_sub_drop(0, 1)` | <!-- metric:u32_sub_drop -->77<!-- /metric:u32_sub_drop --> bytes | 0 bytes | <!-- metric:u32_sub_drop_stack -->9<!-- /metric:u32_sub_drop_stack --> items |
| `u32_lessthan()` | <!-- metric:u32_lessthan -->38<!-- /metric:u32_lessthan --> bytes | 0 bytes | <!-- metric:u32_lessthan_stack -->9<!-- /metric:u32_lessthan_stack --> items |
| `u32_lessthanorequal()` | <!-- metric:u32_lessthanorequal -->61<!-- /metric:u32_lessthanorequal --> bytes | 0 bytes | <!-- metric:u32_lessthanorequal_stack -->13<!-- /metric:u32_lessthanorequal_stack --> items |
| `u32_or(0, 1, 3)` (table excluded) | <!-- metric:u32_or -->326<!-- /metric:u32_or --> bytes | 0 bytes | <!-- metric:u32_or_stack -->272<!-- /metric:u32_or_stack --> items, including table |
| `u32_notequal()` | <!-- metric:u32_notequal -->19<!-- /metric:u32_notequal --> bytes | 0 bytes | <!-- metric:u32_notequal_stack -->9<!-- /metric:u32_notequal_stack --> items |
| `u8_push_xor_table()` | <!-- metric:u8_logic_table_push -->236<!-- /metric:u8_logic_table_push --> bytes | 0 bytes | 256 table items |
| `u8_drop_xor_table()` | <!-- metric:u8_logic_table_drop -->128<!-- /metric:u8_logic_table_drop --> bytes | 0 bytes | consumes 256 table items |

Operand witness serialization is deliberately excluded: callers may construct
words inside the locking script or supply four witness items per word. No
operation-specific hint is needed. The logic table can be shared by any number
of XOR, AND, and OR operations in one script.

## Total-domain compressed logical right shift

`u32_compressed_rshift(shift)` accepts one exact compressed u32 ScriptNum,
including the canonical five-byte encoding of `0x80000000`, and returns the
compressed ScriptNum for the logical result. It rejects non-minimal encodings,
negative zero, wrong-width items, and five-byte values other than `-2^31`.
Internally it expands to four bytes, uses the existing rotation and shared
byte-AND table, then recompresses. The four-byte operation is retained as the
like-for-like witness-width baseline.

The representative rows use shift 7, the deterministic value `0xa5c319e7`,
strict local tapscript execution, and include table setup/cleanup, canonical
input validation, output compression, and a terminal `OP_TRUE`; witness input
pushes are excluded from locking-script bytes. Both rows require zero
auxiliary hint items.

| Configuration | Locking script | Witness | Complete items | Peak stack | Static non-push opcodes |
| --- | ---: | ---: | ---: | ---: | ---: |
| Compressed one-item wire | <!-- metric:u32_rshift_compressed_7 -->1143<!-- /metric:u32_rshift_compressed_7 --> bytes | <!-- metric:u32_rshift_compressed_7_witness -->6<!-- /metric:u32_rshift_compressed_7_witness --> bytes | 1 | <!-- metric:u32_rshift_compressed_7_stack -->272<!-- /metric:u32_rshift_compressed_7_stack --> | <!-- metric:u32_rshift_compressed_7_static_opcodes -->863<!-- /metric:u32_rshift_compressed_7_static_opcodes --> |
| Four-byte u32 baseline | <!-- metric:u32_rshift_bytes_7 -->637<!-- /metric:u32_rshift_bytes_7 --> bytes | <!-- metric:u32_rshift_bytes_7_witness -->12<!-- /metric:u32_rshift_bytes_7_witness --> bytes | 4 | <!-- metric:u32_rshift_bytes_7_stack -->272<!-- /metric:u32_rshift_bytes_7_stack --> | <!-- metric:u32_rshift_bytes_7_static_opcodes -->473<!-- /metric:u32_rshift_bytes_7_static_opcodes --> |

The compressed wire trades locking-script bytes and execution work for three
fewer entry witness items. This is a representation primitive, not a complete
leaf or a consensus/deployability claim.

The local executor did not expose a useful dynamic opcode count for this
standalone fragment, so static non-push counts are reported instead; no
validation-weight result is claimed.

## Security

There is no independent cryptographic security parameter. Arithmetic is exact
only for byte limbs in `0..=255`; callers accepting adversarial witness values
must enforce limb range and canonical Script-number encoding where required.

## Script compatibility and standardness

The fragments use opcodes available in both legacy Script and tapscript.
Arithmetic and comparison fragments can be embedded in tapscript, P2WSH,
P2SH, or a bare script subject to the complete script's size and opcode limits.
Table-backed logic is intended for tapscript: a standalone OR plus table setup
and cleanup is 690 bytes and its legacy non-push opcode count exceeds the
201-opcode limit, so it is not valid in P2SH or P2WSH as a single script. Bare
use is consensus-valid when limits are met but violates standard output-template
policy. Cleanstack is not provided by a fragment and must be enforced by its
caller.

## Witness and hints

No hints are required. A witness-supplied word occupies four stack items, most
significant byte first in the module's normal representation. Binary operation
inputs and any shared logic table must already be at the documented depths.
