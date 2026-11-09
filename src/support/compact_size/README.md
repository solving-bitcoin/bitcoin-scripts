# CompactSize through 65,535 from separate raw byte items

Decode one canonical CompactSize token whose constituent bytes are
separate hostile stack items. Accept the single-byte form and the
three-byte form, and return one canonical numeric ScriptNum.

## Parameters and stack contract

`decode_compact_size_u16_from_raw_items()` has no public parameters.
The top item is the raw prefix. When it is `fd`, the low byte is
immediately beneath it and the high byte is below that. Every
constituent is an exact one-byte vector. With stacks written bottom
to top, the input is either `prefix` or `high low fd` and the
output is one canonical ScriptNum in `0..=65535`. The caller
supplies the exact token suffix, preserves any deeper state, and
consumes or verifies the result before leaving a clean stack.

The prefix `fd` is matched by byte equality. Three-byte values
less than 253 fail verification, as do the larger-form prefixes
`fe` and `ff`. The decoder explicitly recognizes raw `00` and
`80` before doing arithmetic. Other low-half bytes are already
canonical positive ScriptNums. For a high-half byte other than
`80`, the signed ScriptNum is negative, and subtracting it
from 128 yields the unsigned value. The long branch computes
`low + 256*high` using the existing constant multiplier.

There are exactly one or three ordinary data items at entry,
depending on the prefix. There are no hints. Both caller stacks
survive a valid exact suffix. The raw schedule peaks at three or five
combined items for the short or long form. The long form reaches the
1,000-item limit with 995 preserved items and rejects one more.
The fragment expects separate stack items. A contiguous raw byte
vector requires its own parser.

## Script metrics

Both policy-compiled leaves check canonical CompactSize semantics,
verify the same numeric output, and leave one true item. The
[numeric-byte baseline](../../../research/compactsize-raw-decoder/baseline.rs)
encodes each logical byte as a canonical ScriptNum and shares
the same dispatch and minimum-size checks. The input encodings
are different. Values come from deterministic host CompactSize
serialization. Data witness bytes include CompactSize item count
and item-length prefixes. They exclude the leaf, control block,
annex, and transaction. The trace counts executed non-push
instructions and branch delimiters encountered by the interpreter.

| Value | Logical wire bytes | Encoding | Leaf bytes | Data witness bytes | Ordinary items | Hint items (serialized bytes) | Combined peak | Executed non-push ops |
| ---: | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 0 | `00` | Raw byte items | <!-- metric:compactsize_0_raw_script -->139<!-- /metric:compactsize_0_raw_script --> | <!-- metric:compactsize_0_raw_witness -->3<!-- /metric:compactsize_0_raw_witness --> | 1 | 0 (0 bytes) | <!-- metric:compactsize_0_raw_stack -->3<!-- /metric:compactsize_0_raw_stack --> | <!-- metric:compactsize_0_raw_executed -->38<!-- /metric:compactsize_0_raw_executed --> |
| 0 | `00` | Numeric byte items | <!-- metric:compactsize_0_numeric_script -->77<!-- /metric:compactsize_0_numeric_script --> | <!-- metric:compactsize_0_numeric_witness -->2<!-- /metric:compactsize_0_numeric_witness --> | 1 | 0 (0 bytes) | <!-- metric:compactsize_0_numeric_stack -->4<!-- /metric:compactsize_0_numeric_stack --> | <!-- metric:compactsize_0_numeric_executed -->16<!-- /metric:compactsize_0_numeric_executed --> |
| 128 | `80` | Raw byte items | <!-- metric:compactsize_128_raw_script -->141<!-- /metric:compactsize_128_raw_script --> | <!-- metric:compactsize_128_raw_witness -->3<!-- /metric:compactsize_128_raw_witness --> | 1 | 0 (0 bytes) | <!-- metric:compactsize_128_raw_stack -->3<!-- /metric:compactsize_128_raw_stack --> | <!-- metric:compactsize_128_raw_executed -->40<!-- /metric:compactsize_128_raw_executed --> |
| 128 | `80` | Numeric byte items | <!-- metric:compactsize_128_numeric_script -->79<!-- /metric:compactsize_128_numeric_script --> | <!-- metric:compactsize_128_numeric_witness -->4<!-- /metric:compactsize_128_numeric_witness --> | 1 | 0 (0 bytes) | <!-- metric:compactsize_128_numeric_stack -->4<!-- /metric:compactsize_128_numeric_stack --> | <!-- metric:compactsize_128_numeric_executed -->16<!-- /metric:compactsize_128_numeric_executed --> |
| 253 | `fd fd 00` | Raw byte items | <!-- metric:compactsize_253_raw_script -->141<!-- /metric:compactsize_253_raw_script --> | <!-- metric:compactsize_253_raw_witness -->7<!-- /metric:compactsize_253_raw_witness --> | 3 | 0 (0 bytes) | <!-- metric:compactsize_253_raw_stack -->5<!-- /metric:compactsize_253_raw_stack --> | <!-- metric:compactsize_253_raw_executed -->67<!-- /metric:compactsize_253_raw_executed --> |
| 253 | `fd fd 00` | Numeric byte items | <!-- metric:compactsize_253_numeric_script -->79<!-- /metric:compactsize_253_numeric_script --> | <!-- metric:compactsize_253_numeric_witness -->8<!-- /metric:compactsize_253_numeric_witness --> | 3 | 0 (0 bytes) | <!-- metric:compactsize_253_numeric_stack -->5<!-- /metric:compactsize_253_numeric_stack --> | <!-- metric:compactsize_253_numeric_executed -->42<!-- /metric:compactsize_253_numeric_executed --> |
| 32768 | `fd 00 80` | Raw byte items | <!-- metric:compactsize_32768_raw_script -->142<!-- /metric:compactsize_32768_raw_script --> | <!-- metric:compactsize_32768_raw_witness -->7<!-- /metric:compactsize_32768_raw_witness --> | 3 | 0 (0 bytes) | <!-- metric:compactsize_32768_raw_stack -->5<!-- /metric:compactsize_32768_raw_stack --> | <!-- metric:compactsize_32768_raw_executed -->64<!-- /metric:compactsize_32768_raw_executed --> |
| 32768 | `fd 00 80` | Numeric byte items | <!-- metric:compactsize_32768_numeric_script -->80<!-- /metric:compactsize_32768_numeric_script --> | <!-- metric:compactsize_32768_numeric_witness -->8<!-- /metric:compactsize_32768_numeric_witness --> | 3 | 0 (0 bytes) | <!-- metric:compactsize_32768_numeric_stack -->5<!-- /metric:compactsize_32768_numeric_stack --> | <!-- metric:compactsize_32768_numeric_executed -->42<!-- /metric:compactsize_32768_numeric_executed --> |
| 65535 | `fd ff ff` | Raw byte items | <!-- metric:compactsize_65535_raw_script -->142<!-- /metric:compactsize_65535_raw_script --> | <!-- metric:compactsize_65535_raw_witness -->7<!-- /metric:compactsize_65535_raw_witness --> | 3 | 0 (0 bytes) | <!-- metric:compactsize_65535_raw_stack -->5<!-- /metric:compactsize_65535_raw_stack --> | <!-- metric:compactsize_65535_raw_executed -->72<!-- /metric:compactsize_65535_raw_executed --> |
| 65535 | `fd ff ff` | Numeric byte items | <!-- metric:compactsize_65535_numeric_script -->80<!-- /metric:compactsize_65535_numeric_script --> | <!-- metric:compactsize_65535_numeric_witness -->10<!-- /metric:compactsize_65535_numeric_witness --> | 3 | 0 (0 bytes) | <!-- metric:compactsize_65535_numeric_stack -->5<!-- /metric:compactsize_65535_numeric_stack --> | <!-- metric:compactsize_65535_numeric_executed -->42<!-- /metric:compactsize_65535_numeric_executed --> |

## Security, compatibility and execution

The check enforces byte shape and the minimal CompactSize form within
the supported range. A consumer expecting bytes from a different
commitment must bind these same items. The result makes no
cryptographic or authentication claim.

Measured leaves use `CompileOptions::ALL` through the central policy.
Metrics run with the pinned local tapscript Consensus profile, the
520-byte item limit, 1,000-item combined limit, and zero signature
validation charge. The fixtures also run under the local Policy
profile with minimal ScriptNum checks. Evidence is `locally-reproduced`;
execution is `unclassified`. Ordinary arithmetic and branch opcodes
exist in bare, P2SH, P2WSH and tapscript. Context-specific legacy
and relay constraints require separate checks. See
[script types](../../../docs/script-types.md) and
[standardness](../../../docs/standardness.md).

## Reproduction

```sh
cargo test --locked --lib support::compact_size::tests
cargo test --locked --test primitive_metrics compactsize_decoder_metrics_are_current
python3 tools/kb.py validate
cargo test --locked -- --skip fields::
```

The tests cover every supported value against host serialization,
both local profiles at the byte boundaries, nonminimal tokens,
reserved prefixes, malformed items, truncation, extra items, and
caller-state preservation. See the
[knowledge entry](../../../knowledge/primitives/compactsize-u16-items.md).
