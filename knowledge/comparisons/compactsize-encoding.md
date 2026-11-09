# CompactSize byte representations

The [CompactSize decoder](../primitives/compactsize-u16-items.md)
accepts one or three separate stack items and returns a canonical
numeric value. Both complete leaves check the same wire form and
numeric output. Raw items each carry exactly one byte. Numeric
items carry canonical ScriptNum encodings of the logical bytes.
Every item is present at entry and there are zero hints.

| Value | Wire form | Ordinary items | Raw leaf / witness / peak / executed ops | Numeric leaf / witness / peak / executed ops |
| ---: | --- | ---: | ---: | ---: |
| 0 | `00` | 1 | 139 / 3 / 3 / 38 | 77 / 2 / 4 / 16 |
| 128 | `80` | 1 | 141 / 3 / 3 / 40 | 79 / 4 / 4 / 16 |
| 253 | `fd fd 00` | 3 | 141 / 7 / 5 / 67 | 79 / 8 / 5 / 42 |
| 32768 | `fd 00 80` | 3 | 142 / 7 / 5 / 64 | 80 / 8 / 5 / 42 |
| 65535 | `fd ff ff` | 3 | 142 / 7 / 5 / 72 | 80 / 10 / 5 / 42 |

Serialized witness includes the count and item lengths and excludes
the leaf, control block, annex, and transaction. Executed non-push
counts include visited branch delimiters. Raw items save up to three
witness bytes in the measured cases, while every raw leaf is 62 bytes
larger. This is useful when the calling contract already carries
exact wire byte items. See the [measured markers](../../src/support/compact_size/README.md#script-metrics)
and [encoding failures](../negative-results/compactsize-u16-items.md).
