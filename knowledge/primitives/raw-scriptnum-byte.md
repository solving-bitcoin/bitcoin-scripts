# Materialize one raw byte from a numeric ScriptNum

Can sign-magnitude serialization replace a high-half lookup when converting
a canonical numeric byte into one raw byte for a native hash? The hypothesis
is that positive byte values below 128 can pass through, while upper bytes
can use their corresponding negative ScriptNum serialization. Compare the
same canonical input guard and complete SHA-256 digest check. All witness
items are hostile. Hard constraints are input values 0 through 255, exact
one-byte output, the combined 1,000-item limit, zero hints and the central
compilation policy. Evidence is `locally-reproduced`; execution is
`unclassified`.

For 1 through 127 the canonical ScriptNum already consists of that byte.
Canonical numeric zero is empty, so replace it with the literal byte
`00`. For 129 through 255, compute `128 - x`. Its canonical one-byte
sign-magnitude encoding has magnitude `x - 128` and the high bit set.
At exactly 128 that subtraction yields canonical zero, which must be
replaced with the literal byte `80`. Both exceptional cases use exact
one-byte pushes. The branch chooses its fallback byte and both sides
use the same zero test to select it. The source encoding is specified in the pinned
[Bitcoin Core CScriptNum serializer](https://github.com/bitcoin/bitcoin/blob/49faec4f87f5cd19c88db01a82e5c68b087c8227/src/script/script.h#L319-L355).

The comparison uses the same low-half pass-through and zero special case,
with a 128-entry high-half table of raw byte constants for the upper branch.
The scoped catalog, source, comparisons and PR search found
[u4 packing](u4-batch-pack.md) and [PR #284](https://github.com/solving-bitcoin/bitcoin-scripts/pull/284).
Those return canonical numeric bytes, including a sign pad at 128 and
above. This adapter produces one raw stack item for each accepted value.

## Cost boundary

| Input | Schedule | Script bytes | Data witness bytes | Ordinary items | Hint items | Combined peak | Executed non-push ops |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `0x00` | Sign-magnitude | 72 | 2 | 1 | 0 | 4 | 20 |
| `0x00` | High-half table | 391 | 2 | 1 | 0 | 4 | 19 |
| `0xc8` | Sign-magnitude | 72 | 4 | 1 | 0 | 4 | 22 |
| `0xc8` | High-half table | 391 | 4 | 1 | 0 | 129 | 86 |

Both complete leaves check `OP_SHA256` of the converted one-byte item
against an independent host digest, then leave true. Fixtures are
`0x00` and `0xc8`. Whole-leaf optimizer `ALL` compiles the input guard,
conversion, native hash and terminal check. Witness bytes include the
count and length prefix of the sole ordinary input, excluding script,
control block, annex and transaction. There are no hints or caller
items. Dynamic counts include active non-push operations and encountered
branch delimiters. The high-half lookup is only live on its upper path.
No signatures execute.

The measurement uses the local tapscript `Consensus` profile with
stack and element limits and MINIMALIF enabled, numeric minimality and
experimental OP_CAT disabled, and synthetic transaction context. The
valid byte and hash fixtures also pass the local `Policy` profile.
The pinned compiler and interpreter are
[`124b561ed75ac3ec4c6ad99207d8dcdd3bc67180`](https://github.com/BitVM/rust-bitcoin-script/tree/124b561ed75ac3ec4c6ad99207d8dcdd3bc67180)
and [`a09e87af444034698697f0a2267e755cf72f9aed`](https://github.com/adrienlacombe/rust-bitcoin-scriptexec/tree/a09e87af444034698697f0a2267e755cf72f9aed).

## Composition and reproduction

The fragment consumes one exact numeric input suffix and preserves both
caller stacks. The sign-magnitude path peaks at four combined items plus
all caller state. The tests observe 1,000 with 995 caller main items and
one caller alt item and reject a further item. Zero hints are required.
Treat the output as raw bytes. The exceptional outputs `00` and `80`
have false truthiness, and upper bytes have sign-magnitude encodings
different from their original unsigned numeric values.

All 256 inputs are checked by raw-byte equality and a host digest oracle.
Tests also reject out-of-range, nonminimal, oversized, short and surplus
witnesses. Directly hashing the numeric encodings of zero, 128 or 255
fails the matching raw-byte digest checks. See the
[negative result](../negative-results/raw-scriptnum-byte.md).
No funded Core or relay validation was run for these leaves.

```sh
cargo test --locked --lib arithmetic::byte_encoding::tests
cargo test --locked --test primitive_metrics numeric_raw_byte_metrics_are_current
python3 tools/kb.py validate
cargo test --locked -- --skip fields::
```

See the [implementation README](../../src/arithmetic/byte_encoding/README.md)
and catalog `arithmetic/raw-scriptnum-byte`.
