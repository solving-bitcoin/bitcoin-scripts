# Extended Hamming (8,4) byte decoder

Can a reused parity syndrome decode a canonical byte within distance one
of an extended-Hamming codeword using less live state than direct lookup?
The hypothesis is that the syndrome schedule wins for one input, while a
resident table can amortize its initialization over several inputs.
Compare identical byte guards, exact decoded output order and terminal
checks. Every byte is hostile. The hard constraints are the canonical
ScriptNum byte representation, at most 1,000 combined items, zero hints
and the central compilation policy. Evidence is `locally-reproduced`;
execution is `unclassified`.

Number bit positions from the least significant bit starting at one.
Data occupy positions 3, 5, 6 and 7 in increasing significance.
The three syndrome bits are parity over positions 1/3/5/7,
2/3/6/7 and 4/5/6/7. Position 8 completes the overall even parity.
The script uses the repository's canonical byte guard and width-8
bit decomposition. It reuses the first syndrome bit as the parity of
four of the eight bits when computing overall parity.

For even overall parity, the syndrome must be zero. Odd parity permits
one correction. If the syndrome names a data position, flip that bit
when assembling the output. Syndrome zero under odd parity means the
eighth bit alone is corrected, so data stay the same. The independent
host oracle enumerates the 16 codewords and looks for a unique
candidate at distance zero or one. The table stores the resulting
nibble or a rejection sentinel for each possible received byte.

This is the extended binary construction described by
[Hamming's 1950 paper](https://doi.org/10.1002/j.1538-7305.1950.tb00463.x).
The scoped catalog, source and PR search found adjacent checksum and
distance work, including the u4 distance projection in
[PR #270](https://github.com/solving-bitcoin/bitcoin-scripts/pull/270).
Distance between two given vectors and correction to an implicit codebook
have different input and output contracts.

## Matched complete leaves

| Inputs | Schedule | Script bytes | Witness bytes | Ordinary items | Hint items | Combined peak | Executed non-push ops |
| ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | Syndrome | 185 | 4 | 1 | 0 | 13 | 121 |
| 1 | Table | 408 | 4 | 1 | 0 | 259 | 144 |
| 8 | Syndrome | 1,473 | 20 | 8 | 0 | 20 | 975 |
| 8 | Shared table | 585 | 20 | 8 | 0 | 267 | 248 |

The single input is `0x83` and decodes to 1. For the batch, encode
nibble `i` and flip zero-based bit `i`, for `i = 0..7`. All eight inputs
coexist at entry, in increasing nibble order. Both leaves consume the
top input first, stage outputs and restore them in original order.
The lookup batch loads the 256-entry table once and cleans it up after
all queries. The syndrome batch repeats the standalone decoder.

The whole artifact uses optimizer `ALL`. Script costs include validation,
computation, table lifecycle when applicable, output checks and terminal true.
Witness bytes include all canonical data items and their prefixes,
excluding script, control block, annex and transaction. There are
zero hints in either configuration and no caller items in the table.
Dynamic non-push counts include active instructions and encountered
branch delimiters. No signatures execute.

Execution uses the local tapscript `Consensus` profile with synthetic
transaction context. Stack and element limits and MINIMALIF are enabled,
numeric minimality and experimental OP_CAT are disabled. The compiler
and interpreter pins are
[`124b561ed75ac3ec4c6ad99207d8dcdd3bc67180`](https://github.com/BitVM/rust-bitcoin-script/tree/124b561ed75ac3ec4c6ad99207d8dcdd3bc67180)
and [`a09e87af444034698697f0a2267e755cf72f9aed`](https://github.com/adrienlacombe/rust-bitcoin-scriptexec/tree/a09e87af444034698697f0a2267e755cf72f9aed).

## Exact scope and reproduction

All 256 received bytes are tested against the nearest-codeword oracle.
Exactly 144 are accepted. Every one-bit and two-bit perturbation of
each valid codeword is enumerated. The tests also reject malformed
numeric byte encodings, oversized items, short and surplus witnesses,
and a bad item in an otherwise valid ordered batch. A composed syndrome
fixture preserves 986 main and one alt caller items at a peak of 1,000
and rejects one more caller item. For an exact suffix, the fragment
preserves both caller stacks. The caller supplies output binding and
terminal checks. Funded Core and relay tests are outside this experiment.

Both decoders correct within the stated distance. At three flips,
`0x07` is distance three from the zero codeword and distance one from
`0x87`; the decoder returns nibble one. The result cannot authenticate
the sender or tell which valid word was transmitted. See the
[negative result](../negative-results/hamming84-decoder.md).

```sh
cargo test --locked --lib arithmetic::hamming::tests
cargo test --locked --test primitive_metrics hamming84_metrics_are_current
python3 tools/kb.py validate
cargo test --locked -- --skip fields::
```

See the [implementation README](../../src/arithmetic/hamming/README.md)
and catalog record `arithmetic/hamming84-decoder`.
