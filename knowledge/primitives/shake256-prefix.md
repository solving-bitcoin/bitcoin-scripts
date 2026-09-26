# SHAKE256 byte-lane output prefixes

The prefix variant of the repository's byte-oriented SHAKE256 implementation
returns only the requested leading output bytes instead of materializing the
fixed 1,024-byte XOF result.

## Research question

Can output-length specialization turn the existing consensus-incompatible
1,024-item SHAKE256 experiment into a stack-compatible small-output primitive
without changing its FIPS 202 byte convention or Keccak implementation?

The hypothesis is intentionally narrow: a prefix of at most a few dozen bytes
should stay below the 1,000-item combined stack limit, while preserving the
same output bytes as the 1,024-byte reference.

## Construction and boundary

`shake256_prefix(message_bytes, output_bytes)` uses the existing byte-lane
absorption and Keccak-f[1600] code, then squeezes only the number of rate blocks
needed for the requested prefix. `output_bytes` is fixed at generation time and
must be in `1..=1024`; the input remains fixed at `0..=511` bytes. The fragment
consumes one byte item per message byte and leaves the first prefix byte on top.

The representative boundary includes the generated sponge, lookup-table setup
and cleanup, and output restoration. It excludes message pushes, output
comparison, terminal predicates, and transaction framing. The witness is 32
one-byte message items; there are zero hint items.

## Evidence and metrics

Evidence is `locally-reproduced`. Prefixes of 1, 32, 135, 136, 137, and 256
bytes match an independent 1,024-byte SHAKE256 reference, including the rate
boundary. A 32-byte prefix and the rate-crossing 137-byte prefix pass the
strict local combined-stack check.

| Configuration | Script bytes | Witness bytes | Peak items |
| --- | ---: | ---: | ---: |
| 32-byte input, 32-byte prefix | 2,000,127 | 65 | 813 |
| 32-byte input, 137-byte prefix | 3,989,612 | 65 | 893 |

The local tapscript interpreter reports `opcode_count=0` for this execution
because its legacy opcode counter is unavailable in tapscript; executed-opcode
count is therefore left unclaimed. Deployment remains `unclassified` pending
Bitcoin Core consensus and policy validation.

## Limitations

The prefix avoids the raw output's stack overflow, but the representative
fragments remain unsuitable for ordinary script-size and relay-policy limits.
The 137-byte row crosses the one-rate-block boundary with 107 combined stack
items of headroom. Larger prefixes require a fresh stack check because the live
Keccak state, lookup table, and altstack output all count toward the limit.

See the [implementation README](../../src/hashes/shake256/README.md), the
[hash comparison](../comparisons/hashes.md), and research record
`research/shake256-prefix/README.md`.
