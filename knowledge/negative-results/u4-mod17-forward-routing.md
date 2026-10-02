# Forward modulo-17 routing is dominated at the measured boundary

The comparison-only [forward Horner scheduler](../../research/u4-mod17/baseline.rs)
computes exactly the same big-endian residue as the
[reverse fold](../primitives/u4-mod17.md), with the same canonical checks,
no hints, and preserved stacks. It brings the oldest remaining nibble to the
top using depth-dependent `OP_ROLL` and keeps the residue on the altstack.

For 1/2/32/128/997 inputs, optimized fragment sizes are
22/42/746/3,050/24,775 bytes, versus 10/40/670/2,686/20,926 for the reverse
fold. The deterministic witnesses, outputs, and combined peaks match; all
hints are zero and all data coexist at entry. At 32 inputs, forward scheduling
adds 76 bytes and 31 static non-push operations without improving witness size
or the 35-item peak. This is `locally-reproduced` and `unclassified`, with
dynamic opcode counts unavailable. Both are below the optimizer cutoff.

The complete comparison leaves add the same two-byte terminal predicate at
each configuration. The zero-hint result is not a transaction acceptance or
cryptographic claim. The baseline is retained only as a reproducible experiment,
not a second public API. This measured dominance does not rule out a forward
schedule when a different surrounding protocol provides inputs incrementally
or needs intermediate prefix residues.

Reproduce with `cargo run --locked --example u4_mod17_benchmark` and the shared
`u4_reduction_contract` test. The [report](../../research/u4-mod17/metrics.json)
records the exact hashes, dependency pins, witnesses, terminal predicate, and
local options. OP_MOD, OP_MUL and raw bitwise operations were excluded from
the design because they do not provide ordinary usable tapscript arithmetic;
no experiment using them is reported as a successful reduction.
