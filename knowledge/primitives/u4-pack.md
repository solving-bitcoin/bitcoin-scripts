# u4 pair-to-byte packing

`arithmetic::u4::pack::pack_bytes` range-checks big-endian u4 pairs and packs
each pair into a numeric ScriptNum value `16*high + low`. It is a numeric
adapter for arithmetic and comparisons, not raw-byte concatenation: values
128–255 use their minimally encoded multi-byte ScriptNum representation.

## Contract

```text
high[0] low[0] ... high[n-1] low[n-1] -> byte[0] ... byte[n-1]
```

The last output is on top. All `2*n` input items are checked in `0..=15` and
consumed. The script uses no hints, and all input data items coexist at entry.

## Measurement

The representative 32-byte fragment includes all 64 numeric range checks,
four-addition-bit packing, output routing, and a complete 64-item empty-nibble
witness. It excludes input serialization consumers and transaction context.

| Configuration | Script | Witness | Data items | Hints | Peak | Static non-push opcodes |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 32 packed numeric bytes | 1,003 bytes | 65 bytes | 64 | 0 (none) | 67 | 766 |

The measured strict peak is well below the 1,000-item combined stack limit.
The 766 non-push opcodes make the fragment tapscript-oriented rather than a
legacy/P2SH/P2WSH policy target. Consensus and relay-policy validation remain
unclassified.

## Validation

Focused tests cover every single-byte value, multi-byte output ordering,
out-of-range input rejection, and zero-width generation:

```sh
cargo test --locked arithmetic::u4::pack
cargo test --locked --test primitive_metrics u4_pack_metrics_are_current
python3 tools/kb.py validate
```
