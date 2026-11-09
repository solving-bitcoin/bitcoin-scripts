# Authenticated 2-of-3 subset consumer

- **Question:** Can one canonical HORS opening supply the same two indices to
  authentication and a Binohash-style `OP_ROLL` subset selector, without a
  second witness selector that could disagree?
- **Comparison objective:** Exercise all three ordered pairs and hostile
  openings in one strict local tapscript model; compare the measured script
  boundary with the existing clamped and exact HORS fragments.
- **Execution class:** `locally-reproduced`, `unclassified`. The test uses the
  repository's tapscript-context executor with the combined stack limit on.
- **Threat model:** Indices and preimages are hostile. An out-of-range,
  duplicate, reversed, negative, nonminimal, or mismatched opening must fail.

## Parameters

The script embeds three HASH160 commitments to distinct 16-byte deterministic
test preimages and calls the exact-index HORS verifier with `n=3,t=2`. The
opening is `index_1, preimage_1, index_0, preimage_0` from bottom to top.
Both indices must be canonical, in range, and strictly increasing. The
consumer selects two of three toy numeric pool tags `1,2,4` with `OP_ROLL`.
These tags are **not ECDSA signatures**; the script does not compute a legacy
signature hash or execute `OP_CHECKMULTISIG`.

## Reproduction

```sh
cargo test --locked binohash_hors_subset --lib
cargo test --locked --test primitive_metrics binohash_hors_subset_metrics_are_current
```

## Script metrics

The `n=3,t=2` representative uses pair `[0,2]` and 16-byte preimages. The
script duplicates the two index items onto altstack before HORS consumes the
opening, then restores those same items for `OP_ROLL` selection. It checks
the selected tag sum against the uniquely corresponding pair-index sum and
ends with one true stack item. There are four witness **data** items and
**zero hint items** per invocation. All four data items coexist at entry;
the commitments are pushed later. The measured stack peak combines main and
alt stacks. Script bytes are from the final policy-produced bytecode.

| Same `[0,2]` opening | Final script | Serialized data witness | Combined stack peak | Static non-push opcodes |
| --- | ---: | ---: | ---: | ---: |
| Clamped HORS alone | 89 bytes | 38 bytes | 9 items | 19 |
| Exact HORS alone | 110 bytes | 38 bytes | 10 items | 35 |
| Exact HORS plus selection consumer | 153 bytes | 38 bytes | 12 items | 68 |

The [metric markers](../../src/introspection/README.md) are checked by
`tests/primitive_metrics.rs`; this table copies those measured values.

The static opcode count is for the full optimized script. It is not a
measured executed-opcode count, and no Core legacy, relay-policy, transaction
weight, or Binohash grinding result follows from this local tapscript run.

## Security and integration limits

The test checks all three canonical pairs and rejects wrong preimages,
out-of-range, duplicate, reversed, negative, and nonminimal indices. The
nonminimal controls still fail with the executor's `MINIMALDATA` option off.
An extra witness item fails the terminal clean-stack condition.

This proves an index-routing composition for a toy consumer, not a HORS
security bound. The deterministic preimages are public test data, and a real
one-time key would require private generation, domain-separated
message-to-subset derivation, durable disclosure state, and integration with
actual legacy ECDSA signatures. See [OP-009](../../knowledge/open-problems.md#op-009--one-time-authentication-security-profiles)
and [OP-011](../../knowledge/open-problems.md#op-011--reproduce-binohash).
