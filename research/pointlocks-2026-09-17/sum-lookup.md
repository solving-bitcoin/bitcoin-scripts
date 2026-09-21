# HASH160 lookup tables for common-G sum locks

Question: after changing the algebra to [sum-key locks](sum-pointlock.md), can
one compact table authenticate selected verification keys? Each candidate now
needs only `HASH160(P_i)`. The common second key is G and the selected scalar
is extracted as `t_i=-2z/r_i`, with public target `T_i=P_i+G`.

[The probe](../../examples/pointlock_sum_lookup_probe.rs) stages the unlocking
records on the altstack, loads G and a table of key hashes, then destructively
selects each hash with `OP_ROLL`. Each selected key must open that hash, and
the same signature must pass its size guard and both ECDSA checks. Removing
the selected table entry prevents its reuse. Independent candidate generation
and duplicate-key/hash rejection remain setup obligations.

## Measured layouts

All figures use exactly 71-byte low-S signature items, including `0x03`.
The public deterministic fixture generator retries nonces until this length
is reached; it does not derive candidate secrets from a shared public affine
relation. Script sizes include the table, verification, cleanup, and terminal
truthy value, after the repository compilation policy.

| Layout | Redeem script | Complete scriptSig | Static non-push ops | Static sigops | Entry items | Hint items | Combined peak |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Fixed 4-of-17 | 505 B | 938 B | 87 | 8 | 12 | 4 | 33 |
| Variable 1-through-5 of 15 | 507 B | `525+104t` B | 130 | 10 | 15 | 5 | 34 |

The fixed layout's representative selectors give 938 bytes. A selector
above 16 requires a two-byte data push rather than an OP_1..OP_16, so this
number must not be silently treated as every subset's exact size. The complete
transaction calculator uses the actual minimal selector pushes.

Each selected record has `[signature, compressed_key, depth]`: two operand
items and one mandatory lookup-depth hint. A fixed t-selection invocation has
t hints and 3t data items, all present at entry. The variable maximum-five
layout always has five frames, including padding: five depth/sentinel hints
and ten signature/key slots, all fifteen present at entry. The combined peak
includes staged records and table data. Different P2SH inputs execute with
separate stacks; their items do not coexist on one 1,000-item Script stack.

The scriptSig includes minimal data/index pushes and the redeem-script push.
Its enclosing CompactSize prefix, outpoint, sequence, and funding output are
excluded. P2SH adds one redeem-script stack item before its evaluation. These
legacy inputs have no witness items; each contributes an empty-vector byte
when the transaction also contains SegWit inputs. Static opcodes include both
arms of optional branches; executed-opcode counts were not instrumented.

## Optional frames and the rejected global-weight shortcut

The first frame is mandatory. In each later frame, depth zero selects the
inactive branch. It discards the three supplied frame items and the current
top table hash. Thus every round consumes one table position even when no
point is revealed, preserving the depth arithmetic used by subsequent rounds.
Canonical witnesses place active frames first and empty frames last. Other
accepted orders require decoding the actual destructive table operations;
padding contents are not authenticated message data.

The variable layout accepts 1, 2, 3, 4, or 5 selected points, with respective
scriptSig sizes 629, 733, 837, 941, and 1,045 bytes. A proposed codec used 176
pools and exactly 638 total revelations, whose capacity is

```text
[x^638](15x + 105x^2 + 455x^3 + 1365x^4 + 3003x^5)^176
```

The base-2 logarithm is approximately 2048.4076847, enough to rank/unrank a
256-byte message. **The individual scripts do not enforce the total 638.**

This is more than a decoder caveat. An observer of a valid publication can
remove an optional revelation, replace its frame with empty padding, and
adjust selectors without learning any new secret. The resulting transaction
can still pass the Bitcoin scripts while failing the global code. Keeping the
inputs and outputs unchanged preserves a helper P2TR signature: its sighash
does not commit to other inputs' scriptSigs. A protocol that penalizes an
invalid decoded publication can therefore expose the publisher to a
third-party mutation. Merely rejecting the wrong global count offchain does
not demonstrate a safe integration.

The current complete-publication baseline consequently uses fixed-cardinality
pools. The variable-global-weight result is retained as a sizing experiment,
not a deployable proof-publication improvement. See the
[negative result](../../knowledge/negative-results/variable-pointlock-subset-malleation.md).

## Conditional CSV repair

The [CSV probe](../../examples/pointlock_sum_csv_probe.rs) adds a constant
`<5-j> CHECKSEQUENCEVERIFY DROP` to inactive slots j=1..4. A canonical
t-revelation spend sets that input's sequence to `5-t`. Removing a revelation
forces an inactive slot earlier than t and fails at the unchanged sequence.
No runtime counter is needed; the compiled redeem script is **519 bytes**.

The corresponding scriptSig is `537+104t` bytes: 641, 745, 849, 953, or 1,057.
There are still fifteen entry items, five depth/sentinel hints, combined peak
34, ten static sigops, and now 138 static non-push opcodes. The transaction
must use compatible version/sequence flags and the funding output must satisfy
the relative lock-time requirement; the fixture matures funding four blocks.

[Core validation](sum_csv_core_check.json) passes 31 expectations: 30 CSV
fixtures (nine positive, 21 negative) plus the historical cross-pair control.
Every canonical count one through five is accepted, dropping a revelation at
the original sequence is rejected, and raising the sequence makes the dropped
version valid again. The exact positive P2SH fixtures are
`differentially-validated` and `policy-validated`.

The last observation is essential: this repair requires **unavoidable
authorization that commits all input sequences**. The point-lock script cannot
force a helper input to remain present. An attacker able to omit/replace that
helper can raise sequences and remove revelations. CSV therefore supplies a
tested conditional component, not a standalone enforcement of the 638 global
count. The complete baseline remains fixed-cardinality; the outer authorization
and safe handling of unauthorized pool spends require separate protocol work.

## What HASH160 changes

For an opened key P, the two ECDSA checks still reveal `log_G(P+G)` algebraically.
They do not prove that P is the unique opening of the table's HASH160 value.

For an independently fixed honest key commitment, substituting a distinct P'
requires a second preimage. For adversarial setup, an adversary can generate
many honestly openable common-G candidates and search for distinct P,P' with
the same HASH160. They could advertise `T=P+G`, then reveal an opening for
`T'=P'+G`. Every signature check would pass, yet the revealed scalar would
belong to the other advertised target. The generic birthday collision scale
is approximately `2^80` hash trials; this is an attack-work estimate, not a
locally computed collision. The key checks do not turn this commitment into
a preimage-only assumption. Directly embedded P keys avoid this extra lookup
binding assumption.

Reject duplicate public keys and duplicate table hashes in normal setup.
That detects repeated published entries, not a hidden alternate collision
opening. This HASH160 consideration is independent of the unconditional
sum-key extraction formula for the key actually verified.

## Evidence and reproduction

The [saved vectors](sum-lookup-vectors.json) have SHA256
`9e3ccc99d825aa388c781073b88c7cd13291320cc9d35848c5ef80798d5dedf4`.
The [Core report](sum_lookup_core_check.json) passed all **313** expectations:
312 lookup fixtures (46 positive, 266 negative) and one historical cross-pair
control. All 46 positive lookup fixtures were consensus- and policy-accepted.
They cover representative fixed layouts and variable counts, plus malformed
signatures, short items, uncommitted keys, invalid depths, duplicate selection,
and all-empty variable openings.

Evidence is `differentially-validated` for those exact fixtures and
`policy-validated` for their positive P2SH spends. Other enumerated sizing
rows remain `locally-reproduced`, `unclassified` until independently checked.
These results do not validate the rejected global-weight protocol shortcut.
Core is version 30.3, commit `49faec4f87f5cd19c88db01a82e5c68b087c8227`;
compiler `124b561ed75ac3ec4c6ad99207d8dcdd3bc67180`; local interpreter
`702544c9a045ac4fc14846da6da6559e2b7cd9d1`, `ExecCtx::Legacy`, default
options with stack limits enabled. The shared tapscript helper is not used.

```sh
cargo run --locked --example pointlock_sum_lookup_probe
```

[BIP341's signature-message specification](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki#common-signature-message)
lists the data committed by the helper signature. Key-table hashing and
Script semantics are checked against the pinned Core revision above.
