# Windowed small-r point-lock sizing

**Rejected for practical use:** this family needs enormous setup work and
has an unresolved short-signature assumption. The historical figures below
remain valid sizing evidence, but do not meet the practical-setup requirement.
See the [disposition](windowed-publication.md).

The measured direct-key serialization is **39,396 vbytes for both transactions**:
35 P2WSH inputs, each containing four independent 6-of-19 CHECKMULTISIG blocks.
All 76 keys in one input share its hidden window center, so one native-digest
grind permits every allowed subset in all four blocks. A slightly smaller
HASH160 lookup variant costs 38,767 vbytes but needs 52 separate grinds.

These are complete serialization measurements using **placeholder signatures**
at the production 53-byte cap. Production grinding was not executed. The
[algebra review](windowed-small-r-review.md) explains the conditional
short-signature assumption and hidden-offset correlations; the size result
is not an unconditional point-lock extraction theorem.

## Historical direct-key profile: batched CHECKMULTISIG

Each input commits four disjoint 19-key tables and requires exactly six
signatures in each table. Its message radix is `C(19,6)^4`. Across 35 inputs:

```
C(19,6)^140 = 27132^140 > 2^2048
log2(capacity) = 2061.879088846176 bits
```

A fixed-length mixed-radix codec can therefore publish every 256-byte value.
The setup has 2,660 candidate keys and publication reveals 840 target scalars.
All thresholds are fixed; deleting an opening does not produce a valid spend.

| Per input | Measured value |
|---|---:|
| Compiled witness script | 2,761 bytes |
| Serialized witness at 53-byte signatures | 4,065 bytes |
| Static non-push opcodes | 116 |
| Additional CHECKMULTISIG key-count charge | 76 |
| Total charged opcodes | 192 |
| Witness sigop cost | 80 |
| Signature items | 24 |
| Mandatory empty CHECKMULTISIG dummy items | 4 |
| Incremental hint items | 0 |
| Entry data items, excluding script | 28 |
| Complete witness items, including script | 29 |
| Analytical combined main-plus-alt-stack upper bound | 52 |

The 80 sigops reflect four key lists whose counts exceed OP_16: the static
sigop counter conservatively charges 20 for each CHECKMULTISIG. This differs
from the interpreter's extra opcode charge of the actual 19 keys per block.
The script is below the 3,600-byte P2WSH policy limit; entry items and individual
signature items fit the 100-item and 80-byte witness policy limits. Script
execution still needs validation independently of this static accounting.

Across all inputs there are 980 entry data items (840 signatures and 140
mandatory dummies), zero hints, and 1,015 complete witness items. They do not
coexist on one Script stack: each input starts a fresh execution. The reported
bound includes both main and alt stacks during signature staging. It is an
analytical bound, not a measured production execution peak.

Witness block order is reversed relative to script processing order. For
blocks 0 through 3 in the script, serialize block 3 first and block 0 last;
each block consists of its empty dummy followed by the six signatures in
ascending selected-key order. Each signature is checked with `SIZE <= 53`
before that block's native CHECKMULTISIG. The compiled script has no
OP_CODESEPARATOR, so every candidate in the input uses the same native digest.

## Complete transaction accounting

The funding transaction spends one existing P2TR key-path input with a 64-byte
Schnorr signature. It creates the first P2TR helper output and 35 P2WSH outputs.
The spending transaction consumes that helper as input zero and all 35 P2WSH
outputs. It creates a first P2TR output and one nonce-bearing output for each
point-lock input. Each nonce output is `OP_RETURN PUSH8 <counter>`, serialized
as a 19-byte CTxOut. The matching input/output indices are preserved for native
SIGHASH_SINGLE|ANYONECANPAY (`0x83`).

| Transaction | Inputs | Outputs | Weight | Vbytes |
|---|---:|---:|---:|---:|
| Funding | 1 P2TR | 1 P2TR + 35 P2WSH | 6,464 | 1,616 |
| Publication | 1 P2TR + 35 P2WSH | 1 P2TR + 35 nonce outputs | 151,119 | 37,780 |
| Combined | | | 157,583 | **39,396** |

This includes output creation and subsequent consumption, witness item and
script lengths, transaction counters, marker/flag, and both helper signatures.
The existing source UTXO, test grants, and mining are outside this boundary.
Values, fees and dust are separate from serialized size. Acceptance of the
complete set of OP_RETURN outputs is a policy question tested by the native
fixture rather than inferred from the size calculation.

## Honest grind estimate

For the production profile, the known nonce is `k0=1/2`, with a 21-byte DER r.
Choose hidden offsets below `2^190`. Requiring the normalized s integer to
have exactly 25 DER bytes gives the interval `2^191 <= lowS(s) < 2^199`.
A conservative shared-center acceptance width retains a fraction `509/512`
of the approximate `2^-56` success probability. This stronger honest interval
produces exactly 53-byte signatures even though the CMS guard also accepts
shorter valid signatures.

For script size 2,761 the BIP143 preimage has 2,920 bytes. Its prefix before
the changing hashOutputs field is 2,880 bytes, exactly 45 SHA256 blocks.
Cache that prefix midstate. The remaining 40 bytes and padding require one
compression, followed by one outer SHA256 compression. Double-hashing the
19-byte nonce output requires two more. Thus a nonce trial costs four SHA256
compression calls, excluding fixed preprocessing and interval comparisons.

Under independent uniform digest trials, the expected total is

```
35 * 4 * (512/509) * 2^56 = approximately 2^63.13776 compressions.
```

This is an expectation, not a guaranteed upper bound. With a hard budget of
`2^64` compressions, the corresponding Poisson approximation gives roughly
**99.9965% probability** of completing all 35 grinds. This calculation does
not price memory traffic, comparisons, implementation overhead, or the fixed
setup work as SHA256 compressions. The production grind was not run.

## Smaller lookup alternative

The exact-length destructive HASH160 table uses 11-of-64 in each of 52 inputs:
3,328 candidate keys, 572 revealed scalars, script 1,559 bytes, serialized
witness 2,553 bytes, 192 charged opcodes and 11 sigops per input. It has 11
index-hint items and 33 data items per input, all present at entry; the complete
witness has 34 items. The analytical combined-stack bound is 101. Totals are
572 hints, 1,716 data items and 1,768 complete witness items across independent
input executions.

Funding is 2,347 vbytes and publication is 36,420 vbytes: **38,767 combined**.
Its aligned midstate also gives four compressions per trial. Expected honest
work is `208*(512/509)*2^56`, approximately `2^63.70892`; completion within
`2^64` compressions is approximately 93.95% under the same model. The 629-byte
saving trades away substantial grinding headroom and introduces inner HASH160
key commitments. The direct-key CMS profile avoids that extra
commitment layer.

The compact lookup checks the *actual* CHECKSIG signature operand's exact
length after table authentication. This rejects depth-zero/depth-one aliases
that otherwise leave a 20-byte table hash in that operand. Out-of-range and
negative ROLL indices fail natively. Distinctness follows from destructive
removal of the authenticated hash entry, subject to the table binding
assumption and distinct setup entries.

## Evidence and reproduction

The [source](../../examples/pointlock_windowed_size_probe.rs) compiles every
script with `compile_with_policy()` and serializes both complete transactions.
The [quick comparison](windowed-size-quick.json) and
[batched comparison](windowed-batched-size.json) contain measured rows;
this bounded scan does not establish a global byte optimum.

```sh
cargo run --locked --example pointlock_windowed_size_probe -- --quick
cargo run --locked --example pointlock_windowed_size_probe -- --quick --batch-only
```

Production 53-byte sizing: **locally-reproduced**, deployment **unclassified**.
The separate [native Core fixture](windowed_native_core_check.json) initially
validated the same compact lookup with two 3-of-8 pools at the inexpensive
59-byte cap, including 13 malformed cases and all six scalar extractions:
**differentially-validated**, **policy-validated**, Core 30.3 at
`49faec4f87f5cd19c88db01a82e5c68b087c8227`. Its larger cap tests transaction and
Script functionality; it does not demonstrate production work or the
production short-signature assumption. A full batched fixture is separate
from this serialization probe.
