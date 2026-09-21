# Windowed ECDSA publication — rejected for impractical setup

**Disposition: rejected as a solution to the user's task.** The expected
`2^63.138` SHA256 compression calls are impractical. Meeting the historical
`2^64` research ceiling and the on-chain size target does not make this an
acceptable replacement for practical algebraic setup. The unproved
short-signature assumption is an additional unresolved cost of the change.

The measurements and reduced-work fixtures below are retained as research
evidence, not as a recommendation. Further sub-100,000-vB candidates must
have practical setup; the no-ZKP requirement remains in force. Making the
signature cap looser is not an established repair because it also changes
the extraction assumption. See the [negative-result record](../../knowledge/negative-results/windowed-pointlock-setup-cost.md).

Question: can an arbitrary, later-chosen 256-byte value be published through
precommitted selectable point labels, counting both creation and spending,
with noninteractive algebraic setup and no setup ZKP?

**A conditional construction sizes to 39,396 vB.** It uses P2WSH, four
six-of-nineteen CHECKMULTISIG blocks per input, and a shared search that makes
every candidate signature short. The 256-byte payload is not compressed.
There are 35 point-lock inputs, 2,660 candidate labels, and 840 revelations.

This changes the cryptographic guarantee. The earlier sum-key lock has an
exact extraction equation for every accepted signature. Here extraction
depends on the computational difficulty of producing an alternative short
signature with a nonce other than `+/-G/2`. That condition is **not proved**
by the size check. The construction is a research candidate, not a completed
security validation or a production-mined 53-byte publication.

## Setup and the shared search

Write `n` for the secp256k1 group order, `G` for its generator, and

```text
k0 = 1/2 mod n
r0 = x(k0 G)
   = 0x3b78ce563f89a0ed9414f5aa28ad0d96d6795f9c63.
```

The positive DER encoding of `r0` has 21 bytes. For each P2WSH input, choose
a fresh secret base `b` and 76 distinct, independently sampled hidden offsets
`a_i` in `[0, 2^190)`. Define

```text
t_i = b + a_i/(2r0) mod n
T_i = t_i G.
```

Reject zero or duplicate target scalars. Keep the base, offsets, and scalars
secret; publish the target points. Partition these 76 points into four
independent six-of-nineteen selection blocks. The blocks share the base only
to amortize the search. Different inputs use independent bases.

Commit the points in their P2WSH scripts and construct the funding transaction.
Only then compute the real BIP143 hashes. Each point-lock input uses
SIGHASH_SINGLE|ANYONECANPAY and has its own corresponding zero-value output
containing `OP_RETURN <eight-byte nonce>`. Changing that nonce changes this
input's digest without changing the other point-lock inputs' digests.

With actual digest scalar `z`, signing under any `T_i` with nonce `k0` gives

```text
s_i = (z + r0*t_i)/k0 mod n
    = 2z + 2r0*b + a_i mod n.
```

All 76 signature scalars are therefore a common center plus hidden small
offsets. Search for one center making every normalized `s_i` have 25 DER
bytes. Every signature item then has `7 + 21 + 25 = 53` bytes, including
its sighash byte. The conservative search uses either common-sign band:

```text
2^191 <= s_i < 2^199                 for every i,
or
2^191 <= n-s_i < 2^199               for every i.
```

The setup can prepare all 76 openings before knowing the eventual message.
Later, any six labels in each block can be selected with no new search.
No point is defined using an unknown future digest, so there is no funding
fixed-point equation. The corresponding output nonces are fixed after search;
the eventual choice only changes the witnesses.

## Script and encoding

For each block, the witness supplies an empty CHECKMULTISIG dummy and six
signatures. The script checks each signature's size, temporarily preserves
it on the altstack, restores the signatures, and evaluates six-of-nineteen
CHECKMULTISIG over the embedded compressed target keys. Intermediate blocks
verify their result; the final result is a clean truth value. The witness
orders the four blocks opposite their execution order.

Conceptually, one block is:

```text
# Main-stack top: six signatures; the block's dummy is below them.
repeat 6: OP_SIZE 53 OP_LESSTHANOREQUAL OP_VERIFY OP_TOALTSTACK
repeat 6: OP_FROMALTSTACK
6 <T_0> ... <T_18> 19 OP_CHECKMULTISIGVERIFY
```

The actual generator uses the centralized compilation policy. It is in
[the sizing source](../../examples/pointlock_windowed_size_probe.rs), alongside
the alternative HASH160 lookup implementation. The snippet is explanatory;
the compiled complete script determines all measurements.

Each block has `binomial(19,6)=27,132` subsets. Encode the 256-byte big-endian
integer in 140 mixed-radix digits, each a canonical subset rank. Capacity is

```text
binomial(19,6)^140 > 2^2048
log2(capacity) = 2061.879088846176.
```

Fixed local thresholds prevent deleting an opening while preserving that
input's validity. Reveal order does not contribute message bits. Independent
decoding must identify the selected keys, extract their scalars, and recover
the same subset ranks. Values outside the 256-byte range are not codewords.
This does not by itself force all 35 UTXOs into one transaction; the surrounding
BitVM transaction protocol still has to bind its required input set.

## Full transaction accounting

The boundary starts with one existing P2TR funding UTXO. Funding creates a
first P2TR helper output and all 35 P2WSH outputs. Assertion consumes the
helper and every point-lock output, and creates a first P2TR output plus all
35 corresponding nonce outputs. Both helper signatures are 64 bytes.

| Transaction | Production-profile vbytes |
| --- | ---: |
| Funding | 1,616 |
| Assertion | 37,780 |
| **Combined** | **39,396** |

These are complete serialization measurements with 53-byte placeholder
signatures, not transactions claiming to satisfy the production search.
Every created and consumed output, every 19-byte nonce output, CompactSize
field, witness vector, and per-transaction rounding is included. Creating
the initial funding UTXO, extra change, refunds, and the rest of BitVM3 are
outside the boundary. The 256-byte proof is encoded by the selected subsets;
it is not an extra unattested data output.

Per input, the compiled script is 2,761 bytes, the complete witness is
4,065 bytes, and there are 28 entry data items: 24 signatures and four empty
dummies. There are **zero auxiliary hint items**, per block, per input, and
across the entire 35-input publication. The script itself is an additional
witness item. Entry stacks of different inputs do not coexist. The static
charged operation count is 192; witness-v0's 201-operation rule applies.
The analytical combined main-plus-alt-stack bound is 52. Policy counts 80
sigops per input, or 2,800 across the publication; lists above OP_16 receive
the conservative twenty-sigop charge even though each list has nineteen
keys. Across all inputs there are 980 entry items and 1,015 complete witness
items, excluding the helper. See the [sizing report](windowed-sizing.md).

The smaller HASH160 alternative uses 52 eleven-of-sixty-four pools and
572 revelations. It sizes to **38,767 vB**, including the same helper and
nonce-output boundary, but requires 52 searches instead of 35 and introduces
inner HASH160 key commitments. The 629-vB premium for the direct-key profile
buys fewer searches and removes that additional collision-binding assumption.

## Honest work and security boundary

For offsets below `2^190`, the conservative exact-length bands have success
probability at least approximately `(509/512)*2^-56` per independent native
digest. Midstate reuse for the measured scripts needs four SHA256 compression
calls per trial: two for the serialized nonce output and two for the native
signature digest. Interval endpoints can be precomputed; field multiplication
is not required per search trial.

The expected search count for 35 inputs is therefore bounded in the random-hash
model by

```text
140 * (512/509) * 2^56 = approximately 2^63.138
SHA256 compression calls.
```

This is a very large **expected-work** figure, not guaranteed completion in
that many operations or an observed run. Under the independent-search model,
a hard `2^64` compression budget completes all 35 searches with approximately
99.9965% probability. Setup and verification also require a few thousand
curve operations and ordinary bookkeeping; those are separate work units.
The implementation has not performed the production search or benchmarked
its complete hardware cost.

If an accepted signature uses `r0`, extraction tries

```text
t = (s*(+/-k0) - z)/r0 mod n
```

and selects the scalar satisfying `tG=T_i`. The unknown condition is the cost
of an accepted signature using another nonce. The current review gives
conditional search estimates, **not a lower bound or a proof of 80-bit
security**. Arbitrary malicious setup, adaptive transactions, all permitted
sighash modes, preprocessing, and multiple targets must be included in any
eventual security claim.

The hidden-offset trick also creates publicly visible bounded differences:
`2r0*(T_i-T_j)=(a_i-a_j)G`. They do not reveal the hidden numerical offsets,
but reduce single-target generic discrete-log estimates to roughly 95 bits,
before multi-instance refinements. These are correlated computationally
hidden labels, not independent 256-bit scalar secrets. Their use in the
complete garbled protocol needs review.

See the independent [algebra and assumption review](windowed-small-r-review.md).
The production candidate has `locally-reproduced` serialization and
`inspected` algebra; its deployment class is `unclassified`. Reduced-work
native Core fixtures validate the execution and accounting of their own
parameters, not the unperformed production search or its security assumption.

## Native execution evidence

The [native validation note](windowed-native-validation.md) and
[complete reduced-work Core report](windowedbatch256_native_core_check.json)
uses the same 35-input, four-six-of-nineteen layout with a 59-byte ceiling.
It performs the real native search at that easier parameter, uses 9,165
digest trials, and checks every candidate signature against its actual BIP143
digest. Both transactions pass default Core 30.3 policy and are mined on
isolated regtest. Independent Python extraction checks all 840 selected
scalars and reconstructs the exact original 256-byte synthetic payload.

| Reduced-work transaction | Weight | Actual vbytes |
| --- | ---: | ---: |
| Funding | 6,464 | 1,616 |
| Assertion | 156,159 | 39,040 |
| **Combined** | **162,623** | **40,656** |

Its 840 signatures are six bytes longer than the production profile,
accounting for exactly `840*6/4 = 1,260` additional vbytes. The complete
[native transaction artifact](windowedbatch256-native-transactions.json)
preserves the fixture. All fixture secrets are deterministic public test
data, not a production setup.

This exact reduced-work fixture is `differentially-validated` and
`policy-validated`, against Core commit
`49faec4f87f5cd19c88db01a82e5c68b087c8227`. It demonstrates the native digest
independence, complete transaction shape, subset encoding and honest
extraction. **It does not validate the production security assumption or
perform the 53-byte search.** The 59-byte ceiling is an execution test
parameter, not a recommended security parameter. The separate small lookup
[Core fixture](windowed_native_core_check.json) rejects thirteen malformed
cases, including oversized signatures, missing/duplicate selections and
unauthenticated lookup aliases.

```sh
python3 research/pointlocks-2026-09-17/windowed_native_core_check.py --profile batch256
```

The witness-v0 CHECKMULTISIG result comes from Core; the pinned local script
interpreter does not implement that opcode. Its production combined-stack
figure remains an analytical bound rather than a local execution measurement.
Regenerating the reduced-work fixture from the same funding outpoint exactly
matches every saved artifact field. The
[source manifest](windowed-validation-source-manifest.json) records the
corresponding source and artifact SHA256 hashes.

## Other routes and evidence

The [explicit-table lower bound](sub100-lookup.md) explains why changing only
the earlier legacy lookup cannot reach 100,000 vB. This construction escapes
that representation by using witness discount and a different point lock.

If the original 256 bytes are specifically an uncompressed BN254 Groth16
proof, the separate [lossless-compression route](conditional-proof-compression.md)
has a Core-validated 128-byte publication at 92,706 vB using the existing
algebraic sum-key primitive. That conditional result does not replace the
arbitrary-256-byte target addressed here.

Primary specifications: [BIP143](https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki)
for the native digest and SINGLE|ANYONECANPAY behavior,
[BIP66](https://github.com/bitcoin/bips/blob/master/bip-0066.mediawiki) for strict
DER, and [BIP141](https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki)
for witness serialization and execution. The known small-R observation is
discussed in [Binohash](https://robinlinus.com/binohash.pdf); the windowed setup
and its estimates here are separate research, not claims attributed to that paper.
