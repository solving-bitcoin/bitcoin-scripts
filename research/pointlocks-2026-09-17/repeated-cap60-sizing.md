# Rejected repeated short-signature checks: size probe

The question is whether three or four capped native ECDSA checks per selected
point could replace expensive window grinding and still publish any future
256-byte message below 100,000 total creation-plus-spending vbytes. Honest
signatures use the known nonce `G/2`, and each verification key is a publicly
specified nonzero scalar multiple of the same target point. Whether repeating
those checks amplifies the exceptional-short-signature difficulty is a separate
unproven claim; this note measures its serialization cost.

This candidate is **rejected**. The script does not constrain the signatures'
sighash modes: different modes can expose separately variable transaction
fields, invalidating the assumed amplification from several short-signature
conditions on one shared native digest. Even setting that issue aside, the
concrete aligned-key selector does **not** meet the size target. In the
bounded scan, three repetitions cost at least 130,182 vbytes before splitting
an oversized spending transaction. Four repetitions already have a
112,793-vbyte representation cost in the fixed-60-byte-signature model,
before all opcodes and transaction costs.

## Fixed-length representation model

For each independently selectable label, store all `d` verification keys or
all `d` HASH160 key commitments. A selected label supplies `d` signatures,
each modeled as 60 bytes, and any opened keys. Giving all these bytes the
witness discount and granting zero opcode, index, wrapper and transaction cost:

| Representation | One-replica fixed bytes | One-replica selected bytes | d=3 minimum for 2,048 bits | d=4 minimum |
|---|---:|---:|---:|---:|
| HASH160 key table | 21 | 95 | 84,594.99 vB | 112,793.32 vB |
| Embedded compressed keys | 34 | 61 | 90,874.06 vB | 121,165.41 vB |

The minimum is `2048*(d/4)*min_p((a+b*p)/H2(p))`. Entropy is counted per label,
not per replica: the repeated scaled keys describe the same target secret.
As in the earlier [table analysis](sub100-lookup.md), this is a bound for the
stated representation, not an impossibility result for all Bitcoin primitives.
In particular, a 60-byte maximum is not a 60-byte minimum. These numerical
bounds assume that selected signatures are 60 bytes, as in the serialized
probe; a construction producing shorter signatures must be costed separately.
They must not be quoted as universal lower bounds for every capped-signature
construction.

## Concrete aligned-row script

Store the `d` compressed keys of each label contiguously on the main stack.
One witness index selects the whole row. Multiply that index by `d`, add two,
then repeatedly ROLL the next key of the selected row and CHECKSIGVERIFY it
against the corresponding capped signature. Removing the entire row enforces
distinct selected labels. It also binds all replicas to that same label;
independent multisig layers would not establish that property.

For a row whose `j` labels lie above it in the remaining table, the witness
index is `j`. The computed depth is `d*j+2`. All `d` signatures follow that
index, in reverse key order. The signature length guard is `SIZE <= 60`.
The index and signatures are initially staged on altstack. No point/key
opening items are needed because this profile embeds the complete keys.

| Best sampled profile | d=3 | d=4 |
|---|---:|---:|
| Threshold | 5 of 19 | 4 of 15 |
| Number of inputs/pools | 152 | 197 |
| Script bytes per input | 2,155 | 2,259 |
| Serialized witness per input | 3,084 | 3,247 |
| Charged opcodes | 181 | 182 |
| CHECKSIG operations | 15 | 16 |
| Index-hint items per input | 5 | 4 |
| Entry data items per input | 20 | 20 |
| Analytical combined-stack upper bound | 81 | 84 |
| Funding vbytes | 6,647 | 8,582 |
| Single spending transaction vbytes | 123,535 | 168,103 |
| Combined vbytes | **130,182** | **176,685** |

The scan covers `n=4..35`, thresholds below eight, both replica counts, and
retains scripts within 3,600 bytes, 201 charged opcodes and 100 entry items.
It is not a global optimization certificate. Two full transaction serializations
include one original P2TR input, a first P2TR helper output, every P2WSH output,
and a spending transaction consuming all outputs into one P2TR output. Honest
setup requires no digest nonce outputs in this capped-signature variant.
Signatures in the measured transactions are placeholders, not a funded native
P2WSH reproduction. The two selected layouts are additionally exercised with
real known-nonce ECDSA signatures under a legacy constant-digest fixture; that
checks stack/index behavior, not the intended native P2WSH transaction context.

The single spending transactions exceed the 400,000-weight standardness limit.
Splitting either publication into two helper-linked spending transactions adds
approximately 111 vbytes, before any extra protocol requirements. The failure
to reach 100,000 vbytes already holds for the cheaper unsplit accounting.
For d=3 the entire publication has 760 index hints and 3,040 entry data items;
for d=4 it has 788 hints and 3,940 entry data items. Each input executes
independently, so these totals do not coexist on one Script stack. The bounds
include the staged signatures and indices on altstack.

## Why simply sharing the related keys is insufficient

Legacy/SegWit ECDSA consumes a complete 33- or 65-byte serialized public key.
With current enabled stack/hash/arithmetic opcodes, a compressed 33-byte key
must originate as an intact pushed item: native hashes produce 20 or 32 bytes,
and arithmetic produces at most five-byte ScriptNums. No CAT or substring
operation reconstructs or extracts the missing bytes. This is a statement
about these constructors, not a universal lower bound on Script computation.

Public verification of `P_j=a_j*T` during setup does not let the locking script
accept arbitrary replacement P_j values supplied later. Each key still needs
an authenticated representation. Reusing signature bytes as public keys does
not supply one: strict DER signatures start with 0x30, whereas compressed
ECDSA keys start with 0x02 or 0x03. A hash blob containing several keys also
needs an unavailable extraction operation to bind the separately supplied
keys to that blob.

An unrestricted CHECKMULTISIG layer for each replica lets the spender select
different labels in each layer. Honest signatures for unrelated selected
labels then do not amplify the point lock for a label with one exceptional
signature. The selection must be tied across layers or the protocol must
provide a separate argument; neither extra capacity nor amplification can be
credited merely from independent multisig acceptance.

Source: [pointlock_repeated_size_probe.rs](../../examples/pointlock_repeated_size_probe.rs).
Output: [repeated-cap60-size.json](repeated-cap60-size.json). All scripts use
`compile_with_policy()`. Evidence: **locally-reproduced** compilation and
serialization. Deployment class: **unclassified**. No native P2WSH Core result,
cryptographic amplification proof or production point-lock guarantee is claimed.

The sighash separation follows from [BIP143](https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki):
NONE does not commit outputs, SINGLE commits its corresponding output, and ALL
commits every output. Consequently, several checks do not automatically impose
several conditions on one common digest. This is an `inspected` objection to
that assumption, not a measured work factor for a complete construction.

```sh
cargo run --locked --example pointlock_repeated_size_probe
```
