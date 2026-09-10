# Constant-sum Winternitz for 20-byte messages

The newer [constant-composition construction](winternitz-constant-composition20.md)
reduces the same terminal boundary to 2,400 bytes isolated or 2,498 bytes composable.
This page retains the separate mixed-radix construction and its measurements.

`ConstantSumWinternitz20<H = Hash160, P = Preimage16>` losslessly encodes an
unchanged 20-byte message into 41 mixed-radix digits with a fixed sum. It
removes separate checksum chains and verifies the complete vector before
consuming it. There is no onchain message recovery, padding search, or
truncation of the 160-bit input.

- **Question:** can a terminal-only verifier reduce locking-script plus
  serialized signature-witness bytes for every 20-byte input by changing the
  host encoding and lookup relation?
- **Comparison objective:** minimize that combined onchain boundary; report
  locking bytes separately, deterministic fixtures, exact or explicitly
  sampled means, signer-witness maxima, and stack/resource costs.
- **Parameters:** 32 radix-16 coordinates, four radix-18 coordinates, five
  radix-20 coordinates; all 41 digits sum to 321. Each chain has `radix - 1`
  native hash steps. HASH160 and 16-byte initial secrets are the defaults.
  SHA-256, SHA-256/HASH160 commitments, and full-width starts are explicit
  alternatives with matching typed keys and witnesses.
- **Implementation:** [constant_sum.rs](../../src/signatures/winternitz/constant_sum/mod.rs),
  [shared chain generator](../../src/signatures/winternitz/constant_sum/chain.rs),
  [implementation README](../../src/signatures/winternitz/constant_sum/README.md),
  and catalog record `signature/winternitz-constant-sum20`.
- **Evidence:** script correctness and costs are `locally-reproduced`.
  Independent Python encoder/vector and exact-moment checks are separate
  from Script execution. The upper-guard omission has an `inspected` local
  security argument, not a new end-to-end security proof.
- **Execution:** published metrics are `research-unlimited`; the tapscript
  metric helper disables the stack check and appends `OP_TRUE`. Separate
  strict-stack tests have `unclassified` deployment status. No Bitcoin Core
  consensus, relay-policy, or complete-transaction validation is established.

## Lossless encoding and its boundary

The coefficient of `x^321` in
`(1+x+...+x^15)^32 (1+x+...+x^17)^4 (1+x+...+x^19)^5` is exactly
`1470691080098966924606702294670956744709470421906`, which exceeds `2^160`.
The host interprets the 20 input bytes as a big-endian integer and un-ranks it
within the first `2^160` lexicographic vectors. Exact integer suffix counts
support ranking and unranking; floating-point approximations play no role in
capacity or encoding.

`encode_message` and `decode_message` are inverses on all 20-byte messages.
The decoder rejects a wrong digit count, a digit outside its radix, a wrong
sum, and any otherwise valid vector ranked at or above `2^160`. Script does
not run that decoder or enforce the rank bound. Even
`checksig_verify_bounded_and_clear` accepts a larger fixed-sum antichain than
the host encoder uses. Protocols requiring canonical onchain byte binding or
recovered message bytes must provide that additional construction and count
its cost; the measured terminal fragment does neither.

BitVM3 can handle this reversible representation without requiring its
publication Script to recover the original bytes. Onchain byte recovery is
a consumer-specific requirement, not a general incompatibility with BitVM3.
The [integration contract](../../src/signatures/winternitz/constant_sum/README.md#bitvm3-integration-and-byte-recovery)
distinguishes the signature fragment from the surrounding protocol, including
handling of publications outside the host encoder's image.

The namespace binds `bitcoin-lab/winternitz20-constant-sum/v1`, the selected
hash domain, preimage domain, complete radix vector, sum, and signing seed.
Public keys contain 41 independent endpoint commitments. Switching from the
existing Fast encoding requires newly derived keys and signatures; persist
the encoding, hash, and preimage mode alongside the seed.

## Whole-vector verification without individual upper guards

For the default HASH160 profile, witness chunks are `[node_i, digit_i]`.
The verifier includes each raw digit unchanged in an exact sum and uses it
to select a chain-table entry. Negative indices and oversized ScriptNums
fail. An above-range index may escape its chain's table and select a matching
preceding witness value. The fragment therefore provides no standalone local
radix or chain-opening guarantee for that coordinate.

The following is a local inference under honestly generated independent chain
keys, canonical signer digits, one-time use, and the standard chain
inversion/collision assumptions. Every honest digit `d_i` is below its radix.
An alternative out-of-range digit `d'_i` must be greater than `d_i`.
If a different vector passes the same fixed sum, at least one other
coordinate must decrease. Since `d'_j < d_j < radix_j`, the decreased
coordinate remains inside its own lookup table and must supply an earlier
node in that chain. Reading a foreign endpoint on an increased coordinate
does not remove this necessary decrease. ScriptNum addition is exact rather
than modular; arithmetic overflow does not wrap into a valid sum.

This argument belongs to the whole terminal composition. Do not reuse an
unguarded chain fragment to authenticate an independent digit or recover a
locally validated numeric value. `checksig_verify_bounded_and_clear` adds
explicit upper rejection before each chain, at additional script cost.
Both variants still omit canonical raw node-width checks and the host rank
bound. Raw ScriptNum serialization is not part of the authenticated message.
The unbounded relation is broader than the boxed code: a party knowing all
signing secrets can produce an accepted out-of-radix same-sum vector, which
the bounded method rejects. This does not exhibit a forgery from one
canonical signature; it makes the accepted-domain distinction explicit.

SHA-256 variants use the same encoder with 123 witness items, in chunks
`[q_i, node_i, b_i]`, where honest `q_i = digit_i / 2` and
`b_i = 1 - digit_i % 2`. The exact raw value `2*q_i + 1 - b_i` enters the sum;
it is not clamped. Tapscript `MINIMALIF` validates the bit. Every radix is even,
so valid nonnegative quotients and canonical bits recover nonnegative digits.
The same whole-vector argument applies. The bounded method rejects a quotient
at or above half its chain radix.

Constant-sum encoding is established research, `reported` in Zhang, Cui, and
Yu's [ePrint 2023/850](https://eprint.iacr.org/2023/850), received 2023-06-06,
source `constant-sum-wots-2023`. That paper analyzes constant-sum WOTS+; its
results do not prove this custom unkeyed implementation or the Script-specific
upper-guard omission. These are separate evidence claims.

## Measured onchain boundary

All configurations below use Preimage16, seed `[0x42;32]`, final
policy-produced scripts, and a terminal contract. The first three use HASH160.
Locking fragments contain
all commitments, chain verification, sum/checksum verification, and cleanup.
Witnesses include the complete signature item vector and its serialization.
The final predicate, script-item framing, control block, and transaction
overhead are excluded equally. These are byte sums, not full transaction
weights.

| Terminal construction | Script bytes | Zero witness / sum | Maximum signer witness / sum | Entry data items / hints | Combined peak | Static non-push opcodes |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Fast base-16 HASH160 clamped | 2,819 | 785 / 3,604 | 990 / 3,809 | 86 / 0 | 95 | 1,829 |
| Constant-sum HASH160 default | 2,680 | 839 / 3,519 | 944 / 3,624 | 82 / 0 | 93 | 1,774 |
| Constant-sum HASH160 bounded | 2,853 | 839 / 3,692 | 944 / 3,797 | 82 / 0 | 93 | 1,897 |
| Constant-sum SHA-256 | 2,832 | 1,142 / 3,974 | 1,517 / 4,349 | 123 / 0 | 133 | 1,475 |
| Constant-sum hybrid | 2,381 | 1,142 / 3,523 | 1,517 / 3,898 | 123 / 0 | 133 | 1,516 |

The constant-sum fragment saves 139 locking bytes and 185 bytes at the maximum
signer-witness boundary. Its all-`ff` witness is 934 bytes and its varied
`(37*i) mod 256` witness is 924 bytes, giving totals of 3,614 and 3,604.
Exact counting over all `2^160` message ranks gives an approximately
931.841783370768-byte mean witness and 3,611.841783370768-byte mean total.
The maximum 944 bytes is attained by a valid encoded message; it does not
bound accepted hostile raw encodings.

Independent exact counting gives the baseline mean witness approximately
976.262466089252 bytes and mean total 3,795.262466089252 bytes. Thus the
constant-sum default saves approximately 183.420682718484 bytes in the exact
uniform-message expectation, or 4.83%. These decimals are rounded displays
of exact integer/rational counts over the same `2^160` inputs, not samples.
The [README](../../src/signatures/winternitz/constant_sum/README.md#measured-20-byte-costs-and-execution-boundary)
contains metric markers for all fixtures, the bounded profile, both wider
hash choices, static non-push opcodes, and corresponding stack peaks.
Executed-opcode and validation-budget measurements are not available.

Every default signature has 82 entry data items and zero auxiliary hints;
all coexist at entry. The 93-item peak includes both stacks, the lookup table,
and sum accumulator. The baseline's 86 items also need zero hints. SHA-256
variants have 123 entry data items and zero hints; use their separately
measured peaks when composing them. Unrelated state must fit under the same
1,000-item combined main/alt-stack limit. Each terminal method preserves
unrelated stack state and leaves no result, requiring the caller's predicate.

All reported metrics remain `locally-reproduced` and `research-unlimited`,
using the stack-limit-disabled tapscript helper with an appended `OP_TRUE`.
These measurements used `rust-bitcoin-script` revision
`124b561ed75ac3ec4c6ad99207d8dcdd3bc67180` and executor
`bitcoin-scriptexec` revision `ba96bc2bd76774c9d1b011461cb79d983c2c43a1`.
Separate strict-stack tests are `unclassified` for deployment and do not
establish Bitcoin Core consensus or policy acceptance.

## Limits and reproduction

`src/signatures/winternitz/constant_sum/tests/vectors.py` independently reproduces the code capacity,
encoder, host key/signature vectors, exact witness mean, and attained maximum.
It uses Python integer arithmetic and standard-library hashes without loading
the Rust implementation. Rust tests compare fixed vectors and exercise
roundtrips, malformed encodings, unused ranks, sum changes, forwarded chains,
overflow traps, and preserved stack state.

The historical executor could panic when `OP_PICK` addressed outside the
entire stack. The lab now pins repaired interpreter `4b7269a`; see
[adoption and scope](../negative-results/index.md#nr-048-minimal-push-policy-must-follow-execution).
Tests of table escape place their matching trap inside the complete stack.
They establish the intended overflow relation, independently of executor
bounds handling. The later [Core fixtures](../core-validation.md) confirm exact
`OP_PICK`/`OP_ROLL` boundary rejection, not this construction's complete protocol.
The historical metrics retain the tool revisions and evidence classes above. See
[NR-041](../negative-results/index.md#nr-041-20-byte-winternitz-search-and-overflow-relation-boundaries).

The key is strictly one-time. Consuming the Rust key does not prevent restored
seeds, rollback, or concurrent signers. Preimage16 caps generic single-target
initial-secret search at 128 bits; HASH160 commitments retain an approximately
80-bit generic collision bound. Wider intermediate nodes do not strengthen
the hybrid's 20-byte commitment collision bound. Concrete multi-target losses,
the local whole-vector inference, strict Core execution, and complete protocol
costs remain under [OP-009](../open-problems.md#op-009--one-time-authentication-security-profiles).

See also the [signature comparison](../comparisons/signatures.md),
[state-transport protocol](../protocols/one-time-state-transport.md), and
[Fast base-16 primitive](winternitz-fast-base16.md).
