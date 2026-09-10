# Constant-sum Winternitz for 20-byte messages

For the smallest tested terminal cost, see [constant-composition](../constant_composition/README.md):
2,400 bytes isolated or 2,498 bytes composable, compared with this construction's
3,624-byte maximum. The mixed-radix construction below remains a separate encoding
with its own keys and witness format.

`ConstantSumWinternitz20<H = Hash160, P = Preimage16>` is a separate terminal
construction for exactly 20 unchanged message bytes. It reduces the measured
locking fragment plus serialized signature data. The host treats the message as a
big-endian rank and reversibly encodes it into 41 digits: 32 radix-16 digits,
four radix-18 digits, and five radix-20 digits, with digit sum 321. There are
no separate checksum chains, no padding search, and no message truncation.
The digits are enumerative code coordinates, not the original byte nibbles.

The number of bounded vectors with that sum is
`1470691080098966924606702294670956744709470421906`, exceeding `2^160`.
`encode_message` selects the first `2^160` vectors in lexicographic order;
`decode_message` checks digit count, ranges, sum, and rank below `2^160`.
Both use exact integer suffix counts. Script verifies the terminal relation
and does not implement this host decoder or its final rank bound. Even the
bounded verifier consequently accepts a larger antichain than the host
encoder uses. This is appropriate only when the surrounding protocol needs
verification and consumption, rather than recovered bytes or proof of a
canonical onchain byte encoding.

```rust
use bitcoin_lab::signatures::winternitz::ConstantSumWinternitz20;
type Wots = ConstantSumWinternitz20;
let message = [0x42; 20];
let key = Wots::generate_signing_key();
let public_key = Wots::public_key(&key);
let signature = Wots::sign(key, &message);
assert_eq!(Wots::decode_message(signature.digits()).unwrap(), message);
let script = Wots::checksig_verify_and_clear(&public_key);
let witness = signature.to_witness();
assert_eq!(witness.len(), 82);
// Append the surrounding protocol's terminal predicate.
```

The hash choices are `Hash160`, `Sha256`, and `Sha256Hash160`; start modes
are `Preimage16` and `FullWidth`. Every choice has matching typed keys,
commitments, and signatures. The namespace binds the constant-sum domain,
hash domain, preimage domain, radix vector, sum, and seed. Persist the complete
configuration and never reuse the seed after signing. Existing Fast keys and
witnesses cannot be substituted for this construction.

## Terminal relation and the omitted upper bounds

The smallest verifier omits individual upper-digit guards. For HASH160 it
uses numeric witnesses `[node_i, digit_i]`; an above-range `OP_PICK` index can
read a matching value from preceding witness or protocol state. Such a
coordinate is not independently range-checked or locally authenticated. Its
raw nonnegative numeric value is nevertheless included unchanged in the
fixed sum. SHA-256 variants use `[digit_i / 2, node_i, 1 - digit_i % 2]` and
include the equivalent raw digit `2*q + 1 - b`; `MINIMALIF` enforces the bit.
Negative lookup indices and oversized ScriptNums fail.

The security argument is a **local inference**, under honestly generated
independent chain keys, a canonical signer vector, one-time use, and the
ordinary chain inversion/collision assumptions. Every honest digit is below
its chain radix. An overflowing alternative digit is therefore strictly
larger than the signed one, even if its lookup escapes. Any distinct vector
with the same exact sum must also decrease some coordinate. That decreased
coordinate is in range, so its lookup remains inside its own chain table and
requires an earlier chain node. The sum uses non-wrapping ScriptNum arithmetic.
This argument depends on the complete fixed-sum composition; these chain
fragments must not be reused as standalone digit authenticators.
The unbounded relation is broader than the boxed code: someone holding all
signing secrets can construct an accepted out-of-radix same-sum vector, which
the bounded method rejects. That is not a forgery from a canonical signature;
it demonstrates that canonical onchain encoding is not the claimed relation.

`checksig_verify_bounded_and_clear` adds explicit radix rejection before each
chain. It still omits the host rank bound and raw node-width checks. Both
terminal methods intentionally accept the size-profile preimage relation:
only signer-produced starts are guaranteed to be 16 bytes. HASH160/SHA-256
maximum digits compare with native endpoints; hybrid maximum digits also
execute the final commitment hash. Neither method supplies canonical raw
witness serialization or a general WOTS+ security proof.

The general constant-sum method is established research: Zhang, Cui, and Yu,
[ePrint 2023/850](https://eprint.iacr.org/2023/850), received 2023-06-06
(`constant-sum-wots-2023`). Its WOTS+ analysis does not prove this custom
unkeyed Script implementation or the omitted-upper-guard argument above.

## Measured 20-byte costs and execution boundary

The default results use seed `[0x42;32]`, the final compilation policy, and
fragment-only locking scripts containing all commitments, chain checks, sum
verification, and cleanup. Signature witnesses include the item count and
all item-length prefixes. The final predicate, script-item framing, control
block, and transaction overhead are excluded on both sides. The zero fixture
is `[0;20]`, all-`ff` is `[0xff;20]`, and varied byte `i` is `(37*i) mod 256`.

All rows below use `Preimage16`. The bounded row adds explicit digit-range
rejection; both constant-sum HASH160 rows use the same signer witness.

The [overview table](../README.md#winternitz-one-time-signatures) lists these 20-byte
script and witness measurements, including both best-cost profiles.

<details>
<summary>Boundary fixtures used by regression checks</summary>

These fixtures check edge cases and are excluded from the comparison table.

- Constant-sum HASH160: zero <!-- metric:w20_sum_hash160_witness_zero -->839<!-- /metric:w20_sum_hash160_witness_zero --> bytes; all-`ff` <!-- metric:w20_sum_hash160_witness_ff -->934<!-- /metric:w20_sum_hash160_witness_ff --> bytes.
- Constant-sum HASH160, bounded: zero <!-- metric:w20_sum_bounded_hash160_witness_zero -->839<!-- /metric:w20_sum_bounded_hash160_witness_zero --> bytes; all-`ff` <!-- metric:w20_sum_bounded_hash160_witness_ff -->934<!-- /metric:w20_sum_bounded_hash160_witness_ff --> bytes.
- Base-16 HASH160 clamped: zero <!-- metric:w20_base16_hash160_witness_zero -->785<!-- /metric:w20_base16_hash160_witness_zero --> bytes; all-`ff` <!-- metric:w20_base16_hash160_witness_ff -->975<!-- /metric:w20_base16_hash160_witness_ff --> bytes.
- Constant-sum hybrid: zero <!-- metric:w20_sum_hybrid_witness_zero -->1142<!-- /metric:w20_sum_hybrid_witness_zero --> bytes; all-`ff` <!-- metric:w20_sum_hybrid_witness_ff -->1454<!-- /metric:w20_sum_hybrid_witness_ff --> bytes.
- Constant-sum SHA-256: zero <!-- metric:w20_sum_sha256_witness_zero -->1142<!-- /metric:w20_sum_sha256_witness_zero --> bytes; all-`ff` <!-- metric:w20_sum_sha256_witness_ff -->1454<!-- /metric:w20_sum_sha256_witness_ff --> bytes.

</details>

| Terminal profile | Combined main/alt-stack peak | Static non-push opcodes | Complete entry data items | Auxiliary hint items |
| --- | ---: | ---: | ---: | ---: |
| Base-16 HASH160 clamped | <!-- metric:w20_base16_hash160_stack -->95<!-- /metric:w20_base16_hash160_stack --> | <!-- metric:w20_base16_hash160_opcodes -->1829<!-- /metric:w20_base16_hash160_opcodes --> | <!-- metric:w20_base16_hash160_items -->86<!-- /metric:w20_base16_hash160_items --> | <!-- metric:w20_base16_hash160_hints -->0<!-- /metric:w20_base16_hash160_hints --> |
| Constant-sum HASH160 | <!-- metric:w20_sum_hash160_stack -->93<!-- /metric:w20_sum_hash160_stack --> | <!-- metric:w20_sum_hash160_opcodes -->1774<!-- /metric:w20_sum_hash160_opcodes --> | <!-- metric:w20_sum_hash160_items -->82<!-- /metric:w20_sum_hash160_items --> | <!-- metric:w20_sum_hash160_hints -->0<!-- /metric:w20_sum_hash160_hints --> |
| Constant-sum HASH160, bounded | <!-- metric:w20_sum_bounded_hash160_stack -->93<!-- /metric:w20_sum_bounded_hash160_stack --> | <!-- metric:w20_sum_bounded_hash160_opcodes -->1897<!-- /metric:w20_sum_bounded_hash160_opcodes --> | <!-- metric:w20_sum_bounded_hash160_items -->82<!-- /metric:w20_sum_bounded_hash160_items --> | <!-- metric:w20_sum_bounded_hash160_hints -->0<!-- /metric:w20_sum_bounded_hash160_hints --> |
| Constant-sum SHA-256 | <!-- metric:w20_sum_sha256_stack -->133<!-- /metric:w20_sum_sha256_stack --> | <!-- metric:w20_sum_sha256_opcodes -->1475<!-- /metric:w20_sum_sha256_opcodes --> | <!-- metric:w20_sum_sha256_items -->123<!-- /metric:w20_sum_sha256_items --> | <!-- metric:w20_sum_sha256_hints -->0<!-- /metric:w20_sum_sha256_hints --> |
| Constant-sum hybrid | <!-- metric:w20_sum_hybrid_stack -->133<!-- /metric:w20_sum_hybrid_stack --> | <!-- metric:w20_sum_hybrid_opcodes -->1516<!-- /metric:w20_sum_hybrid_opcodes --> | <!-- metric:w20_sum_hybrid_items -->123<!-- /metric:w20_sum_hybrid_items --> | <!-- metric:w20_sum_hybrid_hints -->0<!-- /metric:w20_sum_hybrid_hints --> |

The 2,680-byte default fragment plus the 839-byte zero-message witness totals
3,519 bytes. Independent exact counting over all `2^160` messages gives a
mean witness of approximately 931.841783370768 bytes and a mean total of
3,611.841783370768 bytes. The maximum signer witness is exactly 944 bytes;
it bounds honest signatures, not accepted hostile raw encodings.

The existing `FastWinternitz<20, Hash160, Preimage16>` clamped terminal uses
2,819 script bytes and a 990-byte signer-node witness bound, totaling 3,809
bytes. The new 3,624-byte maximum total is 185 bytes smaller. Its script alone
saves 139 bytes. Independent exact counting over all `2^160` messages gives
the baseline mean witness approximately 976.262466089252 bytes and mean total
3,795.262466089252 bytes. The exact uniform-message expectation improves by
approximately 183.420682718484 bytes, or 4.83%. Both means are rounded decimal
displays of exact counts over the same input distribution; neither is sampled.

The hybrid has the smallest locking fragment among these retained profiles,
2,381 bytes, but its 32-byte nonzero openings increase the maximum combined
cost to 3,898 bytes. HASH160 minimizes the measured mean and maximum combined
costs. Explicit HASH160 upper-bound rejection costs 173 additional script
bytes, yielding a 3,797-byte maximum total with the same signer witness.

All 82 default data items coexist at entry; the measured combined peak is 93,
including the lookup table and sum accumulator. The baseline has 86 entry
items and peaks at 95. Both need **zero auxiliary hint items per invocation**.
SHA-256 variants use 123 entry data items, also with zero hints; their separate
measurements must be used when budgeting stack space. Unrelated live state
counts against the same 1,000-item combined stack limit. Both terminal methods
preserve unrelated main/alt-stack state and leave no result; the caller must
append its predicate.

Metrics are `locally-reproduced` and `research-unlimited`: the tapscript metric
helper disables the stack check and appends `OP_TRUE` for execution. Separate
strict-stack tests remain `unclassified` deployment evidence. No Bitcoin Core
consensus, relay-policy, or complete-transaction validation is claimed.
The historical `ba96bc2` executor could panic on an `OP_PICK` index outside the
entire stack. The lab now pins repaired interpreter `4b7269a`; see
[adoption and scope](../../../../knowledge/negative-results/index.md#nr-048-minimal-push-policy-must-follow-execution).
Adversarial lookup-escape tests still place traps inside the complete stack:
they test the construction's overflow relation, independently of executor
bounds handling. The later Core fixtures confirm exact `OP_PICK`/`OP_ROLL`
boundary rejection, not complete constant-sum protocol validity. Historical
metrics retain their original evidence and execution classes. See the
[negative result](../../../../knowledge/negative-results/index.md#nr-041-20-byte-winternitz-search-and-overflow-relation-boundaries).

`python3 src/signatures/winternitz/constant_sum/tests/vectors.py` independently reproduces the encoder,
host vectors, exact witness mean, and exact maximum. Rust tests compare its
fixed outputs, exercise message roundtrips and invalid ranks, and check chain
mutations, sum binding, overflow traps, malformed numbers, and preserved stack
state. See the [constant-sum primitive page](../../../../knowledge/primitives/winternitz-constant-sum20.md),
the [signature comparison](../../../../knowledge/comparisons/signatures.md), and
[OP-009](../../../../knowledge/open-problems.md#op-009--one-time-authentication-security-profiles).

## BitVM3 integration and byte recovery

BitVM3 can handle constant-sum encoding. Reversible representation of the
proof does not alter the proof; a publication script need not reconstruct
the original bytes when the surrounding verification protocol handles that
representation. The [BitVM 3s paper](https://bitvm.org/bitvm3.pdf), July 22,
2025, describes the broader architecture of moving proof verification into
offchain garbled circuits. That architecture is distinct from requiring
Bitcoin Script itself to recover every proof byte.

An integration whose Script consumer requires the original bytes must add
the corresponding decoder or binding check and count its cost. This is a
consumer-specific requirement, not a general incompatibility with BitVM3.

The accepted relation still includes codewords rejected by the host decoder;
the unbounded mode also admits some out-of-radix vectors. Integration must
define how such publications are interpreted, rejected, or challenged. The
current local tests cover the signature relation, not a complete BitVM3
integration or transaction. The measured totals exclude the surrounding
protocol. The paper is architectural context, not validation of this custom
mixed-radix verifier or its omitted-upper-bound argument.

## Source and tests

- [mod.rs](mod.rs): encoder/decoder, typed keys, signing, terminal composition.
- [chain.rs](chain.rs): numeric and strided fixed-sum chain tables.
- [tests/signature.rs](tests/signature.rs): roundtrips, host vectors, malformed
  inputs, forwarding attacks, and exact stack cleanup.
- [tests/chain.rs](tests/chain.rs) and [tests/overflow.rs](tests/overflow.rs):
  chain-table boundaries and accepted out-of-range publications.
- [tests/vectors.py](tests/vectors.py): independent encoding, signatures, and
  exact witness means/maxima, including the ordinary base-16 baseline.

Run `cargo test --locked --lib signatures::winternitz::constant_sum` and
`python3 src/signatures/winternitz/constant_sum/tests/vectors.py`.

## Script compatibility

These are tapscript fragments; bare Script, P2SH, and P2WSH cannot use the
measured scripts under their legacy opcode limits. Strided verification also
relies on tapscript MINIMALIF. No complete transaction or policy validation
is established. See [shared security](../shared/README.md#security).
