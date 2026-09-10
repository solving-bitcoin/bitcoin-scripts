# One-time authenticated state transport

BitVM-style protocols may authenticate intermediate state with one-time hash
constructions so a later script can recover and check individual digits.

## Dependency map

```text
State value
├── digitization (bit, nibble, byte, limb, or field coefficient)
├── message/domain encoding
├── one-time key generation and public commitment
├── witness signature/opening
├── Script verification and recovered value layout
└── enforced key lifecycle across transaction graph
```

Lamport 2-bit, HORS-like subsets, and base-16 Winternitz solve different parts
of this problem. The HORS module does not derive indices from a message. The
Lamport helper authenticates only two bits. Winternitz provides typed message
APIs but requires strict one-time key management and can make state transport
witness-heavy.

The following Fast costs use the default HASH160 chain and `FullWidth`
initial secrets.

The Fast Winternitz path makes the transport boundary more explicit. Numeric
profiles use 134 digit/chain items; the 4,325-byte bitwise recovery profile uses
333 items, peaks at 334, and returns the same 64 high/low nibbles. Its canonical
bits and the exact verifier depend on tapscript `MINIMALIF`. The 4,206-byte
terminal profile peaks at 333 items and clears the message when transport is
unnecessary. The
consuming Rust key prevents ordinary same-process reuse only. Transaction-graph
state, crash rollback, restored seeds, distributed signers, and raw ScriptNum
canonicality remain protocol obligations. Size profiles relax raw chain-item
length; protocols requiring exactly 20-byte signature nodes should use the
4,934-byte strict-chain profile. Fast and legacy witnesses are not
wire-compatible.

The residual-digit exact verifier and staged checksum reduce strict exact
recovery to 5,267 bytes and exact terminal verification to 5,205 bytes without
changing Fast witness encoding. These improvements do not supply durable
reuse prevention. There are zero auxiliary hint items; all 134 numeric or 333 bitwise data items and
any other protocol state contribute to the entry and combined stack limits.
Full tables for narrow checksum digits now reduce HASH160 clamped/strict
numeric fragments by six bytes; strict lookup also removes a redundant
lower-bound check and saves 73 bytes. Its upper bound and `OP_PICK` rejection
of negative indices prevent selectors from reading preceding protocol state.

For total on-chain bytes, the explicit clamped lookup profile uses the same
134-item numeric witness and reduces the zero-message recovery/terminal sums
to 5,941/5,879 bytes. It authenticates the upper-clamped digit, including the
checksum, so protocols that require rejection of above-range raw digit
encodings must choose a strict profile. Lowest locking-script size alone does
not determine transport cost: serialized signature data must also be counted.

Protocol evaluation must count public commitment placement, witness
serialization, recovered-state cleanup, and the transaction graph that prevents
key reuse.

Hash selection is also part of the protocol: `FastWinternitz<N, Sha256>` uses
32-byte chain nodes instead of HASH160's 20-byte nodes, and separate key
derivation domains. Persist the hash choice and construct matching public
commitments before signing. The 32-byte zero-message clamped terminal total
increases from 5,879 to 7,227 bytes; entry item count (134), auxiliary hint
count (0), and combined peak (143) stay the same. SHA-256 pair fusion changes
the profile ranking: bitwise recovery totals 7,152 bytes versus clamped's
7,289, at the cost of 333 entry items and peak 334. These are fragment-plus-data
measurements under `research-unlimited` tapscript execution, not complete
state-transport transaction weights. A wider hash does not replace a concrete
multi-target security argument or durable one-time-key management.


The independent start-mode choice is `FastWinternitz<N, H, Preimage16>`.
Persist it together with the hash and message length: it has separate key
namespace derivation, so existing commitments cannot be reused by changing a
runtime witness encoding. Only zero-valued digits reveal 16-byte initial
secrets; subsequent nodes retain the native width and public commitments
retain the selected commitment width.
The explicit `FullWidth` mode retains existing keys and witness encodings.

With 66 zero digits, the same Wots32 fixture reduces the measured clamped
terminal sum to 5,615 bytes for HASH160 or 6,171 for SHA-256. These results are
`locally-reproduced` and `research-unlimited` under the tapscript metric helper
with the stack limit disabled; they are not complete transaction weights or
Core consensus/policy validation. Witness items and auxiliary hints stay at 134
and zero, with the same measured 143-item clamped peak; bitwise still uses 333 entry
data items and zero hints. All items coexist at entry. Strict raw-width
profiles pay extra script bytes to select 16 or the native width from the
authenticated digit. A protocol should evaluate its actual message/checksum
distribution and the full transport transaction before choosing a profile.

`FastWinternitz<N, Sha256Hash160>` provides a third hash choice: 32-byte
SHA-256 nodes and 20-byte HASH160 endpoint commitments, with a fresh derivation
domain. The 32-byte-message bitwise terminal fragment shrinks to 3,812 bytes,
394 below HASH160 bitwise. It still needs 333 data items and peaks at 333.
For the same zero-message fixture, its Preimage16 witness is 1,686 bytes and
the fragment-plus-data total is 5,498; FullWidth totals 6,554. This changes
the commitment format, so persist the choice and regenerate keys when
switching from either existing hash choice.

The `checksig_verify_strided_and_clear` terminal profile and
`to_strided_witness()` serializer use three items per chain: a quotient, a
node, and a canonical low bit. The quotient is upper-clamped before both
table selection and checksum accumulation. For `Sha256Hash160`, the fragment
is 3,961 bytes and consumes 201 data items with a 209-item combined peak.
Its Preimage16 zero-message witness is 1,357 bytes, giving a 5,318-byte sum;
FullWidth uses 2,413 witness bytes and totals 6,374. Bitwise remains the
smaller locking fragment; strided has the smaller zero-message total among
these measured terminal profiles. Both consume the message, so a protocol
that needs recovered state must select a recovery profile instead.

The hybrid and strided measurements are `locally-reproduced` and
`research-unlimited` under the stack-limit-disabled tapscript metric helper.
Each invocation needs zero auxiliary hints. All 333 or 201 data items coexist
at entry, and peaks include checksum state and temporary tables; unrelated
live state must fit under the same 1,000-item limit. A caller-supplied final
predicate and transaction framing are excluded. Separate strict-stack tests
do not constitute Core consensus or policy validation.

A 16-byte initial secret caps generic single-target classical start search at
128 bits. The selected commitments retain their hash-output collision bounds,
which are a different security property; they do not restore the larger
FullWidth secret-search space. In particular, the hybrid's 20-byte HASH160
commitments retain an approximately 80-bit generic collision bound despite
32-byte internal nodes. Its size profiles also accept arbitrary raw node
widths at the maximum digit, because a final commitment hash always executes;
strict exact and lookup keep the raw-width checks. Concrete multi-target/chain analysis and
durable one-time-key state remain protocol obligations under
[OP-009](../open-problems.md#op-009--one-time-authentication-security-profiles).

For the earlier fixed-sum approach to verifying and consuming an unchanged 20-byte value,
`ConstantSumWinternitz20` replaces byte/nibble digitization and separate
checksum chains with a reversible host encoding into 41 mixed-radix digits
of sum 321. The default HASH160/Preimage16 fragment is 2,680 bytes, with an
attained 944-byte maximum signer witness and 3,624-byte maximum combined
cost. The corresponding 20-byte Fast base-16 clamped profile totals 3,809
bytes from a 2,819-byte fragment and 990-byte signer witness bound. The
constant-sum zero-message total is 3,519 bytes; its exact mean over all
`2^160` inputs is approximately 3,611.841783370768 bytes.
The baseline exact mean is approximately 3,795.262466089252 bytes over the
same input distribution, so the mean saving is approximately 183.420682718484
bytes (4.83%); these are exact-count expectations displayed as rounded decimals.

This is a new key and witness format. The host maps each 20-byte value to one
of the first `2^160` lexicographic codewords and can decode it exactly; Script
accepts the larger fixed-sum terminal relation. It does not recover bytes or
check the host rank limit. Even the bounded method checks radix ranges and
the sum without proving that the vector belongs to the host's 160-bit image.
Protocols requiring onchain byte binding or transport need a separate
consumer/decoder and must include its cost.

The smallest method omits individual upper-digit guards and can read matching
foreign stack entries for overflow coordinates. The complete sum still uses
each raw digit unchanged. The local security inference requires honest keys,
canonical signer vectors, one-time use, and chain inversion/collision
assumptions: any distinct same-sum vector must decrease an in-range
coordinate, whose own chain table then requires an earlier node. This is a
whole-vector guarantee; unguarded chain fragments cannot serve as local digit
authenticators. The bounded method is available when the protocol requires
explicit rejection of above-range digits. Both methods retain relaxed raw
node-width acceptance and preserve unrelated main/alt-stack state.

The default signature has 82 coexisting entry data items, zero auxiliary
hints, and a 93-item combined peak including its table and sum accumulator.
The baseline has 86/0/95. SHA-256 variants use 123 entry items and zero hints;
their measured combined peak is 133. The hybrid's 2,381-byte fragment is
smaller but its 1,517-byte maximum witness produces a 3,898-byte combined
maximum, above the HASH160 default's 3,624. Use the combined onchain boundary
when selecting the hash. All variants
require a final caller predicate, and surrounding state counts against the
same 1,000-item limit. Metrics are `locally-reproduced`, `research-unlimited`
under the stack-limit-disabled tapscript helper with `OP_TRUE`; strict-stack
tests remain `unclassified` deployment evidence. Transaction framing and
the caller predicate are excluded. There is no complete constant-sum protocol
Core consensus or policy validation. The historical executor's out-of-stack
`OP_PICK` panic is addressed by repaired pin `4b7269a`; see
[adoption and scope](../negative-results/index.md#nr-048-minimal-push-policy-must-follow-execution).
That tooling repair does not strengthen the recorded fragment evidence.

See the [constant-sum primitive](../primitives/winternitz-constant-sum20.md)
and [OP-009](../open-problems.md#op-009--one-time-authentication-security-profiles)
before treating this encoding and whole-vector relation as a protocol component.

BitVM3 can handle the reversible constant-sum representation without having
the publication Script reconstruct the original proof bytes. This differs
from a consumer that requires authenticated bytes on the Script stack. The
[BitVM 3s paper](https://bitvm.org/bitvm3.pdf), July 22, 2025, describes the
offchain garbled-circuit architecture (`bitvm3s-2025`); it does not validate
this repository’s custom fixed-sum Script relation. Complete integration
must still define how unused-rank and out-of-radix publications are handled.
See the [construction’s integration contract](../../src/signatures/winternitz/constant_sum/README.md#bitvm3-integration-and-byte-recovery).

The newer [constant-composition construction](../primitives/winternitz-constant-composition20.md)
reduces this publication cost further. A reversible host encoder assigns the
unchanged 20-byte rank to 49 independently keyed chains with radix-25 counts
`[1 × 15, 2 × 7, 3 × 2, 14]`. Verification processes fixed digit slots,
removing one authenticated key from the public pool each time; the fourteen
remaining keys implicitly receive the maximum digit. There are 35 openings,
35 selectors, and zero auxiliary hints. All 70 data items coexist at entry
and are staged above any existing altstack state.

HASH160/Preimage16 uses a 1,598-byte isolated fragment and an attained maximum
802-byte serialized signer witness, totaling 2,400 bytes, with combined peak
119. The composable clamped fragment uses 1,696 + 802 = 2,498 bytes and peaks
at 120 while retaining unrelated main state. The isolated API requires the
entire main stack to contain exactly the 70 signature items, checks that
depth explicitly, and preserves only unrelated alt state. That guard is
essential before dropping selector clamps. These costs remain
`locally-reproduced`, `research-unlimited`, with the caller predicate and
transaction framing excluded; strict tests remain `unclassified`.

BitVM3 can consume this reversible assignment subject to a defined protocol
integration; publication Script does not reconstruct bytes or restrict
assignments to the first `2^160` ranks. The consumer must bind the assignment
to its intended message and define unused-rank and witness-alias handling.
The local one-time argument uses a fixed multiset as an antichain, honestly
generated independent keys, and chain inversion/collision assumptions.
HASH160 retains its existing security tradeoffs. The historical `ba96bc2`
executor panicked at the exact out-of-pool `OP_ROLL` boundary; that result was
not a clean local rejection. The lab now pins repaired interpreter `4b7269a`,
without relabeling historical measurements. The later
[v30.3 differential experiment](../core-validation.md) confirms that boundary
rejection and validates one complete isolated HASH160 leaf (703 vbytes,
70 entry data items, zero hints, local stack-limited peak 119). This is
`differentially-validated`, `policy-validated` publication-leaf evidence; it
does not validate a complete state-transport or BitVM transaction protocol. See
[NR-042](../negative-results/index.md#nr-042-constant-composition-search-and-endpoint-sharing-limits).
