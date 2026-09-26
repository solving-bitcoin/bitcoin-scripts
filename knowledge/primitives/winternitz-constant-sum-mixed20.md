# Mixed-stage constant-sum Winternitz for 20-byte messages

`MixedConstantSumWinternitz20` is an experimental terminal one-time signature
for an unchanged 20-byte message. Its catalog ID is
`signature/winternitz-constant-sum-mixed20`. The implementation and exact
geometry are documented in the [construction README](../../src/signatures/winternitz/constant_sum_mixed/README.md).

## Result

The entry-guard fragment is 1,491 bytes and its attained maximum serialized
signer witness is 844 bytes, totaling **2,335 bytes**. Checking isolation after
staging saves one Script byte, totaling **2,334 bytes**. Both have 66 signature
data items, zero auxiliary hints, and a 111-item combined stack peak. These are
`locally-reproduced`, `research-unlimited` fragment metrics. Strict local tests
are `unclassified` for deployment; no Core validation is claimed.

This boundary includes embedded endpoints, all signature checks and cleanup,
and the full signature-witness serialization. It excludes a terminal predicate,
Taproot script/control-block framing, transaction overhead, and an onchain
message decoder. The numbers are bytes, not transaction vbytes.

## Construction

Forty-five independent alternating SHA256/RIPEMD160 chains end in 20-byte
commitments. Thirty-three openings are explicit and twelve maximum-digit
endpoints are implicit. Three opening slots have fixed digits. Fifteen pair
relations each permit `(u,v)` or `(u-t,v+t)` for positive even `t`, retaining
the same sum and hash phase. An equality-controlled swap identifies which
opening needs `t/2` additional HASH160 operations. No branch bit is supplied.

All 32,768 branch masks yield distinct histograms. The exact union capacity is
`1474534644173396013943101947755055475538944000000`, approximately
`2^160.012808`. Big-endian message ranks are mapped reversibly into the first
`2^160` codewords by exact class selection and multinomial unranking. Script
accepts the full union, while host decoding rejects the unused rank suffix.

All admitted vectors have digit sum 1,566, so the code is an antichain. The
verifier enforces the narrower union through the local pair relations and fixed
slots. Destructive endpoint selection enforces distinct chain indices.

## Evidence and limitations

Rust tests cover exact capacity and byte sizes, message round trips, both guard
placements, strict local execution, caller altstack preservation, malformed
nodes and selectors, missing and extra items, and unused-rank rejection. An
independent standard-library Python checker reconstructs every histogram, exact
capacity, constant sum, hash count, and cost formula.

The parameters came from heuristic exploration with exact validation of the
retained candidate. They do not prove a global optimum over constant-sum codes,
antichains, hash schedules, or Bitcoin Script verifiers. The one-time security
argument assumes independent chain derivation and hash inversion/collision
resistance. It is not a WOTS+ reduction. Seed restoration, rollback, and
concurrent reuse remain operational hazards. The 16-byte starts cap generic
single-target preimage search at 128 bits before multi-target effects; 20-byte
endpoints have an 80-bit generic collision bound.

See the [signature comparison](../comparisons/signatures.md),
[one-time state transport](../protocols/one-time-state-transport.md), and
[OP-009](../open-problems.md#op-009--one-time-authentication-security-profiles).
