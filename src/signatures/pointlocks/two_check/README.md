# Experimental two-check ECDSA point lock

This conditional point-lock candidate derives a companion key from the public
target `T=tG` alone. Its two native ECDSA checks use one signature and one
legacy `scriptCode`. It saves three bytes and removes the executed
`OP_CODESEPARATOR` used by the [three-check construction](../three_check/),
but requires a stronger, unresolved assumption to exclude ordinary-digest
spends. Public extraction is established for the constant-digest branch only.

## Parameters

- `T=tG`: valid compressed secp256k1 target point; no default.
- `C=2^248`: integer interpretation of the internal legacy out-of-range
  SIGHASH_SINGLE digest bytes `01 00...00`.
- `k0=2^-1 mod n`, `r0=x(G/2)`:
  `3b78ce563f89a0ed9414f5aa28ad0d96d6795f9c63`.
- Companion key: `Q=-(2*C/r0)G-T`; reject `Q=infinity` and `Q=T`.
- Signature item: strict DER plus its actual sighash byte, length greater
  than 57 bytes. Honest signing uses SIGHASH_SINGLE at an input index with no
  corresponding output.

## Script metrics

```text
OP_SIZE 57 OP_GREATERTHAN OP_VERIFY
OP_DUP <T> OP_CHECKSIGVERIFY
<Q> OP_CHECKSIG
```

| Configuration | Locking script | Signature item | Bare scriptSig | Unlocking witness | Hint items | Maximum stack items |
| --- | ---: | ---: | ---: | --- | ---: | ---: |
| Representative `[7;32]` target | <!-- metric:pointlock_two_check_script -->76<!-- /metric:pointlock_two_check_script --> bytes | 60 bytes | 61 bytes | None: legacy input | 0 (none) | 3 |

The complete policy-produced bare predicate includes both compressed keys,
the size guard, both checks, and the terminal truth value. It executes six
non-push opcodes. The signature and its minimal push are included in the
separate signature-item and scriptSig columns. A P2SH wrapper pushes the
76-byte redeem script with a two-byte PUSHDATA1 prefix, giving a 139-byte
representative scriptSig with two pushed data items. The rare 61-byte high-S
signature uses a 62-byte bare or 140-byte P2SH scriptSig. There is no serialized
witness for the legacy input; a helper input's witness belongs to a complete
transaction measurement. Funding, transaction framing, helper inputs,
authorization, and refund branches are excluded from this table.

## Security

The `>57` size predicate excludes all ECDSA `r+n` coordinate alternatives.
For the same signature `(r,s)` and actual digest scalar `z`, the distinct
keys `T,Q` therefore reconstruct opposite nonce points. Their sum gives

```text
r = r0*z/C mod n.
```

When `z=C`, this forces the nonce point to `+/-G/2`, and an observer extracts
`t=(+/-s*k0-C)/r0 mod n`, selecting the candidate whose public point is `T`.
For `z!=C`, the equations do not force a publicly known nonce. A deterministic
synthetic vector passes both signature equations for an ordinary supplied
digest and fails the G/2 extraction rule; it is not a mined native
transaction. See the [negative result](../../../../knowledge/negative-results/two-check-point-lock-extraction.md).

A malicious spender that knows `t` can convert any accepted ordinary spend
into a known-nonce match between `x(kG)` and the actual transaction digest.
Independent-list searching suggests a work scale near `2^128`, but this is
only a model estimate, not a concrete security claim, general lower bound, or
ECDLP reduction. An arbitrary-target adversary need not know `t` or the nonce
scalar. Thus the point-only interface additionally requires resistance to
ordinary native transcripts with adversarially selected targets; that
stronger assumption has not been established.

Pre-spend hiding uses secp256k1 discrete-log hardness. The point is revealed
on the intended spend, so protocols must account for that disclosure and
provide separate payment authorization where needed. This experimental
variant must not inherit the stronger extraction claim of `three_check`.

## Script compatibility and standardness

| Script type | Construction boundary |
| --- | --- |
| Bare legacy | Applicable ECDSA and constant-digest semantics; arbitrary bare output is not a standard relay template. |
| P2SH | Representative low-S complete transaction is policy-validated by pinned Core 30.3; 76-byte redeem script fits the 520-byte limit and uses two sigops. High-S fallback remains non-standard. |
| P2WSH | Incompatible with honest construction: BIP143 does not supply the legacy out-of-range SINGLE constant. |
| Tapscript | Incompatible: 33-byte keys have unknown-key semantics, not ECDSA verification. |

The [complete Core experiment](../../../../research/pointlocks-2026-09-17/CORE.md)
is `differentially-validated`: all 18 combined two-/three-check expectations
match Core 30.3 commit `49faec4f87f5cd19c88db01a82e5c68b087c8227`.
The two-check low-S P2SH fixture is `policy-validated`; its bare counterpart,
high-S fallbacks, and undefined-flag positive are `consensus-validated` with
policy rejection. The representative P2SH complete transaction weighs
1,054 WU. Its two input witness vectors serialize to
<!-- metric:pointlock_two_check_core_witness -->4<!-- /metric:pointlock_two_check_core_witness -->
bytes (one `OP_TRUE` helper item and the empty legacy-input vector), plus
two transaction marker/flag bytes. This is the complete transaction witness,
not witness data consumed by the legacy predicate. Detailed accounting is
in that report.
These execution results do not prove the arbitrary-target extraction
assumption. See
[`docs/script-types.md`](../../../../docs/script-types.md) and
[`docs/standardness.md`](../../../../docs/standardness.md).

## Witness and hints

At predicate entry there is exactly one data item: `DER(r,s)||sighash_byte`.
There are zero auxiliary hint items per invocation and no measured batched
configuration. The P2SH scriptSig contains two data pushes, signature then
redeem script; P2SH evaluates the redeem script with the one-signature stack.
All signature data is public after spending. A representative invocation
peaks at three combined main/alt-stack items, so unrelated live state must
still be counted against the 1,000-item limit when composing it.

## Stack contract

```text
... signature -> ... true
```

The signature must pass strict DER, the size guard, and both ECDSA checks.
The altstack is unused. With a clean one-item entry stack, success leaves
exactly one truthy result. Invalid or exceptional target points are rejected
by construction.

## Operational notes

- `point_lock(T)` generates the predicate; `companion_key(T)` derives `Q`.
- `sign(t)` generates the honest G/2 signature, using high-S only when low-S
  is too short for the guard. This fallback is consensus-oriented, not
  policy-complete.
- `legacy_digest(tx,index,T,flag)` calculates the actual digest with the
  policy-produced script and raw consensus sighash byte.
- `extract(T,signature,digest)` verifies both checks before returning
  `NonConstantDigest` for a valid ordinary-digest transcript. That error
  reports an unresolved extraction branch, not an invalid signature.
- `extract_from_transaction` parses the signature's actual sighash byte and
  computes the digest before calling that partial extractor.

The 76-byte script executes locally without NOP padding. Tests cover size and
stack accounting, honest extraction, malformed inputs, exceptional targets,
the high-S boundary, and the synthetic ordinary-digest counterexample.
The bigint signing helpers are deterministic research code, not constant-time
production signing code. A complete honest transaction normally needs a
helper input because a transaction must have an output while the point-lock
input must be beyond the last output index.

Pinned-Core negative fixtures reject a mutated signature scalar, a changed
input index, an added second output, and a 57-byte item. The high-S and
undefined-flag positives demonstrate the difference between consensus and
policy. Rust differential tests recompute the actual transaction digests and
run extraction on the recorded positive transactions.

## Knowledge-base integration

- Catalog: `signature/point-lock-ecdsa-two-check`.
- [Point-lock knowledge page](../../../../knowledge/primitives/point-locks.md).
- [Signature comparison](../../../../knowledge/comparisons/signatures.md).
- [Exact algebra and assumption review](../../../../research/pointlocks-2026-09-17/algebra.md).
- [Ordinary-digest extraction boundary](../../../../knowledge/negative-results/two-check-point-lock-extraction.md).
- [OP-017: security and deployment validation](../../../../knowledge/open-problems.md#op-017--point-lock-security-and-deployment-validation).

The shared G/2 and legacy SINGLE conventions are documented by the Binohash
reference on the knowledge page. The recovery-geometry findings R9 and R18
are linked in the algebra review; neither supplies the missing arbitrary-
target reduction. Validate integration with `python3 tools/kb.py validate`.
