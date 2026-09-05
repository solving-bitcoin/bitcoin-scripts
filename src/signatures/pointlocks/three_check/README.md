# Three-check ECDSA point lock

This folder implements the 79-byte point-only construction. Given only
`T=tG`, it derives `Q=-(2*z0/r0)G-T` and reuses one ECDSA signature in three
checks with two legacy `scriptCode` views. No adaptor transcript, signature
commitment, or zero-knowledge proof is required.

## Script

```text
OP_SIZE 57 OP_GREATERTHAN OP_VERIFY
OP_DUP <T>
OP_2DUP OP_CHECKSIGVERIFY
OP_CODESEPARATOR
OP_CHECKSIGVERIFY
<Q> OP_CHECKSIG
```

| Configuration | Locking script | Signature item | Bare `scriptSig` | Hint items | Maximum stack items |
| --- | ---: | ---: | ---: | ---: | ---: |
| Representative `[7;32]` target | <!-- metric:pointlock_three_check_script -->79<!-- /metric:pointlock_three_check_script --> bytes | 60 bytes | 61 bytes | 0 (none) | 5 |

The metrics use the policy-produced locking script and the complete bare
legacy `scriptSig` containing one minimally pushed signature. Legacy spends
have no witness serialization. Wrapper, transaction, authorization, and refund
bytes are excluded. The focused unit test fixes the signature-item and
`scriptSig` values; the repository metric marker records the schema-supported
locking-script field.

## Compatible script types

| Script type | Compatibility | Reason |
| --- | --- | --- |
| Bare legacy | Consensus-compatible but non-standard | Uses legacy ECDSA, legacy `OP_CODESEPARATOR`, and the out-of-range SIGHASH_SINGLE digest. Arbitrary bare outputs are not standard relay templates. |
| P2SH | Consensus-compatible but non-standard spend | The 79-byte redeem script fits the 520-byte push limit and retains legacy sighashing. Executed `OP_CODESEPARATOR` violates current `CONST_SCRIPTCODE` relay policy. |
| P2WPKH | Incompatible | P2WPKH supplies a fixed P2PKH `scriptCode`; it cannot execute this predicate. |
| P2WSH | Incompatible with the construction | BIP143 fixes the out-of-range SIGHASH_SINGLE bug, so the honest fixed-digest signature is unavailable. |
| Taproot key path | Incompatible | There is no script and no legacy ECDSA verification. |
| Tapscript | Incompatible | `OP_CHECKSIG` verifies BIP340 Schnorr signatures; 33-byte legacy keys do not invoke ECDSA. |

There is currently no policy-standard deployment. High-S is additionally
non-standard when the rare completeness fallback is needed, although it is
valid under legacy consensus rules.

## Security properties

The `>57` guard does not assume that finding an x-coordinate shorter than
`x(G/2)` is hard. It excludes every `r` for which both field coordinates `r`
and `r+n` can exist. The first two checks then reconstruct nonce points that
must be equal or opposite.

- Opposite nonce points reveal `t=-(zA+zB)/(2r) mod n`.
- Equal nonce points require `zA=zB mod n`, a related-scriptCode collision in
  the legacy transaction hashes reduced modulo `n`.
- On the SIGHASH_SINGLE-bug path, both digests equal `z0=2^248`; the companion
  check forces `r=r0=x(G/2)`, after which the known-nonce equation reveals `t`.

Pre-spend hiding relies on the secp256k1 discrete-log problem. Extractability
relies on the related-scriptCode reduced-sighash collision assumption. The
128-bit classification is a conservative design target, not an independently
audited reduction or reproduced attack bound.

## Operational boundary

The honest spend places this input at an index with no corresponding output
and uses SIGHASH_SINGLE. Because a valid transaction needs an output, this
normally requires at least two inputs. The predicate reveals `t` but does not
provide independent payment authorization; protocols should add a separate
authorization key or a refund branch as needed.

The deterministic bigint signing helpers are not constant-time. The pinned
local interpreter also delegates ECDSA verification to libsecp256k1, which
rejects high-S; the high-S fallback is therefore checked algebraically here
pending execution of a complete transaction by pinned Bitcoin Core.

## Rust API

- `point_lock(T)` constructs the predicate and rejects exceptional targets.
- `companion_key(T)` exposes the deterministic `Q` derivation.
- `sign(t)` creates the honest SINGLE-bug signature and selects low-S or the
  high-S completeness fallback.
- `script_code_views(T)` and `legacy_digest_pair(tx, index, T, flag)` derive
  the exact policy-produced legacy views and rust-bitcoin sighashes.
- `extract_from_transaction(T, signature_item, tx, index)` accepts even
  consensus-valid non-standard sighash bytes, verifies all three equations,
  and returns the scalar only when it reproduces `T`.
