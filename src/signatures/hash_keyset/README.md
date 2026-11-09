# HASH160-committed x-only Schnorr signer set

Verify one native Schnorr signature from a hostile revealed x-only
key. The locking script embeds a list of HASH160 identifiers.

## Parameters and stack contract

`verify_hash160_keyset(identifiers)` takes 1 through 512 public
20-byte identifiers. There is no default. An identifier is
HASH160 of the exact 32-byte BIP340 public key. Repeated identifiers
have the same membership semantics as a single occurrence.

Main starts with `caller | signature public_key`. The fragment
checks the key length before hashing, checks membership in the
public identifier list, then runs native `OP_CHECKSIGVERIFY` with
the same key. Both caller stacks survive. The fragment produces
no result. A standalone leaf supplies terminal true.

## Script metrics

The [fixture](../../../tests/support/hash_keyset.rs) compares the
HASH160 scan with two embedded-key leaves. The first checks
membership by raw key equality using the same two ordinary witness
items. The second selects an embedded key with one index hint.
Its singleton leaf embeds the one key directly and needs no hint.

The fixture uses deterministic secp256k1 keypairs with scalar
values `1..=n`. The final key signs each leaf's own transaction
digest with a 64-byte default-sighash signature. All leaves
verify exactly one signature and end with true. All data and
hints coexist at entry. Data witness bytes include the item count
and data item lengths, excluding leaf and control block. Complete
witness bytes additionally include the exact leaf and its
33-byte depth-zero control block. There is no annex. Incremental
hint bytes include the item length and exclude the shared count.
Peak combines main and alt stacks. Executed counts exclude pushes.

| Keys | Schedule | Leaf bytes | Data witness bytes | Complete witness bytes | Ordinary items | Hint items (bytes) | Combined peak | Executed non-push ops | Initial validation budget | Charge |
| ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | HASH160 identifiers | <!-- metric:hash_keyset_1_hashed_script -->35<!-- /metric:hash_keyset_1_hashed_script --> | <!-- metric:hash_keyset_1_hashed_data -->99<!-- /metric:hash_keyset_1_hashed_data --> | <!-- metric:hash_keyset_1_hashed_complete -->169<!-- /metric:hash_keyset_1_hashed_complete --> | 2 | 0 (0 bytes) | <!-- metric:hash_keyset_1_hashed_stack -->6<!-- /metric:hash_keyset_1_hashed_stack --> | <!-- metric:hash_keyset_1_hashed_executed -->10<!-- /metric:hash_keyset_1_hashed_executed --> | <!-- metric:hash_keyset_1_hashed_budget -->219<!-- /metric:hash_keyset_1_hashed_budget --> | <!-- metric:hash_keyset_1_hashed_charged -->50<!-- /metric:hash_keyset_1_hashed_charged --> |
| 1 | Scan embedded keys | <!-- metric:hash_keyset_1_scanned_script -->40<!-- /metric:hash_keyset_1_scanned_script --> | <!-- metric:hash_keyset_1_scanned_data -->99<!-- /metric:hash_keyset_1_scanned_data --> | <!-- metric:hash_keyset_1_scanned_complete -->174<!-- /metric:hash_keyset_1_scanned_complete --> | 2 | 0 (0 bytes) | <!-- metric:hash_keyset_1_scanned_stack -->5<!-- /metric:hash_keyset_1_scanned_stack --> | <!-- metric:hash_keyset_1_scanned_executed -->5<!-- /metric:hash_keyset_1_scanned_executed --> | <!-- metric:hash_keyset_1_scanned_budget -->224<!-- /metric:hash_keyset_1_scanned_budget --> | <!-- metric:hash_keyset_1_scanned_charged -->50<!-- /metric:hash_keyset_1_scanned_charged --> |
| 1 | Embedded index | <!-- metric:hash_keyset_1_indexed_script -->35<!-- /metric:hash_keyset_1_indexed_script --> | <!-- metric:hash_keyset_1_indexed_data -->66<!-- /metric:hash_keyset_1_indexed_data --> | <!-- metric:hash_keyset_1_indexed_complete -->136<!-- /metric:hash_keyset_1_indexed_complete --> | 1 | 0 (0 bytes) | <!-- metric:hash_keyset_1_indexed_stack -->2<!-- /metric:hash_keyset_1_indexed_stack --> | <!-- metric:hash_keyset_1_indexed_executed -->1<!-- /metric:hash_keyset_1_indexed_executed --> | <!-- metric:hash_keyset_1_indexed_budget -->186<!-- /metric:hash_keyset_1_indexed_budget --> | <!-- metric:hash_keyset_1_indexed_charged -->50<!-- /metric:hash_keyset_1_indexed_charged --> |
| 4 | HASH160 identifiers | <!-- metric:hash_keyset_4_hashed_script -->107<!-- /metric:hash_keyset_4_hashed_script --> | <!-- metric:hash_keyset_4_hashed_data -->99<!-- /metric:hash_keyset_4_hashed_data --> | <!-- metric:hash_keyset_4_hashed_complete -->241<!-- /metric:hash_keyset_4_hashed_complete --> | 2 | 0 (0 bytes) | <!-- metric:hash_keyset_4_hashed_stack -->6<!-- /metric:hash_keyset_4_hashed_stack --> | <!-- metric:hash_keyset_4_hashed_executed -->19<!-- /metric:hash_keyset_4_hashed_executed --> | <!-- metric:hash_keyset_4_hashed_budget -->291<!-- /metric:hash_keyset_4_hashed_budget --> | <!-- metric:hash_keyset_4_hashed_charged -->50<!-- /metric:hash_keyset_4_hashed_charged --> |
| 4 | Scan embedded keys | <!-- metric:hash_keyset_4_scanned_script -->148<!-- /metric:hash_keyset_4_scanned_script --> | <!-- metric:hash_keyset_4_scanned_data -->99<!-- /metric:hash_keyset_4_scanned_data --> | <!-- metric:hash_keyset_4_scanned_complete -->282<!-- /metric:hash_keyset_4_scanned_complete --> | 2 | 0 (0 bytes) | <!-- metric:hash_keyset_4_scanned_stack -->5<!-- /metric:hash_keyset_4_scanned_stack --> | <!-- metric:hash_keyset_4_scanned_executed -->14<!-- /metric:hash_keyset_4_scanned_executed --> | <!-- metric:hash_keyset_4_scanned_budget -->332<!-- /metric:hash_keyset_4_scanned_budget --> | <!-- metric:hash_keyset_4_scanned_charged -->50<!-- /metric:hash_keyset_4_scanned_charged --> |
| 4 | Embedded index | <!-- metric:hash_keyset_4_indexed_script -->145<!-- /metric:hash_keyset_4_indexed_script --> | <!-- metric:hash_keyset_4_indexed_data -->68<!-- /metric:hash_keyset_4_indexed_data --> | <!-- metric:hash_keyset_4_indexed_complete -->248<!-- /metric:hash_keyset_4_indexed_complete --> | 1 | 1 (2 bytes) | <!-- metric:hash_keyset_4_indexed_stack -->6<!-- /metric:hash_keyset_4_indexed_stack --> | <!-- metric:hash_keyset_4_indexed_executed -->10<!-- /metric:hash_keyset_4_indexed_executed --> | <!-- metric:hash_keyset_4_indexed_budget -->298<!-- /metric:hash_keyset_4_indexed_budget --> | <!-- metric:hash_keyset_4_indexed_charged -->50<!-- /metric:hash_keyset_4_indexed_charged --> |
| 32 | HASH160 identifiers | <!-- metric:hash_keyset_32_hashed_script -->779<!-- /metric:hash_keyset_32_hashed_script --> | <!-- metric:hash_keyset_32_hashed_data -->99<!-- /metric:hash_keyset_32_hashed_data --> | <!-- metric:hash_keyset_32_hashed_complete -->915<!-- /metric:hash_keyset_32_hashed_complete --> | 2 | 0 (0 bytes) | <!-- metric:hash_keyset_32_hashed_stack -->6<!-- /metric:hash_keyset_32_hashed_stack --> | <!-- metric:hash_keyset_32_hashed_executed -->103<!-- /metric:hash_keyset_32_hashed_executed --> | <!-- metric:hash_keyset_32_hashed_budget -->965<!-- /metric:hash_keyset_32_hashed_budget --> | <!-- metric:hash_keyset_32_hashed_charged -->50<!-- /metric:hash_keyset_32_hashed_charged --> |
| 32 | Scan embedded keys | <!-- metric:hash_keyset_32_scanned_script -->1156<!-- /metric:hash_keyset_32_scanned_script --> | <!-- metric:hash_keyset_32_scanned_data -->99<!-- /metric:hash_keyset_32_scanned_data --> | <!-- metric:hash_keyset_32_scanned_complete -->1292<!-- /metric:hash_keyset_32_scanned_complete --> | 2 | 0 (0 bytes) | <!-- metric:hash_keyset_32_scanned_stack -->5<!-- /metric:hash_keyset_32_scanned_stack --> | <!-- metric:hash_keyset_32_scanned_executed -->98<!-- /metric:hash_keyset_32_scanned_executed --> | <!-- metric:hash_keyset_32_scanned_budget -->1342<!-- /metric:hash_keyset_32_scanned_budget --> | <!-- metric:hash_keyset_32_scanned_charged -->50<!-- /metric:hash_keyset_32_scanned_charged --> |
| 32 | Embedded index | <!-- metric:hash_keyset_32_indexed_script -->1085<!-- /metric:hash_keyset_32_indexed_script --> | <!-- metric:hash_keyset_32_indexed_data -->68<!-- /metric:hash_keyset_32_indexed_data --> | <!-- metric:hash_keyset_32_indexed_complete -->1190<!-- /metric:hash_keyset_32_indexed_complete --> | 1 | 1 (2 bytes) | <!-- metric:hash_keyset_32_indexed_stack -->34<!-- /metric:hash_keyset_32_indexed_stack --> | <!-- metric:hash_keyset_32_indexed_executed -->25<!-- /metric:hash_keyset_32_indexed_executed --> | <!-- metric:hash_keyset_32_indexed_budget -->1240<!-- /metric:hash_keyset_32_indexed_budget --> | <!-- metric:hash_keyset_32_indexed_charged -->50<!-- /metric:hash_keyset_32_indexed_charged --> |
| 129 | HASH160 identifiers | <!-- metric:hash_keyset_129_hashed_script -->3107<!-- /metric:hash_keyset_129_hashed_script --> | <!-- metric:hash_keyset_129_hashed_data -->99<!-- /metric:hash_keyset_129_hashed_data --> | <!-- metric:hash_keyset_129_hashed_complete -->3243<!-- /metric:hash_keyset_129_hashed_complete --> | 2 | 0 (0 bytes) | <!-- metric:hash_keyset_129_hashed_stack -->6<!-- /metric:hash_keyset_129_hashed_stack --> | <!-- metric:hash_keyset_129_hashed_executed -->394<!-- /metric:hash_keyset_129_hashed_executed --> | <!-- metric:hash_keyset_129_hashed_budget -->3293<!-- /metric:hash_keyset_129_hashed_budget --> | <!-- metric:hash_keyset_129_hashed_charged -->50<!-- /metric:hash_keyset_129_hashed_charged --> |
| 129 | Scan embedded keys | <!-- metric:hash_keyset_129_scanned_script -->4648<!-- /metric:hash_keyset_129_scanned_script --> | <!-- metric:hash_keyset_129_scanned_data -->99<!-- /metric:hash_keyset_129_scanned_data --> | <!-- metric:hash_keyset_129_scanned_complete -->4784<!-- /metric:hash_keyset_129_scanned_complete --> | 2 | 0 (0 bytes) | <!-- metric:hash_keyset_129_scanned_stack -->5<!-- /metric:hash_keyset_129_scanned_stack --> | <!-- metric:hash_keyset_129_scanned_executed -->389<!-- /metric:hash_keyset_129_scanned_executed --> | <!-- metric:hash_keyset_129_scanned_budget -->4834<!-- /metric:hash_keyset_129_scanned_budget --> | <!-- metric:hash_keyset_129_scanned_charged -->50<!-- /metric:hash_keyset_129_scanned_charged --> |
| 129 | Embedded index | <!-- metric:hash_keyset_129_indexed_script -->4335<!-- /metric:hash_keyset_129_indexed_script --> | <!-- metric:hash_keyset_129_indexed_data -->69<!-- /metric:hash_keyset_129_indexed_data --> | <!-- metric:hash_keyset_129_indexed_complete -->4441<!-- /metric:hash_keyset_129_indexed_complete --> | 1 | 1 (3 bytes) | <!-- metric:hash_keyset_129_indexed_stack -->131<!-- /metric:hash_keyset_129_indexed_stack --> | <!-- metric:hash_keyset_129_indexed_executed -->73<!-- /metric:hash_keyset_129_indexed_executed --> | <!-- metric:hash_keyset_129_indexed_budget -->4491<!-- /metric:hash_keyset_129_indexed_budget --> | <!-- metric:hash_keyset_129_indexed_charged -->50<!-- /metric:hash_keyset_129_indexed_charged --> |

## Security, compatibility and composition

The signature and revealed key are hostile. The explicit
32-byte guard is part of the predicate. In tapscript a nonempty
key of another length selects an upgradeable key type, and a
native signature opcode can accept it with a nonempty signature.
The tests reproduce that behavior for an unguarded committed short
key and verify that the guarded leaf rejects it before charging a
signature check. An invalid 32-byte curve key also fails. A match
depends on the script's public hash identifiers and the native
Schnorr check. This experiment makes no independent claim about
hash binding or key secrecy.

The construction targets tapscript. Bare, P2SH and P2WSH
signature opcodes have different key and signature semantics.
See the [script-type](../../../docs/script-types.md) and
[standardness](../../../docs/standardness.md) boundaries.

The local transaction-aware interpreter runs the policy-produced
leaf with stack limits enabled and experimental OP_CAT disabled.
A synthetic previous output commits to that exact leaf. The
fixture verifies the control block using repository code and
computes the native signature digest from the exact transaction
context. Budget starts at 50 plus complete witness size and the
measured single valid signature charges 50. Evidence is
`locally-reproduced`. Execution is `unclassified`.

The HASH160 scan needs two ordinary items and zero hints. Its
combined peak is six before caller state and does not grow with
the number of identifiers. A 512-entry test preserves 994 caller
items at exactly 1,000. Future inputs and retained outputs add to
that live state.

## Reproduction

```sh
cargo test --locked --test hash_keyset_contract
cargo test --locked --test primitive_metrics hash160_keyset_metrics_are_current
python3 tools/kb.py validate
cargo test --locked -- --skip fields::
```

The focused tests check every key in a four-key set, default and
explicit ALL sighashes, nonmember and wrong-leaf signatures,
empty and malformed signatures, unknown key types, invalid x-only
points, and exact stack limits. See the
[knowledge page](../../../knowledge/primitives/hash160-schnorr-keyset.md).
