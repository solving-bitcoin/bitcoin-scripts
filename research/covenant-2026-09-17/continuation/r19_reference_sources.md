# R19: an explicit execution-binding interface in a newer verifier

Date: 2026-09-17. Question: does newer primary work provide the mandatory
intended-output reference computation missing from the 199-opcode native
component, without new BTC opcodes or retained signing secrets?

**No BTC construction meeting that interface was found in this bounded
search.** One newly inspected implementation provides a useful concrete
comparison: it makes every verifier fragment mandatory using native BCH
introspection. This is a specification of what a proposed BTC substitute must
accomplish, not such a substitute.

Evidence: `inspected`; the authors' execution claims remain `reported`.
Deployment of a BTC composition: `unclassified`. This audit generated no
Script, ran no source code or field tests, and claims no measured bytes,
witness items, hint items, stack peak, opcode count, or transaction weight.

## Exact source and mechanism

[0zkbrewer/BCH-FRI-STARK-Verifier](https://github.com/0zkbrewer/BCH-FRI-STARK-Verifier/tree/a600e828d68eb41840049cb16d0c21850ff9df57),
commit `a600e828d68eb41840049cb16d0c21850ff9df57`, commit timestamp
2026-07-27T13:06:17+02:00, was fetched into a temporary directory for read-only
inspection. Its README distinguishes the chipnet demo from the later fully
wired configuration; the latter's redeployment and full-parameter run are
still pending in that version. No deployment result was independently checked.

In
[`_covenant_bind_asm`](https://github.com/0zkbrewer/BCH-FRI-STARK-Verifier/blob/a600e828d68eb41840049cb16d0c21850ff9df57/apps/native_ct_verifier_tx.py#L107),
input zero compares each auxiliary input's `OP_UTXOBYTECODE` result with its
committed P2SH32 locking script. P2SH execution then authenticates the actual
redeem script. Shared transcript values are obtained with `OP_INPUTBYTECODE`
and `OP_SPLIT`. `build_sound_verifier_inputs` binds every auxiliary input,
including producers, rather than only terminal checks. Source comments
describe why prior binding to unlocking bytes allowed a bare output to carry
the expected bytes without executing the associated verifier. The externally
selected input-zero outpoint anchors the construction.

The
[opcode translation table](https://github.com/0zkbrewer/BCH-FRI-STARK-Verifier/blob/a600e828d68eb41840049cb16d0c21850ff9df57/apps/native_ct_shard.py#L7010)
also uses BCH arithmetic, `OP_CAT`, `OP_SPLIT`, functions and loops. This is
not bytecode executable with its intended semantics under existing BTC rules.

## Connection to the current missing reference

The relevant distinction is between three predicates:

1. A witness includes the bytes of the intended checker.
2. The transaction actually spends the output committing to that checker.
3. That checker validates the same transcript and native transaction context
   used by the other checks.

The native BTC component alone does not imply predicates 2 and 3 for extra
inputs. This BCH design implements them with direct inspection of spent
locking scripts and other inputs' unlocking bytes. Importing its arithmetic
or transcript layout would leave those two operations missing in BTC.
Authenticating a script's hash in a witness cannot stand in for authenticating
the locking script of an actually consumed output.

Consequently a constructive next result must replace those operations with
an existing-BTC-native relation and account for the resulting funding
dependencies, or put the complete reference computation in the mandatory
execution itself. This source does not reduce that task to proof arithmetic
alone. It provides a concrete omission/substitution test for any future
multi-input candidate; it is not an impossibility argument against one.

## Search scope

The search covered indexed primary papers, author posts, and repositories
combining Binohash, QSB, ColliderScript, covenants without softforks,
transaction introspection, and mandatory proof verification, with a cutoff of
2026-09-17. The earlier [seven-source review](../seven/search6_related_work.md),
[R4](r4_sources.md), and [R11](r11_reference_sources.md) were read first;
their protocols were not reclassified here. New search hits for client-side
Simplicity/TEE signing, optional attestation anchoring, and proposed softfork
opcodes did not supply the required existing-BTC relation. Search indexing is
incomplete; absence of a located construction is not nonexistence evidence.
