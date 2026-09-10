# Local execution support

The lab and `bitcoin-script-stack` use the same repaired `bitcoin-scriptexec`
revision, selected by an immutable Cargo patch:
[`702544c9a045ac4fc14846da6da6559e2b7cd9d1`](https://github.com/adrienlacombe/rust-bitcoin-scriptexec/commit/702544c9a045ac4fc14846da6da6559e2b7cd9d1).
It retains three resource repairs on upstream `ba96bc2`: entry/per-step
resource checks ([PR #18](https://github.com/BitVM/rust-bitcoin-scriptexec/pull/18)),
`OP_PICK`/`OP_ROLL` bounds ([PR #19](https://github.com/BitVM/rust-bitcoin-scriptexec/pull/19)),
and checking minimal pushes only when executed
([PR #20](https://github.com/BitVM/rust-bitcoin-scriptexec/pull/20)).
It additionally adopts Sander Bosma's existing
[CODESEPARATOR fix #16](https://github.com/BitVM/rust-bitcoin-scriptexec/pull/16)
with extended regression tests, preserves empty signatures for unknown key types,
and returns script errors for invalid x-only keys, missing SIGHASH_SINGLE outputs
and executed Tapscript multisig. All **57 upstream tests** pass at this integration
revision. The [signature experiment](../../knowledge/tapscript-signature-validation.md)
records the exact comparison scope and original commits. The fork is temporary
while the upstream PRs are reviewed; compiler and other dependency pins remain
unchanged. Historical reports retain their original interpreter provenance.

Generated scripts use `ScriptCompilation::compile_with_policy()`; raw-byte
helpers execute the exact supplied serialization. Every local entry point uses
`tapscript`, and local acceptance alone has deployment `unclassified`.

## Explicit fragment profiles

`support::tapscript::execute_tapscript(script, witness, profile)` accepts a
policy-compiled `ScriptBuf` and data witness items, excluding the script,
control block and annex. All witness data and hints coexist at entry.

| Check | `TapscriptProfile::Consensus` | `TapscriptProfile::Policy` |
| --- | --- | --- |
| Numeric encoding | Nonminimal encodings permitted | Minimal encodings required |
| Data-push encoding | Nonminimal encodings permitted | Minimal only for executed pushes |
| `OP_IF` / `OP_NOTIF` inputs | Exactly empty or `01` | Exactly empty or `01` |
| Normal execution resources | 1,000 combined items; 520-byte elements | Same, plus 80-byte initial data items |
| Decoded `OP_SUCCESSx`, including `OP_CAT` | Immediate pre-scan success | Policy rejection |
| Experimental `OP_CAT` evaluation | Disabled | Disabled |

The policy data-item check runs before script parsing, matching Core's
`IsWitnessStandard` for a tapscript leaf. Both profiles then scan decoded
instructions sequentially for `OP_SUCCESSx`, before entry resources or any
execution. A malformed prefix rejects; malformed suffixes after the first
`OP_SUCCESSx` are not reached. Bytes inside push payloads never count as
opcodes. An earlier `OP_RETURN`, a skipped branch or an oversized initial stack
does not prevent consensus pre-scan success. These are the rules in pinned
Core v30.3
[`ExecuteWitnessScript`](https://github.com/bitcoin/bitcoin/blob/49faec4f87f5cd19c88db01a82e5c68b087c8227/src/script/interpreter.cpp#L1827)
and [`IsWitnessStandard`](https://github.com/bitcoin/bitcoin/blob/49faec4f87f5cd19c88db01a82e5c68b087c8227/src/policy/policy.cpp#L310).

`TapscriptResult` records the selected profile and a typed outcome.
`accepted()` returns `Some(true)` or `Some(false)` for supported local
verdicts, and **`None` for unsupported opcodes or initialization errors**.
An unsupported result must never be counted as a consensus rejection.
`execution()` supplies stack statistics only when the interpreter actually ran.
`OpSuccess` has no fabricated execution or budget measurements. A normally
completed fragment with multiple outputs still has `ExecuteInfo.success = false`
under the complete-leaf clean-stack convention; inspect its error and outputs
when evaluating such a fragment.

These are deliberately context-free fragment profiles. Signature operations,
`OP_CODESEPARATOR`, CLTV and CSV return `UnsupportedOpcode`, including when
present in a skipped branch. Policy additionally refuses upgradeable NOPs
(`NOP1`, `NOP4` through `NOP10`) because the dependency lacks the corresponding
policy flag. This conservative refusal avoids claiming an unchecked verdict;
a later `OP_SUCCESSx` still takes precedence during the pre-scan. A complete
Taproot commitment, annex, transaction, signature budget, fee rules, transaction
standardness and unknown-key policy require the independent Core harness.

## Existing research helpers

The public helpers in `execution.rs` retain their research settings:
minimal-number and executed-push checks are enabled, and experimental `OP_CAT`
is enabled. They do not implement the `OP_SUCCESSx` pre-scan. Their names ending
in `strict` refer to resource enforcement, not complete consensus validation.

| Helpers | Combined main/alt-stack item limit | Initial witness element limit |
| --- | --- | --- |
| `execute_script`, `execute_script_buf` | 1,000 after every instruction | No witness |
| `execute_*_with_inputs_strict` | 1,000 at entry and after every instruction | 520 bytes |
| `dry_run_taproot_input` | 1,000 at leaf entry and after every instruction | 520 bytes for data items |
| `execute_*_without_stack_limit` | Disabled | No witness |
| `execute_script_with_inputs`, `execute_raw_script_with_inputs` | Disabled | 520 bytes |

`ExecuteInfo.stack_limit_enforced` exposes the choice. Count-disabled research
execution is `research-unlimited`; count enforcement alone leaves deployment
`unclassified`. Disabling the item-count limit does not disable element limits.
All helpers now exercise the repaired upstream checks directly; the former
duplicate resource wrapper has been removed. Peak statistics still include
entry state and the failing instruction's live main-plus-alt stack. Exact
out-of-stack indices now return `InvalidStackOperation` rather than panicking.

Research helper limitations remain: malformed script construction can panic,
experimental opcode behavior differs from current consensus, and transaction
context is a dummy template except in the Taproot dry run. The dry run extracts
a leaf but does not validate its commitment or full transaction and does not
pass the annex into signature checks. Upstream validation-weight initialization
and opcode counters are not complete Taproot transaction measurements. Use the
new typed profiles for the supported context-free subset and Core for complete
transaction evidence.

Signature repairs are submitted as [#21](https://github.com/BitVM/rust-bitcoin-scriptexec/pull/21)
and [#22](https://github.com/BitVM/rust-bitcoin-scriptexec/pull/22). Additional
CODESEPARATOR tests [target the existing fix author's branch](https://github.com/bob-collective/rust-bitcoin-scriptexec/pull/1).
All 20 funded signature cases now match pinned Core, including rejection
diagnostics, with two identical reports and zero local panics in that corpus.

## Verification and adoption boundary

Fresh experiment generators use `support::provenance::{interpreter, compiler,
stack}` or `dependency(package_name)` to report the resolved package name,
version, full Git source and immutable commit from the build-time embedded
`Cargo.lock`. Missing or ambiguous packages, malformed identities and non-Git
sources return errors. Rebuilding after a lock change updates the values; an
already built binary retains its own identity even if the on-disk lock changes.
This does not attest uncommitted edits in a Cargo Git checkout. The shared
utility replaces copied pins in Core fixtures and PRINCE differential output;
historical artifacts retain their original metadata.

```sh
cargo test --locked --test execution_limits --test tapscript_profiles
cargo test --locked signatures::winternitz::constant_composition::tests::signature
```

The resource regressions exercise the repaired dependency itself, including
initial 1,000/1,001 counts, 520/521-byte elements, main/alt coexistence and data
pushes. The profile tests cover all 256 possible opcode bytes against the exact
`OP_SUCCESSx` set, payload masking, malformed prefixes/suffixes, policy ordering,
minimal numeric/push encodings and mandatory tapscript `MINIMALIF`.
Evidence for these local tests is `locally-reproduced`, deployment
`unclassified`. [Core comparisons](../../knowledge/core-validation.md) supply
separate `differentially-validated` complete-transaction evidence.

The full non-field suite passes 460 tests (24 existing ignores, 143 field tests
filtered). All six active primitive metric tests pass: the five historical
baselines are unchanged, and the new checked-PRINCE test adds three complete-leaf
rows with 15 explicit measurements:

```sh
CARGO_PROFILE_TEST_OPT_LEVEL=1 CARGO_TARGET_DIR=target/nonfield-opt1 cargo test --locked -- --skip fields::
```

Only the host test optimization level is changed; debug assertions and overflow
checks retain their defaults. Script compilation still uses the unchanged
`124b561e` compiler and repository policy. The recorded 44-fixture Core report
reproduced identically on two fresh nodes at its original `4b7269a4` pin; its 86 applicable local/Core
verdict comparisons pass, with commitment validation explicitly outside the
local fragment API.

The [checked PRINCE experiment](../../knowledge/prince-core-validation.md)
extends the supported subset to a computation leaf with consensus-enforced
input validation. Its 20 funded cases and 40 local profile comparisons pass,
with three exact valid spends accepted by default Core policy. This adds
primitive-specific evidence without widening the context-free API's claims.

Return to an immutable upstream revision when it contains all adopted repairs or
equivalent implementations and passes these regressions, Core comparisons,
unchanged primitive metrics and the non-field suite. Do not silently repoint
historical evidence or update the other dependency pins during that migration.
