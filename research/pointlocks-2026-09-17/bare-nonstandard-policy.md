# Opt-in mempool policy for the bare publication

The original **161,382-vB** bare publication now enters the mempool and is
mined by an explicitly configured, locally patched Bitcoin Core 30.3. Scripts,
signatures and complete transaction bytes are identical to the original
[consensus-validated publication](bare-publication.md). No extra script bytes
or consensus-rule relaxation is needed.

## Exact change

`-acceptnonstdtxn=1` bypasses transaction/output/input-template standardness
checks on test networks, but upstream Core still uses
`STANDARD_SCRIPT_VERIFY_FLAGS` in `MemPoolAccept::PolicyScriptChecks`. Thus the
bare script's deliberately retained table fails CLEANSTACK even with this
option. The config-only control reproduces that precise rejection.

The [patch](core-nonstandard-policy.patch) changes only that function:

```cpp
const unsigned int scriptVerifyFlags = m_pool.m_opts.require_standard
    ? STANDARD_SCRIPT_VERIFY_FLAGS
    : GetBlockScriptFlags(*m_active_chainstate.m_chain.Tip(), m_active_chainstate.m_chainman);
```

With the explicit nonstandard option, mempool script verification uses the
active consensus flags, followed by Core's existing ConsensusScriptChecks.
Default policy follows the unchanged STANDARD_SCRIPT_VERIFY_FLAGS branch.
Block validation, signature equations, script resource limits and the
subsequent consensus checks are unchanged. Other mempool checks, including
fees and package limits, are not removed by this patch.

The change also permits the recorded high-S, nonminimal-hint, non-push scriptSig
and undefined-SINGLE-flag cases; all were already consensus-valid on the
unmodified binary. Accepted partial publication and surplus codewords remain
application-boundary controls, not complete BitVM3 publications.

## Reproduced outcomes

| Binary/configuration | Funding mempool | Spending mempool |
|---|---|---|
| Upstream + `acceptnonstdtxn=1` | accepted and mined | CLEANSTACK rejection |
| Patched + default `acceptnonstdtxn=0` | original `scriptpubkey` rejection | original nonstandard-input rejection |
| Patched + `acceptnonstdtxn=1` | accepted and mined | accepted and mined |

Under the patched opt-in policy, **all 11 consensus-valid spending variants**
pass `testmempoolaccept`. **All 15 invalid controls** fail both mempool checks
and block consensus. The complete primary publication passes `sendrawtransaction`
and ordinary `generatetoaddress` block-template mining. Independent decoding
again recovers 553 scalars and the exact 256 bytes; all 80 funding outputs,
including the helper, are spent. Combined size remains **161,382 vB**.

Evidence: **differentially-validated**. Transaction deployment remains
**consensus-validated** in the catalog; default relay acceptance remains false.
This documents acceptance by the specified modified policy, not adoption by
unmodified Bitcoin nodes or public miners. All testing used disposable regtest
nodes with wallets, peers and external networking disabled.

Reports: [config only](bare-nonstandard-config-only.json),
[patched opt-in](bare-nonstandard-patched.json),
[patched default-policy control](bare-nonstandard-patched-default.json).

## Build and run

The compiled daemon is at:

```text
/private/tmp/bitcoin-core-nonstandard-build/core-build/bin/bitcoind
```

The source is pinned to `49faec4f87f5cd19c88db01a82e5c68b087c8227`.
[Build provenance](core-nonstandard-build.json) records source archives and
SHA256s, compiler, build commands, patch hash, and binary hash. Boost 1.88.0
and libevent 2.1.12 use the hashes in that Core revision's `depends/packages`.
Build tools and dependencies are isolated under `/private/tmp`; wallet, GUI,
IPC, ZMQ, benchmarks and Core unit-test targets were excluded from this daemon
build. The targeted native tests above exercise the changed path.

To recreate the build tools and daemon:

```sh
python3 -m venv /private/tmp/bitcoin-core-nonstandard-tools
/private/tmp/bitcoin-core-nonstandard-tools/bin/python -m pip install cmake==4.4.3 ninja==1.13.2
PYTHONDONTWRITEBYTECODE=1 python3 research/pointlocks-2026-09-17/build_bare_policy_core.py
```

Reproduce the three validation profiles, using local loopback RPC permission:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 research/pointlocks-2026-09-17/bare_nonstandard_mempool_check.py
PYTHONDONTWRITEBYTECODE=1 python3 research/pointlocks-2026-09-17/bare_nonstandard_mempool_check.py --patched
PYTHONDONTWRITEBYTECODE=1 python3 research/pointlocks-2026-09-17/bare_nonstandard_mempool_check.py --patched --default-policy
```

The harness sets `-regtest -acceptnonstdtxn=1` only for its disposable opt-in
nodes and records effective arguments. Existing node settings are not changed.
Primary source: [pinned Core validation implementation](https://github.com/bitcoin/bitcoin/blob/49faec4f87f5cd19c88db01a82e5c68b087c8227/src/validation.cpp).
