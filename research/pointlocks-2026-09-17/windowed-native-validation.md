# Reduced-work native validation of windowed point locks

Question: does the windowed small-r construction support real pre-funded
P2WSH transactions, selectable point revelations, and the complete 256-byte
publication codec under current Bitcoin rules?

**The complete reduced-work fixture passes Bitcoin Core.** It publishes an
arbitrary seeded 256-byte value in **40,656 combined vB**, using signatures
bounded by 59 bytes. This is functional evidence for the native digest,
scripts, codec, and transaction accounting. It does **not** execute the
proposed production 53-byte grind, establish the computational soundness of
that shorter-signature predicate, or make cap59 a secure production substitute.

## Full batched CHECKMULTISIG fixture

Each of **35 P2WSH inputs** contains four fixed six-of-nineteen blocks. There
are **2,660 candidate keys and 840 selected signatures**. Each input has one
secret base `b`; its 76 offsets `a_i` are separate deterministic public test
fixtures in `[0,2^190)`. Production offsets and bases must remain secret.

```text
k0 = 1/2 mod n
r0 = x(k0G)
t_i = b + a_i/(2r0) mod n
s_i = 2z + 2r0*b + a_i mod n.
```

After funding fixes every outpoint, the probe varies the eight-byte nonce in
the corresponding OP_RETURN output. It computes each actual native BIP143
`SINGLE|ANYONECANPAY` digest and retries until every candidate's normalized `s`
has a 31-byte DER encoding. The actual signatures are all exactly 59 bytes.
The script permits signatures at most 59 bytes. Each input is ground
independently; witness selection does not change any native digest.

The measured full fixture needed **9,165 native hash trials** across 35 inputs.
Sixteen pools used the negative low-S band and nineteen used the positive
band, exercising both signs of the known nonce in extraction. These are
reduced-work counts, not a benchmark or estimate for the production grind.

The codec has capacity `binomial(19,6)^140`, approximately
**2061.879088846176 bits**. It interprets the 256 bytes as a big-endian integer
and uses lexicographic subset ranks. Reveal order is not counted as extra
information. Each block's cardinality is enforced by CHECKMULTISIG.

| Transaction | Weight | Virtual bytes |
| --- | ---: | ---: |
| Create first P2TR helper and all 35 P2WSH outputs | 6,464 | 1,616 |
| Spend helper and all 35 P2WSH inputs, with 35 nonce outputs | 156,159 | 39,040 |
| **Combined** | **162,623** | **40,656** |

The boundary includes every pool output's creation and consumption, the P2TR
helper signatures, all 35 zero-value OP_RETURN nonce outputs, transaction
headers, length/count encodings, and separate vbyte rounding. It starts from
one existing P2TR funding input. The test funding grant, extra change, refunds,
and complete BitVM3 protocol transactions are excluded.

Each witness script is **2,761 bytes**. Each complete pool witness is
**4,209 bytes**, with **28 entry data items**: 24 signatures and four required
empty CHECKMULTISIG dummies. There are **zero auxiliary hint items**. The
witness script is the 29th serialized witness item. Across all inputs there
are 980 entry data items and zero hints, on separate execution stacks.

The combined stack peak is **not locally measured** for this profile. The
documented upper bound is 52. The pinned local interpreter does not implement
CHECKMULTISIG, so the probe deliberately skips it and uses host ECDSA checks
plus Bitcoin Core. Compiler-produced static counts are 116 non-push operations,
192 operations including CHECKMULTISIG key charges, and 80 static sigops per
input. The script uses the repository's centralized compilation policy.

[The Core report](windowedbatch256_native_core_check.json) records both
transactions passing default mempool policy, entering the mempool, and being
mined. The exact reduced-work fixture is `differentially-validated` and
`policy-validated`, under Core 30.3 commit
`49faec4f87f5cd19c88db01a82e5c68b087c8227`.

Independent Python reads Core's decoded transaction, reconstructs every BIP143
digest, checks all **2,660 candidate signatures**, identifies the selected
keys from their signatures and each committed multisig block, extracts all
**840 scalars**, and reconstructs the exact original **256-byte** value.
The recovered payload's SHA256 is
`619a68968f5bc0b8afffec4b4945f1a9ad67f06b2a5f5900d282afa7c278aef0`.
The [complete transaction artifact](windowedbatch256-native-transactions.json)
includes all scripts, signatures, selected points, native digests, and trial
counts. Every secret in that artifact is a public deterministic test fixture.

## Relation to the 53-byte size estimate

The [compiled sizing result](windowed-batched-size.json) gives **39,396 vB** for
the same layout with 53-byte signatures: 1,616 vB creation and 37,780 vB
spending. The script length is unchanged; the 840 signatures would each save
six witness bytes, exactly `840*6/4 = 1,260 vB` in total.

That result is `locally-reproduced` serialization accounting with deployment
`unclassified` for the production parameters. The 53-byte signatures have not
been generated on those native transactions. Reducing the guard changes the
funding addresses and digests, so the cap59 signatures cannot be reused.
Production work estimates and the shorter-signature predicate's assumptions
belong to the separate construction and review notes.

## Smaller compact-lookup boundary fixture

[The earlier two-pool report](windowed_native_core_check.json) exercises two
three-of-eight compact HASH160 lookup scripts at cap59. Both valid transactions
passed policy and were mined, at 197 + 488 = **685 vB**. All 16 candidate
signatures verified on their actual native digests; six selected scalars were
independently extracted.

Each script is 223 bytes and each complete witness 513 bytes. Each input has
nine entry data items, including three depth hints, plus the witness script.
The combined main-plus-alt-stack peak is **18**, measured in `ExecCtx::SegwitV0`
with `Options::default()` and enabled stack limits. The two inputs therefore
use six total hint items and eighteen entry data items on separate stacks.

Thirteen negative variants failed both default policy and consensus block
validation: an otherwise valid oversized signature, an uncommitted key,
duplicate selection, missing opening, malformed signature, wrong sighash flag,
zero/one/negative/oversized depths, two hash-authentication aliases, and a changed
native output digest. The aliases specifically exercise the compact lookup's
post-authentication check on the actual signature operand. Those tests concern
the compact lookup; they are not CHECKMULTISIG negative vectors.

## Reproduce and interpret

```sh
python3 research/pointlocks-2026-09-17/windowed_native_core_check.py
python3 research/pointlocks-2026-09-17/windowed_native_core_check.py --profile batch256
```

The isolated regtest has wallets, networking, and peers disabled. Source:
[Rust probe](../../examples/pointlock_windowed_native_probe.rs),
[script builders](../../examples/pointlock_windowed_size_probe.rs), and
[Core harness](windowed_native_core_check.py).

This is publication-component evidence. SINGLE|ANYONECANPAY permits moving
or deleting complete input/output pairs; the standalone point-lock scripts do
not force the helper's presence or require all pools to be consumed together.
A complete BitVM3 integration must make the intended transaction authorization
and publication shape unavoidable, or define how partial spends are handled.
