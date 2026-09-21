# Search 1: three-opcode routing and a fixed first nonce

Question: can two DER rare-event evaluations use more than 27 effective nonce bits within the 201-opcode Legacy limit, with all setup, cleanup, native root binding, and distinctness counted?

**Result: yes for the isolated native-side two-hit fragment.** A 273-byte raw script has **199 counted non-push opcodes**, one fixed nonce `SHA256`, and **76,414,578,004,274,613** permitted distinct second hash words (56.084697 bits after excluding that fixed word). This removes the pair-only nonce-encoding obstacle. It does **not** implement the four evaluations on representations A and B, and supplies no Small arithmetic verifier or complete covenant.

Evidence: exact host counts and deterministic bytecode-model checks are `locally-reproduced`; deployment is `unclassified`. No two-DER-hit witness was mined. These are raw consensus-boundary candidate vectors, not repository compiler metrics. No Tapscript executor or disabled stack-limit helper was used.

Parent validation update: [Core runner](core_fragments.py) and [results](core_fragments.json)
independently accepted all eight observable routing vectors under consensus and
policy, and rejected six malformed routing cases. This establishes
`differentially-validated` / `policy-validated` for those observable fragments
only. They omit the native key check and both DER gates; the complete two-hit
candidate remains `unclassified`. Complete metrics are in the [round report](README.md).

## Exact sequence and boundary

Let `A` be an opaque native-bound public key, necessarily longer than four bytes. Let `n=61`, with 60 witness selectors, pushed in reverse execution order below A. The main stack initially has **exactly 61 items**; the altstack is empty. Pushes do not count towards the 201-opcode limit.

```text
OP_DEPTH <61> OP_EQUALVERIFY                         # 2
<300602010102010101> OP_OVER OP_CHECKSIGVERIFY        # 2

OP_DUP OP_SHA256 OP_DUP OP_0 OP_CHECKSIG OP_DROP
OP_TOALTSTACK                                       # 6

OP_DUP H_0                                          # 2
for i = 1,...,60:
    OP_2 OP_ROLL OP_ROLL H_i                         # 3 per stage

OP_NIP                                              # 1
OP_DUP OP_0 OP_CHECKSIG OP_DROP                       # 3
OP_FROMALTSTACK OP_EQUAL OP_NOT                      # 3
```

The first signature is the fixed r=s=1, SIGHASH_ALL signature already studied in the main investigation. It binds A to the actual transaction through ECDSA recovery. Each empty-key CHECKSIG aborts on malformed nonempty DER and returns false on well-formed DER; DROP discards this false result. Hash-derived lengths exclude the empty-signature bypass. The last three operations require different digests and leave one true item.

The hash schedule is the first 61 symbols of repeated `SARDT`, ending in S:

```text
SARDTSARDTSARDTSARDTSARDTSARDTSARDTSARDTSARDTSARDTSARDTSARDTS
```

Here S=SHA256, A=SHA1, R=RIPEMD160, D=HASH256 and T=HASH160. Both rare-gate outputs are 32 bytes. The full schedule has 85 primitive hash invocations after expanding D into `ss` and T into `sr`; a selected output word has at most 85 primitive invocations.

The generator exports `full_script(schedule)` and a complete hex vector in `search1_nonce_encoding.json`. Its `observable_script(schedule,expected)` replaces the PoW gates and native signature check with an exact observable digest check, for independent Core testing without mining.

## Why three-opcode routing is safe at this boundary

At a routing stage, main stack is `[remaining selectors, state0, state1]`. Both states exceed four bytes. `OP_2 OP_ROLL` brings the next selector above the states. The next OP_ROLL chooses a state, and H hashes it. State count remains exactly two.

An index below zero aborts. An index at least two either fails immediately or moves a future selector into the state region and hashes it. There are then three long state items above the remaining selectors. The next `OP_2 OP_ROLL` fetches a long state, and the following OP_ROLL rejects its greater-than-four-byte ScriptNum. At the final stage there are exactly two main-stack states, so an index at least two fails immediately. The first DER digest is on the altstack and is inaccessible to OP_ROLL.

**Exact initial depth and isolated main-stack layout are essential.** Extra caller state below this fragment would reopen final-stage selection of an unrelated value. This version explicitly rejects extra initial items. Native CHECKSIG establishes that A is a valid public key and thus cannot be a short ScriptNum. The observable test vectors use a fixed 33-byte public root.

## Effective nonces, aliases, and same-nonce use

Every resulting digest is obtained by a subsequence of the hash schedule ending at its final S. The two registers begin with the same A. One receives the selected subsequence, the other absorbs omitted operations; whichever register is updated last is returned. All subsequences ending at the final stage are realizable. The first stage needs no selector because selecting between two identical initial registers would be redundant.

A semantic nonce is the **primitive hash word** over `s` (SHA256), `a` (SHA1), and `r` (RIPEMD160). Exact aliases `D=ss`, `T=sr`, and repeated-symbol subsequence aliases are collapsed. The host script constructs an epsilon NFA for optional schedule stages, determinizes it, and counts distinct accepted words. For n=61 the exact count is 76,414,578,004,274,614. The fixed nonce `s` is among them, so the second nonce domain has one fewer word.

Different selector strings can encode the same semantic word; the program does not pretend those aliases contribute entropy. Since the first nonce is fixed, final digest inequality rejects **every** alias of the fixed word. Hash collisions between different words could cause extra rejection, not accept a duplicated effective nonce. Nonminimal numeric encodings likewise do not create additional effective nonces.

A canonical offchain representative can be obtained by selecting the lexicographically first subsequence whose expanded word equals a desired semantic nonce, using dynamic programming over schedule position and word position. Map its include/omit decisions to the two register positions. Canonical selector bytes are then empty or `01`.

For an A/B bridge, the **same selector vector and fixed hash schedule must drive both representations**, yielding the same primitive word, rather than accepting independent vectors and merely declaring them equal. Digest inequality must hold on at least the native side. This note supplies only the native-side pair; duplicating it for B exceeds 201 opcodes and still would not produce the missing arithmetic representation.

## Honest work and the corrected asymmetric allocation

The earlier two-equal-sized-suffix exclusion does not cover this allocation: fix the first nonce and devote the available routing operations to the second nonce. Search allowed transaction/funding metadata until `DER(SHA256(A))` holds, then search second words for another DER hit. With p=780555/2^65, first-stage expected trials are `1/p = 2^45.425859`; each includes actual transaction hashing and native public-key recovery. Setup is counted, not assumed free.

In the ideal distinct-word model, the second domain has `Np ≈ 2^10.658838`, so after a first hit, the probability there is no second hit is approximately `exp(-1617)`. Uniform sampling of distinct words is available by counting suffix languages in the small deterministic automaton and unranking words. An unranked word is translated to a canonical selector vector by the DP above. No exponentially large table is required.

Even without sharing hash prefixes, the second phase costs at most about `85/p = 2^51.835250` primitive hash invocations in expectation, plus word sampling, native predicate formatting checks, and final verification. Prefix-DAG enumeration can reduce repeated hashing further but is unnecessary for the exponent improvement. A concrete cost claim must additionally price the expected `2^45.425859` native key recoveries and transaction serializations. This experiment does not measure that enormous setup, and does not certify a complete construction below 2^64 total machine operations.

Fixing one nonce restricts the accepted K2,2 proofs; in the ideal independent-edge model it cannot invalidate the general adaptive forgery lower bound quoted in the original two-hit note. Concrete hash-word correlations and state collisions still need a separate security analysis. There is no complete covenant security claim here.

The [independent synthesis](search7_synthesis.md) records an exact small-state
counterexample to treating distinct words as automatically independent and
states the additional transcript/collision obligations. No K2,2 lower-bound
transfer to the concrete routing construction is claimed.

## Costs and reproduction

`complete-leaf:` raw candidate includes root binding, both DER gates, depth validation, all state setup/cleanup, and final inequality; excludes the scriptSig input pushes. Script is 273 bytes and 199 counted/executed non-push opcodes for a successful path. The P2SH wrapper adds two opcodes in its separate evaluation. It does not share the redeemscript's 201-opcode counter.

Inputs: **60 nonce-selector items (60 control hints), one A item, zero other hint items**. All coexist at entry. Combined main-plus-alt peak is **64**, by bytecode inspection. P2SH scriptSig additionally pushes the redeemscript, for 62 pushed items. With canonical binary selectors and compressed 33-byte A, scriptSig is 370 bytes. The P2SH scriptPubKey is 23 bytes. Legacy witness serialization is **0 bytes**. No complete transaction weight is reported.

The raw host interpreter checks all 1,023 selector vectors for schedules of length 1 through 10, eight deterministic length-61 vectors, 300 invalid selector placements, and two incorrect entry-depth cases. Its trace results and observable Core-ready vectors are in the JSON. These host checks do not establish Bitcoin consensus validity.

```sh
python3 research/covenant-2026-09-17/seven/search1_nonce_encoding.py
```

Pinned rule source for review: Bitcoin Core 30.3 commit [`49faec4f87f5cd19c88db01a82e5c68b087c8227`](https://github.com/bitcoin/bitcoin/blob/49faec4f87f5cd19c88db01a82e5c68b087c8227/src/script/interpreter.cpp), especially OP_ROLL, DER validation, public-key validation, stack limits, and opcode counting. Full signatures and Core validation remain for the parent investigation.
