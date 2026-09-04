# Bitcoin Script — Complete Reference

A knowledge-base document covering the Bitcoin scripting language: execution model, full opcode
set, script types, signature hashing, resource limits, standardness policy, and the historical
quirks that make Script behave unlike any other language.

## How to read this document

Every rule is tagged:

- **`[C]` consensus** — violating it makes the transaction invalid in a block. Cannot be bypassed
  without a fork.
- **`[P]` policy / standardness** — violating it means default nodes will not relay or mempool the
  transaction, but it is still valid if mined. Bypassable via direct-to-miner submission,
  `-acceptnonstdtxn`, `generateblock`, or non-default node software.
- **`[?]`** — a value that drifts between Bitcoin Core releases; verify against source before
  depending on it.

**The `[C]` / `[P]` distinction is the single most important thing in this document.** Most
confident-but-wrong claims about Bitcoin Script come from treating a relay policy as a consensus
rule, or vice versa. Non-standard transactions do get mined.

Reviewed against knowledge current to mid-2026. Policy defaults are Bitcoin Core v29/v30-era.
Authoritative source for every number here: `src/script/interpreter.cpp`, `src/script/script.h`,
`src/policy/policy.h`.

---

# Part 1 — The language

## 1.1 What Script is

A stack-based, Forth-like bytecode language evaluated by every full node when validating a
transaction input. Its job is to answer one boolean question: *may this input be spent?*

Deliberate design properties:

- **No loops, no recursion, no jumps.** A single left-to-right pass. Only forward conditional
  execution via `OP_IF`/`OP_NOTIF`/`OP_ELSE`/`OP_ENDIF`. Script is **not Turing complete** and every
  script provably terminates in time bounded by its length.
- **No state.** Two stacks (main and alt) and nothing else. No variables, no heap, no named storage.
  The only dynamic addressing is `OP_PICK`/`OP_ROLL`, which take a stack-supplied index.
- **No introspection.** A script cannot read the transaction spending it: no access to inputs,
  outputs, amounts, txids, fees, or the transaction's own serialisation. The only partial exceptions
  are `OP_CHECKLOCKTIMEVERIFY`/`OP_CHECKSEQUENCEVERIFY`, which *compare against* but cannot *read*
  `nLockTime`/`nSequence`, and signature checks, which verify a commitment to transaction data
  without exposing it. This is the central limitation behind every covenant proposal (`OP_CTV`,
  `OP_CAT`, `OP_TXHASH`, `OP_VAULT`).
- **No external input.** No block data, no timestamps, no randomness, no oracles, no network access.
- **Deterministic.** Every node must reach the same verdict on the same bytes. Anything that could
  vary between implementations is a consensus bug.

## 1.2 Where scripts live

| Location | Contents | Notes |
|---|---|---|
| `scriptPubKey` | Locking script, in a transaction **output** | Sets the spending condition |
| `scriptSig` | Unlocking script, in a transaction **input** | Legacy / P2SH only |
| `witness` | A stack of byte vectors, per input | SegWit v0 and Taproot |
| `redeemScript` | Last stack item of a P2SH `scriptSig` | Executed after the P2SH template matches |
| `witnessScript` | Last witness item of a P2WSH spend | Hash-committed by the scriptPubKey |
| `leafScript` | Second-to-last witness item of a Taproot script-path spend | Committed via Merkle path |

The witness is **not a script** — it is a plain list of byte vectors that becomes the initial stack.
It cannot contain opcodes. This eliminates an entire class of malleability.

## 1.3 Evaluation order

1. The unlocking side is evaluated first: `scriptSig` is executed (legacy), or the witness stack is
   loaded directly (segwit).
2. The resulting stack is passed to the locking script, which executes with that stack as its
   initial state.
3. **The two scripts are evaluated separately, not concatenated.** Bitcoin originally concatenated
   them; this changed in 2010 because concatenation let the spender inject opcodes that interacted
   with the locking script. They now get separate `EvalScript` calls sharing a copied stack.
4. For P2SH: after the locking script succeeds, the final `scriptSig` item is deserialised and
   executed as a script against the remaining stack.
5. For P2WSH / tapscript: the witness script is likewise executed against the remaining witness
   items.

**Success requires** no abort and a final stack that is non-empty with a truthy top element. Under
`CLEANSTACK` (§5.4) the final stack must contain *exactly one* item.

**Failure modes:** an executed `OP_RETURN`; a `VERIFY`-family opcode whose condition is false; a
disabled or reserved opcode; stack underflow; exceeding a resource limit; unbalanced conditionals;
a false or empty final stack.

## 1.4 Truthiness

An element is **false** if it is:

- the empty byte vector, or
- all zero bytes (`0x00`, `0x0000`, …), or
- "negative zero" (`0x80`, or any run of zeros followed by `0x80`).

Everything else is true. Note that `0x00` — a single zero byte — is false, and is a *different stack
element* from the empty vector even though both are false. This distinction causes recurring bugs.

## 1.5 Number encoding (`CScriptNum`)

- **Little-endian, sign-magnitude.** The high bit of the *last* (most significant) byte is the sign
  bit. `1` is `0x01`, `-1` is `0x81`, `127` is `0x7f`, `128` is `0x8000`, `-128` is `0x8080`. This is
  **not** two's complement.
- If the magnitude's top byte would have its high bit set, an extra byte is appended to carry the
  sign — which is why `128` needs two bytes.
- **Negative zero (`0x80`) is representable** and distinct from the empty vector, though both are
  false.
- **Arithmetic operands are limited to 4 bytes `[C]`** — values in ±(2³¹−1). A result may exceed this
  and sit on the stack, but feeding it into another arithmetic opcode fails. Script therefore has no
  native 64-bit arithmetic, which is why satoshi amounts (needing 51 bits) cannot be manipulated
  directly — a major obstacle for on-chain amount logic.
- `OP_CHECKLOCKTIMEVERIFY` and `OP_CHECKSEQUENCEVERIFY` accept **5-byte** operands `[C]`, so
  locktimes beyond the 4-byte signed range are expressible.
- **Minimal encoding** (`SCRIPT_VERIFY_MINIMALDATA`) `[P]`: numbers must use the fewest bytes
  possible. `0x0100` for 1 is consensus-valid but non-standard.

## 1.6 Push semantics

| Encoding | Byte(s) | Payload size |
|---|---|---|
| Direct push | `0x01`–`0x4b` | 1–75 bytes |
| `OP_PUSHDATA1` | `0x4c` + 1-byte len | up to 255 |
| `OP_PUSHDATA2` | `0x4d` + 2-byte LE len | up to 65,535 |
| `OP_PUSHDATA4` | `0x4e` + 4-byte LE len | up to 2³²−1 |

The encoding can express far more than the machine allows: **any single stack element is capped at
520 bytes `[C]`** (`MAX_SCRIPT_ELEMENT_SIZE`) — in legacy, segwit v0, and tapscript alike. A
`PUSHDATA2` of 1,000 bytes is well-formed and always fails at runtime.

`MINIMALDATA` `[P]` additionally requires the *smallest* available push encoding: `OP_1` not
`0x0101`, a direct push not `PUSHDATA1` for short values, `OP_0` not a zero-length `PUSHDATA1`.

---

# Part 2 — Opcode reference

Stack notation reads left to right with the **top of stack on the right**: `x1 x2 → x2 x1` means the
top two items are swapped.

## 2.1 Constants

| Opcode | Hex | Effect |
|---|---|---|
| `OP_0`, `OP_FALSE` | `0x00` | Pushes the **empty byte vector** (not a zero byte) |
| *(direct push)* | `0x01`–`0x4b` | Pushes the next N bytes |
| `OP_PUSHDATA1` | `0x4c` | Pushes N bytes, N in the next 1 byte |
| `OP_PUSHDATA2` | `0x4d` | N in the next 2 bytes (LE) |
| `OP_PUSHDATA4` | `0x4e` | N in the next 4 bytes (LE) |
| `OP_1NEGATE` | `0x4f` | Pushes `0x81` (−1) |
| `OP_RESERVED` | `0x50` | **Invalid if executed**; fine in a dead branch. `OP_SUCCESS80` in tapscript |
| `OP_1`…`OP_16` | `0x51`–`0x60` | Pushes a single byte `0x01`…`0x10`. `OP_1` is also `OP_TRUE` |

Everything `≤ OP_16` (`0x60`) is a "push" and does **not** count toward the 201-opcode limit.

## 2.2 Flow control

| Opcode | Hex | Effect |
|---|---|---|
| `OP_NOP` | `0x61` | Does nothing |
| `OP_VER` | `0x62` | **Invalid if executed**. `OP_SUCCESS98` in tapscript |
| `OP_IF` | `0x63` | Pops a value; executes the branch if true |
| `OP_NOTIF` | `0x64` | Pops a value; executes if false |
| `OP_VERIF` | `0x65` | **Always invalid**, even unexecuted, in every script version |
| `OP_VERNOTIF` | `0x66` | **Always invalid**, even unexecuted |
| `OP_ELSE` | `0x67` | Inverts the current branch condition |
| `OP_ENDIF` | `0x68` | Closes the conditional |
| `OP_VERIFY` | `0x69` | Pops; fails the script if false |
| `OP_RETURN` | `0x6a` | **Fails the script immediately** when executed |

- `OP_IF`/`OP_NOTIF` **consume** their condition. `VERIFY`-suffixed opcodes push nothing. Mismatched
  `IF`/`ENDIF` is a script error.
- Conditionals nest; depth is bounded only by script size.
- `OP_RETURN` fails only when **executed** — it can sit harmlessly in a dead branch. Contrast the
  disabled opcodes (§2.9), which fail even unexecuted. As the first opcode of a `scriptPubKey` it
  makes the output provably unspendable and prunable from the UTXO set.
- **`MINIMALIF`**: the `OP_IF`/`OP_NOTIF` operand must be exactly the empty vector or `0x01`. `[P]`
  for legacy and segwit v0, **`[C]` for tapscript**. Without it the condition is malleable — a
  third party can swap `0x02` for `0x01` and change the txid.

## 2.3 Stack manipulation

| Opcode | Hex | Stack effect |
|---|---|---|
| `OP_TOALTSTACK` | `0x6b` | Moves the top item to the alt stack |
| `OP_FROMALTSTACK` | `0x6c` | Moves the top alt-stack item back |
| `OP_2DROP` | `0x6d` | `x1 x2 →` |
| `OP_2DUP` | `0x6e` | `x1 x2 → x1 x2 x1 x2` |
| `OP_3DUP` | `0x6f` | `x1 x2 x3 → x1 x2 x3 x1 x2 x3` |
| `OP_2OVER` | `0x70` | `x1 x2 x3 x4 → x1 x2 x3 x4 x1 x2` |
| `OP_2ROT` | `0x71` | `x1 x2 x3 x4 x5 x6 → x3 x4 x5 x6 x1 x2` |
| `OP_2SWAP` | `0x72` | `x1 x2 x3 x4 → x3 x4 x1 x2` |
| `OP_IFDUP` | `0x73` | Duplicates the top item **only if truthy** |
| `OP_DEPTH` | `0x74` | Pushes the stack size (before the push) |
| `OP_DROP` | `0x75` | `x →` |
| `OP_DUP` | `0x76` | `x → x x` |
| `OP_NIP` | `0x77` | `x1 x2 → x2` |
| `OP_OVER` | `0x78` | `x1 x2 → x1 x2 x1` |
| `OP_PICK` | `0x79` | `xn … x0 n → xn … x0 xn` — **copies** the nth item |
| `OP_ROLL` | `0x7a` | `xn … x0 n → … x0 xn` — **moves** the nth item |
| `OP_ROT` | `0x7b` | `x1 x2 x3 → x2 x3 x1` |
| `OP_SWAP` | `0x7c` | `x1 x2 → x2 x1` |
| `OP_TUCK` | `0x7d` | `x1 x2 → x2 x1 x2` |

`OP_PICK` and `OP_ROLL` are the only dynamically-addressed opcodes, taking a 0-based index from the
top of the stack. They are the closest thing Script has to array indexing and are what make
table-lookup constructions possible. The index must be a valid `CScriptNum` within the current stack
depth or the script fails — so an **untrusted index must be clamped** (typically with `OP_MIN`)
before use, or an out-of-range value becomes a denial-of-spend.

`OP_IFDUP` makes stack depth data-dependent, which is why it appears rarely; it exists to save a
`DUP`+`IF` pair.

The **alt stack** counts toward the same 1,000-element limit as the main stack. It is otherwise just
scratch space, useful because Script cannot cheaply reach past a few positions.

## 2.4 Splice

| Opcode | Hex | Status |
|---|---|---|
| `OP_CAT` | `0x7e` | **Disabled** |
| `OP_SUBSTR` | `0x7f` | **Disabled** |
| `OP_LEFT` | `0x80` | **Disabled** |
| `OP_RIGHT` | `0x81` | **Disabled** |
| `OP_SIZE` | `0x82` | Pushes the **byte length** of the top item, without popping it |

`OP_SIZE` is the only surviving splice opcode and is more useful than it looks: it is the sole way
for Script to observe a property of an opaque blob it cannot otherwise read — most importantly the
length of a DER-encoded signature (§4.6), which varies with the signature's numeric content.

`OP_CAT`'s absence is why hash-chain, covenant, and data-manipulation constructions are so
contorted: there is no way to assemble a preimage from parts before hashing it. It was disabled in
2010 alongside the bitwise and multiplication opcodes after a memory-exhaustion DoS (repeated
concatenation doubling an element's size). Re-enabling it in tapscript, where the 520-byte element
cap already bounds the DoS, is an active proposal.

## 2.5 Bitwise and equality

| Opcode | Hex | Status |
|---|---|---|
| `OP_INVERT` | `0x83` | **Disabled** |
| `OP_AND` | `0x84` | **Disabled** |
| `OP_OR` | `0x85` | **Disabled** |
| `OP_XOR` | `0x86` | **Disabled** |
| `OP_EQUAL` | `0x87` | Pops two; pushes 1 if byte-identical, else the empty vector |
| `OP_EQUALVERIFY` | `0x88` | `OP_EQUAL` + `OP_VERIFY` |
| `OP_RESERVED1` | `0x89` | Invalid if executed |
| `OP_RESERVED2` | `0x8a` | Invalid if executed |

`OP_EQUAL` compares **raw bytes**, not numeric values: `0x01` and `0x0100` are numerically equal but
not `OP_EQUAL`. Use `OP_NUMEQUAL` for numeric comparison — but note `OP_NUMEQUAL` fails on operands
longer than 4 bytes, so hashes and pubkeys must be compared with `OP_EQUAL`.

## 2.6 Arithmetic

All operands must be ≤ 4 bytes `[C]`.

| Opcode | Hex | Effect |
|---|---|---|
| `OP_1ADD` | `0x8b` | `a → a+1` |
| `OP_1SUB` | `0x8c` | `a → a−1` |
| `OP_2MUL` | `0x8d` | **Disabled** |
| `OP_2DIV` | `0x8e` | **Disabled** |
| `OP_NEGATE` | `0x8f` | `a → −a` |
| `OP_ABS` | `0x90` | absolute value |
| `OP_NOT` | `0x91` | `a → 1 if a==0 else 0` |
| `OP_0NOTEQUAL` | `0x92` | `a → 0 if a==0 else 1` |
| `OP_ADD` | `0x93` | `a b → a+b` |
| `OP_SUB` | `0x94` | `a b → a−b` |
| `OP_MUL` | `0x95` | **Disabled** |
| `OP_DIV` | `0x96` | **Disabled** |
| `OP_MOD` | `0x97` | **Disabled** |
| `OP_LSHIFT` | `0x98` | **Disabled** |
| `OP_RSHIFT` | `0x99` | **Disabled** |
| `OP_BOOLAND` | `0x9a` | both non-zero |
| `OP_BOOLOR` | `0x9b` | either non-zero |
| `OP_NUMEQUAL` | `0x9c` | numeric equality |
| `OP_NUMEQUALVERIFY` | `0x9d` | + `VERIFY` |
| `OP_NUMNOTEQUAL` | `0x9e` | numeric inequality |
| `OP_LESSTHAN` | `0x9f` | `a b → a<b` |
| `OP_GREATERTHAN` | `0xa0` | `a b → a>b` |
| `OP_LESSTHANOREQUAL` | `0xa1` | `a b → a≤b` |
| `OP_GREATERTHANOREQUAL` | `0xa2` | `a b → a≥b` |
| `OP_MIN` | `0xa3` | smaller of two |
| `OP_MAX` | `0xa4` | larger of two |
| `OP_WITHIN` | `0xa5` | `x min max → min ≤ x < max` (**half-open**) |

There is **no multiplication, division, or modulo**. Multiplication by a constant must be built from
repeated `OP_ADD`/`OP_DUP`; division is effectively unavailable. Combined with the 4-byte operand
limit, Script's arithmetic suits counters, indices, and small comparisons and nothing more.

`OP_WITHIN` is inclusive on the lower bound, exclusive on the upper — an easy off-by-one.

## 2.7 Cryptography

| Opcode | Hex | Effect |
|---|---|---|
| `OP_RIPEMD160` | `0xa6` | RIPEMD-160 |
| `OP_SHA1` | `0xa7` | SHA-1 |
| `OP_SHA256` | `0xa8` | SHA-256 |
| `OP_HASH160` | `0xa9` | RIPEMD160(SHA256(x)) |
| `OP_HASH256` | `0xaa` | SHA256(SHA256(x)) |
| `OP_CODESEPARATOR` | `0xab` | Marks where the scriptCode begins for later signature checks |
| `OP_CHECKSIG` | `0xac` | `sig pubkey → bool` |
| `OP_CHECKSIGVERIFY` | `0xad` | + `VERIFY` |
| `OP_CHECKMULTISIG` | `0xae` | `dummy sig… m pubkey… n → bool` |
| `OP_CHECKMULTISIGVERIFY` | `0xaf` | + `VERIFY` |
| `OP_CHECKSIGADD` | `0xba` | **Tapscript only**: `sig num pubkey → num` or `num+1` |

Security notes:

- **`OP_HASH160` gives a 160-bit output → only ~80-bit collision resistance.** Wherever an adversary
  can influence what gets hashed, assume 2⁸⁰ is the ceiling. This is why P2SH is considered risky
  for multi-party contracts in which a counterparty contributes script material, and why P2WSH's
  256-bit SHA-256 is preferred.
- **`OP_SHA1` is collision-broken.** Never use it for security. It remains available and is
  occasionally used *deliberately* in research constructions precisely because collisions are
  findable.
- `OP_CHECKSIG` **returns false rather than aborting** on an invalid signature — unless `NULLFAIL`
  applies, which requires a failing check to have been given an *empty* signature. You cannot pass
  garbage and branch on the result.
- Hashing operates on whole stack elements. Without `OP_CAT` you cannot hash a concatenation.

## 2.8 Locktime and upgrade hooks

| Opcode | Hex | Effect |
|---|---|---|
| `OP_NOP1` | `0xb0` | No-op; `[P]` discouraged |
| `OP_CHECKLOCKTIMEVERIFY` (`OP_NOP2`) | `0xb1` | Absolute timelock check (BIP-65) |
| `OP_CHECKSEQUENCEVERIFY` (`OP_NOP3`) | `0xb2` | Relative timelock check (BIP-112) |
| `OP_NOP4`–`OP_NOP10` | `0xb3`–`0xb9` | No-ops; `[P]` discouraged |

`OP_NOP1` and `OP_NOP4`–`OP_NOP10` are true no-ops at consensus `[C]` but rejected by
`DISCOURAGE_UPGRADABLE_NOPS` `[P]`, reserving them for soft forks. `OP_NOP2` and `OP_NOP3` were
consumed exactly that way.

**Both timelock opcodes are `VERIFY`-style**: they fail the script on violation and **leave the
operand on the stack**, so idiomatic use is `<n> OP_CHECKLOCKTIMEVERIFY OP_DROP`.

**`OP_CHECKLOCKTIMEVERIFY` (absolute)** fails `[C]` if:
- the operand is negative;
- the operand and the transaction's `nLockTime` fall on opposite sides of the **500,000,000**
  threshold (below = block height, at/above = Unix timestamp) — you cannot compare a height against
  a time;
- the operand is greater than `nLockTime`;
- the input's `nSequence` is `0xffffffff`, which would disable locktime enforcement entirely.

Accepts 5-byte operands.

**`OP_CHECKSEQUENCEVERIFY` (relative)** compares against the input's `nSequence`:
- **Bit 31** (`0x80000000`) is the **disable flag**. If set in `nSequence`, relative locktime is off
  and CSV fails.
- **Bit 22** (`0x00400000`) selects units: unset = **blocks**, set = **512-second intervals**. The
  operand and `nSequence` must agree on this bit.
- The **low 16 bits** carry the value — maximum relative lock is 65,535 blocks (~455 days) or
  65,535 × 512 s (~388 days).
- Requires transaction `nVersion ≥ 2` `[C]`.

The corresponding transaction-level rules are BIP-68 (`nSequence` semantics) and `nLockTime` itself;
the opcodes make those fields *enforceable by the script* rather than merely settable by the spender.

## 2.9 Disabled, reserved, and undefined

**Permanently disabled `[C]`, and — critically — they fail even inside an unexecuted branch:**

`OP_CAT`, `OP_SUBSTR`, `OP_LEFT`, `OP_RIGHT`, `OP_INVERT`, `OP_AND`, `OP_OR`, `OP_XOR`, `OP_2MUL`,
`OP_2DIV`, `OP_MUL`, `OP_DIV`, `OP_MOD`, `OP_LSHIFT`, `OP_RSHIFT`.

The check happens during the opcode scan, before the executed/not-executed test. You cannot hide a
disabled opcode behind `OP_0 OP_IF … OP_ENDIF`.

**Always invalid, even unexecuted, in every script version:** `OP_VERIF` (`0x65`), `OP_VERNOTIF`
(`0x66`).

**Invalid only if executed:** `OP_RESERVED` (`0x50`), `OP_VER` (`0x62`), `OP_RESERVED1` (`0x89`),
`OP_RESERVED2` (`0x8a`).

**Undefined:** `0xbb`–`0xff` are invalid in legacy and segwit v0. In tapscript most become
`OP_SUCCESSx` (§6.5) — which **inverts** the behaviour from "always fails" to "always succeeds."

---

# Part 3 — Script types

## 3.1 P2PK — Pay to Public Key

```
scriptPubKey:  <pubkey> OP_CHECKSIG
scriptSig:     <signature>
```

- The original 2009 form, used by early coinbase outputs including the genesis block.
- Accepts compressed (33-byte) or uncompressed (65-byte) keys.
- **No address format exists** — P2PK predates addresses.
- Bloats the UTXO set: the full key sits in the output, and is exposed before spending (the basis of
  quantum-exposure arguments about early coins).
- scriptPubKey size: 35 or 67 bytes.

## 3.2 P2PKH — Pay to Public Key Hash

```
scriptPubKey:  OP_DUP OP_HASH160 <20-byte hash160(pubkey)> OP_EQUALVERIFY OP_CHECKSIG
scriptSig:     <signature> <pubkey>
```

- 25 bytes. Dominant form from 2011 until segwit adoption.
- Address: Base58Check, version `0x00` mainnet (`1…`), `0x6f` testnet (`m…`/`n…`).
- The `OP_DUP` exists because `OP_HASH160` consumes its input and the key is needed again for
  `OP_CHECKSIG`.
- Uncompressed keys remain permitted `[C]` and standard `[P]`. Compressed and uncompressed forms of
  the same key give **different addresses** — a classic wallet-recovery pitfall.

## 3.3 P2MS — Bare multisig

```
scriptPubKey:  OP_m <pubkey_1> … <pubkey_n> OP_n OP_CHECKMULTISIG
scriptSig:     OP_0 <sig_1> … <sig_m>
```

- `[C]` up to n = 20 keys. `[P]` standard only for **n ≤ 3**, and only when `-permitbaremultisig` is
  enabled (Core default true; Knots and some configurations disable it).
- No address format.
- Signatures must appear in the **same relative order as their pubkeys** (§6.1).
- Requires the `OP_0` dummy element (§6.1).
- Historically abused as a data carrier via fake pubkeys, which is why the policy switch exists.
  Superseded by P2SH/P2WSH-wrapped multisig, which keeps the keys hidden until spend and the output
  small.

## 3.4 P2SH — Pay to Script Hash (BIP-16)

```
scriptPubKey:  OP_HASH160 <20-byte hash160(redeemScript)> OP_EQUAL
scriptSig:     <…redeemScript args…> <serialized redeemScript>
```

- **Special-cased in the interpreter**, not expressible in pure Script semantics: when the
  scriptPubKey byte-for-byte matches the template, the final `scriptSig` item is deserialised and
  executed.
- **scriptSig must be push-only `[C]`** for P2SH inputs. (For bare legacy inputs push-only is merely
  `[P]`, via `SIGPUSHONLY`.)
- **redeemScript ≤ 520 bytes `[C]`**, because it travels as a stack element. Far below the
  10,000-byte script limit, and the practical ceiling on legacy contract complexity.
- Address: Base58Check version `0x05` mainnet (`3…`), `0xc4` testnet (`2…`).
- **160-bit hash → ~80-bit collision resistance.** Where an adversary contributes script material
  they may be able to construct two redeemScripts with the same hash for ~2⁸⁰ work. P2WSH's 256-bit
  hash has no such weakness.
- `[P]` caps the redeemScript at 15 sigops (`MAX_P2SH_SIGOPS`), which limits bare multisig nested
  inside P2SH.

## 3.5 P2WPKH — Pay to Witness Public Key Hash (BIP-141/143)

```
scriptPubKey:  OP_0 <20-byte hash160(pubkey)>
scriptSig:     (empty)
witness:       <signature> <pubkey>
```

- Witness program version 0, 20-byte program. 22-byte scriptPubKey.
- **The sighash scriptCode is *not* the scriptPubKey.** It is a synthesised P2PKH script,
  `0x1976a914{20-byte keyhash}88ac`. Implementations get this wrong constantly.
- **Uncompressed pubkeys are non-standard `[P]`** in segwit v0 (`WITNESS_PUBKEYTYPE`).
- Address: bech32, HRP `bc1` mainnet / `tb1` testnet, witness version 0.
- Signature data lives in the witness: discounted 4× in weight, excluded from the txid.

## 3.6 P2WSH — Pay to Witness Script Hash

```
scriptPubKey:  OP_0 <32-byte sha256(witnessScript)>
witness:       <…args…> <witnessScript>
```

- **Single SHA-256**, not HASH160 — 256-bit, no collision concern.
- The witnessScript *is* the scriptCode. No `FindAndDelete`.
- Limits: witnessScript ≤ 10,000 bytes `[C]` but **3,600 bytes `[P]`**
  (`MAX_STANDARD_P2WSH_SCRIPT_SIZE`); witness stack ≤ 100 items `[C]` of ≤ 520 bytes each `[C]`,
  tightened to **≤ 80 bytes per item `[P]`** (`MAX_STANDARD_P2WSH_STACK_ITEM_SIZE`).
- The 80-byte standard stack-item limit is a frequent surprise — it blocks pushing, say, a 100-byte
  proof element in a relayable transaction.
- Address: bech32, 32-byte program.

## 3.7 Nested SegWit — P2SH-P2WPKH / P2SH-P2WSH

```
scriptPubKey:  OP_HASH160 <hash160(witnessProgram)> OP_EQUAL
scriptSig:     <serialized witnessProgram>      e.g. <0x0014{20-byte keyhash}>
witness:       <signature> <pubkey>
```

- Wraps a witness program in P2SH so pre-segwit wallets can pay to a familiar `3…` address.
- The `scriptSig` must be **exactly one push** of the serialised witness program; any extra content
  disables witness handling and the spend fails.
- Costs extra bytes versus native segwit and reintroduces the 160-bit hash. Legacy compatibility
  only; avoid for new work.

## 3.8 P2TR — Pay to Taproot (BIP-341/342)

```
scriptPubKey:  OP_1 <32-byte x-only output key>
```

Output key `Q = P + t·G`, where `P` is the internal key and
`t = tagged_hash("TapTweak", P ‖ merkle_root)`.

**Key path spend.** Witness is a single element: a **64-byte** Schnorr signature (implicit
`SIGHASH_DEFAULT`) or **65 bytes** with an explicit sighash flag appended. On-chain this is
indistinguishable from a plain single-signature spend — the privacy benefit. MuSig2 or FROST
multisig looks identical to single-sig.

**Script path spend.** Witness is `[…script args…] [leafScript] [controlBlock]`.
- Control block is `33 + 32m` bytes: one byte (leaf version | parity of the output key), the 32-byte
  internal key, then `m` Merkle path elements.
- **Merkle path depth ≤ 128 `[C]`** → up to 2¹²⁸ leaves. Only the executed leaf and its path are
  revealed; sibling branches stay private.
- Leaf hash = `tagged_hash("TapLeaf", leaf_version ‖ compact_size(script) ‖ script)`. Branches use
  `tagged_hash("TapBranch", …)` over the two children **sorted lexicographically**, so no left/right
  position information leaks.
- **Leaf version `0xc0` = tapscript.** Other leaf versions are reserved and evaluate as
  **anyone-can-spend `[C]`** (upgrade hook), non-standard `[P]`. The version byte's low bit carries
  the parity flag, so valid versions are even.

**Annex.** If the witness has ≥ 2 elements and the last begins with `0x50`, it is the annex: stripped
before evaluation, committed to by the signature, otherwise unused. Non-standard `[P]`,
consensus-valid `[C]`. Reserved for future extension.

- Address: **bech32m** (BIP-350), *not* bech32 — a different checksum constant, adopted because
  bech32 has a length-extension weakness at certain lengths. Witness version 1.
- Encoding a v1 address with a bech32 encoder produces something invalid or silently wrong. Always
  match encoding to witness version.

## 3.9 OP_RETURN — provably unspendable data carrier

```
scriptPubKey:  OP_RETURN <data>
```

- The script fails immediately when executed, so the output can never be spent and nodes prune it
  from the UTXO set. That is the point: it is the UTXO-set-friendly way to embed data.
- Almost always created with a zero-satoshi value.
- **Policy history:** for years `[P]` allowed exactly one such output per transaction carrying ≤ 80
  bytes (`-datacarriersize` 83, counting opcode and push). **Bitcoin Core v30 (October 2025)** raised
  the default to 100,000 bytes — effectively uncapped, since the transaction size limit binds first
  — and permitted **multiple** data-carrying outputs. The `-datacarrier`/`-datacarriersize` options
  remain configurable (a planned deprecation was reversed shortly before release). Bitcoin Knots
  ships tighter defaults.
- This is politically contested. **Do not assume any given node relays large OP_RETURN data**; assume
  heterogeneous policy across the network.
- None of it was ever a consensus rule. Miners have always been free to include arbitrary sizes.

## 3.10 Non-standard and special cases

- **Empty scriptPubKey**: spendable by anyone with `OP_1` in the scriptSig. `[C]` valid, `[P]`
  non-standard.
- **Future witness versions v2–v16**: `[C]` **anyone-can-spend** — the soft-fork upgrade hook. `[P]`
  non-standard (`DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM`). Never pay to one.
- **Malformed witness v0 programs**: a v0 program that is neither 20 nor 32 bytes is `[C]`
  **invalid** — not anyone-can-spend. v0 was locked down; later versions deliberately were not.
- **Bare (raw) scripts**: an arbitrary script placed directly in a scriptPubKey. `[C]` valid up to
  10,000 bytes; `[P]` non-standard unless it matches a known template. The only way to execute a
  legacy script larger than the 520-byte P2SH ceiling.
- **NUMS internal key**: a taproot output whose internal key is a provably-unspendable point (no
  known discrete log) is script-path-only. The standard construction for "no key-path escape hatch."

## 3.11 Size and weight quick reference

| Type | scriptPubKey | Typical spend input (vbytes) |
|---|---|---|
| P2PK | 35 / 67 B | ~114 |
| P2PKH | 25 B | ~148 |
| P2SH 2-of-3 | 23 B | ~297 |
| P2WPKH | 22 B | ~68 |
| P2WSH 2-of-3 | 34 B | ~104 |
| P2SH-P2WPKH | 23 B | ~91 |
| P2TR key path | 34 B | ~57.5 |

Weight: non-witness bytes count **4 WU**, witness bytes count **1 WU**. `vsize = ceil(weight / 4)`.
Block limit 4,000,000 WU `[C]`.

---

# Part 4 — Signature hashing

Signature checks are the only mechanism by which a script commits to the transaction spending it.
Everything about *what* a signature commits to is determined by the sighash algorithm and the
sighash flag byte.

## 4.1 The six sighash modes

The final byte of an ECDSA signature is the sighash flag.

| Mode | Flag | Commits to | Omits |
|---|---|---|---|
| `ALL` | `0x01` | nVersion, all prevouts, all nSequence, all outputs, nLockTime | nothing |
| `NONE` | `0x02` | nVersion, all prevouts, **this input's** nSequence, nLockTime | all outputs; zeroes other inputs' nSequence |
| `SINGLE` | `0x03` | nVersion, all prevouts, this input's nSequence, **the output at the same index**, nLockTime | other outputs; zeroes other inputs' nSequence |
| `ALL｜ANYONECANPAY` | `0x81` | nVersion, this input's prevout + nSequence, all outputs, nLockTime | all other inputs |
| `NONE｜ANYONECANPAY` | `0x82` | nVersion, this input's prevout + nSequence, nLockTime | all outputs, all other inputs |
| `SINGLE｜ANYONECANPAY` | `0x83` | nVersion, this input's prevout + nSequence, one output, nLockTime | other inputs, other outputs |

Taproot adds **`SIGHASH_DEFAULT` = `0x00`**, which commits to exactly the same fields as `ALL` but is
encoded by *omitting* the flag byte, giving a 64-byte signature.

**`SIGHASH_DEFAULT` is not the same hash type as `SIGHASH_ALL`.** They cover identical data, but
`hash_type` is itself the first byte of the sighash message (after the epoch byte), so `0x00` and
`0x01` produce **different digests** over the same transaction. A signature valid under one is not
valid under the other. The rules:

| Signature | Meaning | Valid? |
|---|---|---|
| 64 bytes | `SIGHASH_DEFAULT` (`0x00`) — inferred from length | Yes |
| 65 bytes ending `0x01` | `SIGHASH_ALL` — same coverage, one byte larger | Yes `[C]` |
| 65 bytes ending `0x00` | An explicit `SIGHASH_DEFAULT` | **Invalid `[C]`** |

The last row is deliberate: BIP-341 rejects an explicitly-appended `0x00` so that the default has
exactly one encoding. Two valid encodings of the same hash type would be a malleability vector.

Practical uses: `NONE` lets one party sign an input while leaving the outputs to others (blank
cheque). `SINGLE` pairs input *i* with output *i*, used in some coinjoin and swap designs.
`ANYONECANPAY` lets others add inputs, used in crowdfunding/assurance-contract patterns.

## 4.2 The sighash byte is barely validated

The mode is decoded by masking, not by comparison:

- `flag & 0x1f` selects the base mode; **anything other than 2 or 3 is treated as ALL**.
- `flag & 0x80` selects ANYONECANPAY.

Consequences for legacy and segwit v0:

- **All 256 byte values are `[C]` valid**, and each produces a *different* sighash, because the full
  4-byte flag is appended to the preimage. `0x01`, `0x21`, and `0x41` all mean ALL but hash
  differently.
- Only the 6 canonical values are `[P]` standard (`STRICTENC`).
- This gives a spender **8 free bits of sighash entropy per signature at zero computational cost** —
  relevant to any construction whose security rests on the difficulty of reaching a particular
  sighash.
- **Taproot closes this**: unknown sighash flags are `[C]` invalid, and `0x00` explicitly means
  DEFAULT.

## 4.3 Legacy sighash algorithm (pre-SegWit)

Double-SHA256 over a serialisation of the transaction in which:

- the current input's scriptSig is replaced by the **scriptCode**;
- all other inputs' scriptSigs are replaced by empty;
- inputs and outputs are dropped or zeroed according to the mode;
- the 4-byte sighash type is appended.

Known defects, all fixed by later versions:

- **Quadratic hashing.** The sighash is recomputed from scratch for every input, so validation cost
  grows as O(n²) in transaction size. This is the DoS vector behind block-validation-time concerns.
- **Does not commit to the input amount** — enabling a fee-blindness attack where a signer can be
  tricked about how much they are spending. Fixed in BIP-143.
- **`FindAndDelete` mutates the scriptCode** (§6.3).
- **The `SIGHASH_SINGLE` bug** (§6.2).

## 4.4 BIP-143 sighash (SegWit v0)

Preimage field order:

```
nVersion (4) ‖ hashPrevouts (32) ‖ hashSequence (32) ‖ outpoint (36) ‖
scriptCode (var) ‖ amount (8) ‖ nSequence (4) ‖ hashOutputs (32) ‖
nLockTime (4) ‖ sighashType (4)
```

- `hashPrevouts` / `hashSequence` / `hashOutputs` are precomputed once per transaction and reused
  across inputs → **linear** validation.
- **Commits to the input amount `[C]`** — closes the fee-blindness attack.
- **Explicitly removes `FindAndDelete`.** The scriptCode is the witnessScript verbatim (or the
  synthesised P2PKH script for P2WPKH).
- `OP_CODESEPARATOR` retained but simplified: the scriptCode starts after the last *executed*
  separator.
- Under `ANYONECANPAY`, `NONE`, or `SINGLE`, the corresponding precomputed hashes are replaced by
  32 zero bytes.

## 4.5 BIP-341 sighash (Taproot)

Single SHA-256 with **tagged hashing** (`TapSighash`), not double-SHA256, and prefixed with a
`0x00` epoch byte. Field order:

```
hash_type (1) ‖ nVersion (4) ‖ nLockTime (4) ‖
[ if not ANYONECANPAY: sha_prevouts ‖ sha_amounts ‖ sha_scriptpubkeys ‖ sha_sequences ] ‖
[ if not NONE/SINGLE: sha_outputs ] ‖
spend_type (1) ‖
[ if ANYONECANPAY: outpoint ‖ amount ‖ scriptPubKey ‖ nSequence  else: input_index (4) ] ‖
[ if annex: sha_annex ] ‖
[ if SINGLE: sha_single_output ]
[ script path only: tapleaf_hash (32) ‖ key_version (1) ‖ codesep_pos (4) ]
```

- **Commits to all input amounts *and* all input scriptPubKeys** — a strictly stronger commitment
  than BIP-143, closing several attack classes involving lying about what other inputs are.
- Commits to the annex when present, the leaf hash on script path, and the codeseparator position
  as an explicit field rather than by mutating the scriptCode.
- Unknown sighash flags `[C]` rejected.
- Tagged hashing (`SHA256(SHA256(tag) ‖ SHA256(tag) ‖ msg)`) domain-separates every hash use in
  taproot, preventing cross-context collisions.

## 4.6 scriptCode — what the signature actually covers

The scriptCode is "the portion of the spending condition the signature commits to." Which bytes
those are differs per context, and this is a persistent source of implementation bugs:

| Context | scriptCode |
|---|---|
| Bare / P2PK / P2PKH / P2MS | The scriptPubKey, **after `FindAndDelete`** and from the last executed `OP_CODESEPARATOR` |
| P2SH | The redeemScript, same treatment |
| P2WPKH | Synthesised P2PKH script `0x1976a914{keyhash}88ac` — *not* the scriptPubKey |
| P2WSH | The witnessScript, from the last executed `OP_CODESEPARATOR`, **no `FindAndDelete`** |
| Tapscript | No scriptCode; the sighash commits to the **leaf hash** plus `codesep_pos` |

## 4.7 ECDSA signature encoding

```
0x30 [total-len] 0x02 [r-len] [r] 0x02 [s-len] [s] [sighash-flag]
```

- Six bytes of DER structure plus the two integers plus one sighash byte.
- **Strict DER (BIP-66, `[C]` since 2015)** requires integers encoded non-negative and minimally: if
  the MSB of `r` or `s` is set, a `0x00` byte is prepended (adding a byte); unnecessary leading zeros
  must be trimmed.
- Bitcoin Core's `IsValidSignatureEncoding` bounds the total at **9 to 73 bytes**. The minimum,
  `30 07 02 01 <r> 02 01 <s> <flag>`, requires `r` and `s` both single bytes below 128. The maximum
  corresponds to 33-byte `r` and `s` (each with a sign-padding zero) plus the flag.
- **Signature length is therefore variable and content-dependent, and `OP_SIZE` can read it.** A
  script can require a signature of a specific short length, which is only achievable by grinding
  the message until `s` has enough leading zero bits. This is the basis of proof-of-work
  verification inside Script (§8.1) — a genuine, if exotic, property of the language.
- **Low-S** (BIP-146): `s` must be in the lower half of the curve order, eliminating the trivial
  `(r, s) → (r, −s)` malleability. `[P]` for legacy; enforced in practice everywhere.
- **`NULLFAIL`**: a *failing* signature check must have been given an **empty** signature. `[P]` for
  legacy, `[C]` for segwit.

## 4.8 Public key encoding

- 33 bytes compressed (`0x02`/`0x03` prefix), 65 bytes uncompressed (`0x04`). Hybrid encodings
  (`0x06`/`0x07`) are `[C]` valid but `[P]` rejected by `STRICTENC`.
- SegWit v0: uncompressed keys `[P]` non-standard.
- Taproot: **x-only, 32 bytes**, implicit even-Y. In tapscript, a pubkey of any length **other than 0
  or 32** is treated as an unknown key type and `OP_CHECKSIG` **succeeds** on it `[C]` — an upgrade
  hook, and a serious footgun for hand-written tapscript. An **empty** pubkey is a hard failure.
- **ECDSA key recovery**: given `(R, s)` and a message, the public key that would verify can be
  computed. Practical consequence — an arbitrary well-formed byte string can be declared a signature
  and a matching pubkey derived afterwards. Legitimate uses include compact `signmessage` formats;
  exotic uses include embedding valid "signatures" as script constants.

---

# Part 5 — Resource limits and standardness

## 5.1 Consensus limits, legacy and SegWit v0

| Limit | Value | Notes |
|---|---|---|
| `MAX_SCRIPT_SIZE` | 10,000 bytes | Per script (scriptPubKey, redeemScript, witnessScript) |
| `MAX_SCRIPT_ELEMENT_SIZE` | 520 bytes | Per stack element |
| `MAX_OPS_PER_SCRIPT` | 201 | Counts opcodes **> `OP_16`** only |
| `MAX_STACK_SIZE` | 1,000 | Main stack **+ alt stack combined** |
| `MAX_PUBKEYS_PER_MULTISIG` | 20 | Per `OP_CHECKMULTISIG` |
| Block sigop cost | 80,000 | §5.3 |
| Block weight | 4,000,000 WU | |

**The 201-opcode counter has two traps:**

1. `OP_CHECKMULTISIG`/`OP_CHECKMULTISIGVERIFY` **add the number of public keys** to the counter on
   top of the 1 for the opcode itself. A 20-key CHECKMULTISIG consumes 21 of the budget.
2. Opcodes in **unexecuted branches still count**. The counter is a static property of the script
   text, not of the execution path, and is not reset by `OP_CODESEPARATOR`.

## 5.2 Per-type ceilings

- **P2SH**: redeemScript ≤ **520 bytes `[C]`** (it is a stack element). The binding constraint on
  legacy contracts.
- **P2WSH**: witnessScript ≤ 10,000 `[C]` / **3,600 `[P]`**; witness stack ≤ 100 items `[C]`, each
  ≤ 520 `[C]` / **80 `[P]`**.
- **Bare script**: up to 10,000 bytes `[C]`, `[P]` non-standard. The only legacy route past 520 bytes.
- **Tapscript**: the 10,000-byte script limit and the 201-opcode limit are **removed `[C]`**. The
  520-byte element cap and 1,000-element stack cap remain. Resource control moves to a
  validation-weight budget (§6.5).

## 5.3 Sigops

Legacy sigop accounting is **static** — it counts opcodes in the serialised script without executing
it, including branches that can never run.

- `OP_CHECKSIG` / `OP_CHECKSIGVERIFY` = 1.
- `OP_CHECKMULTISIG` / `OP_CHECKMULTISIGVERIFY` = **20**, unless immediately preceded by a minimal
  push of a number 1–16, in which case it counts as that number. (An unusual case where the
  *encoding* of a neighbouring push changes the cost.)
- Block limit: 80,000 sigop **cost** `[C]`, where legacy sigops weigh 4 and witness sigops weigh 1 —
  i.e. the pre-segwit 20,000 limit, scaled.
- P2SH: sigops inside the redeemScript are counted after the template match. `[P]` caps one input's
  redeemScript at 15 sigops.
- Taproot spends are **not** counted here at all; they use the validation-weight budget instead.

**BIP-54 (Consensus Cleanup)** would add a per-transaction limit of **2,500 potentially executed
legacy sigops `[C]`**, counted across each input's scriptSig, the previous output's scriptPubKey and
the P2SH redeemScript, with BIP-16 accounting. Bitcoin Core already enforces it as a standardness
rule for forward compatibility. Status as of mid-2026: specification complete, implemented in
Bitcoin Inquisition, **not activated on mainnet**. Notably BIP-54 deliberately leaves
`FindAndDelete` and `OP_CODESEPARATOR` intact at the consensus level — unlike the 2019 draft, which
proposed removing them — to minimise confiscation risk.

## 5.4 Script verification flags

| Flag | Effect | Class |
|---|---|---|
| `DERSIG` (BIP-66) | Strict DER signature encoding | `[C]` |
| `NULLDUMMY` (BIP-147) | CHECKMULTISIG dummy must be the empty vector | `[C]` |
| `CHECKLOCKTIMEVERIFY` / `CHECKSEQUENCEVERIFY` | NOP2/NOP3 redefined | `[C]` |
| `WITNESS` / `P2SH` | Enable the respective special-casing | `[C]` |
| `STRICTENC` | Valid sighash flag byte and pubkey encoding | `[P]` |
| `LOW_S` | Canonical low-S signatures | `[P]` |
| `NULLFAIL` | Failing signature check must have an empty signature | `[P]` (`[C]` for segwit) |
| `MINIMALDATA` | Minimal pushes and number encodings | `[P]` |
| `SIGPUSHONLY` | scriptSig contains only pushes | `[P]` (`[C]` for P2SH) |
| `CLEANSTACK` | Exactly one true item remains | `[P]` (`[C]` for segwit/taproot) |
| `CONST_SCRIPTCODE` | No `FindAndDelete`, no `OP_CODESEPARATOR` in legacy | `[P]` |
| `MINIMALIF` | `IF` operand is `{}` or `0x01` | `[P]` (`[C]` for tapscript) |
| `DISCOURAGE_UPGRADABLE_NOPS` | Reject `OP_NOP1`, `OP_NOP4`–`10` | `[P]` |
| `DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM` | Reject witness v2–16 | `[P]` |
| `WITNESS_PUBKEYTYPE` | No uncompressed keys in segwit v0 | `[P]` |

**`CLEANSTACK` deserves special attention.** It requires the final stack to hold exactly one truthy
element. For bare and P2SH scripts it is `[P]`; for segwit v0 and taproot it is `[C]`. Leaving
debris on the stack is consensus-legal in legacy but kills relay — and cleaning up costs `OP_DROP`s,
which consume the 201-opcode budget. Exotic legacy scripts sometimes deliberately fail CLEANSTACK
because the drops are unaffordable.

## 5.5 Transaction-level standardness

| Rule | Value | Class |
|---|---|---|
| `MAX_STANDARD_TX_WEIGHT` | 400,000 WU | `[P]` |
| `MIN_STANDARD_TX_NONWITNESS_SIZE` | 65 bytes | `[P]` |
| `MAX_STANDARD_SCRIPTSIG_SIZE` | 1,650 bytes | `[P]` |
| Version | 1, 2, or 3 | `[P]` `[?]` |
| Mempool ancestors / descendants | 25 txs / 101 kvB each way | `[P]` `[?]` |
| Dust threshold | ~546 sat P2PKH, ~294 sat P2WPKH at 3 sat/vB | `[P]` |
| Bare multisig | n ≤ 3, `-permitbaremultisig` | `[P]` |
| scriptPubKey template | Must match a known type | `[P]` |

The 65-byte minimum exists because **64-byte transactions** are a Merkle-tree weakness: a 64-byte
transaction can be confused with an internal Merkle node, enabling forged SPV proofs. BIP-53/BIP-54
propose making them `[C]` invalid.

## 5.6 Getting non-standard transactions mined

Since `[P]` rules are not consensus, non-standard transactions are minable:

- `-acceptnonstdtxn` on a private node, plus direct submission to a cooperating miner.
- `generateblock` RPC on regtest/signet.
- Private mempool services — Marathon's Slipstream (launched February 2024) accepts
  consensus-valid-but-non-standard transactions directly.
- Mining pools running modified policy. In May 2025, Antpool, F2Pool and SpiderPool — roughly
  36–40% of hashrate at the time — committed to mining non-standard transactions for BitVM-style
  protocols.

The practical implication: **a design that violates only `[P]` rules is viable but carries a liveness
assumption**, not a validity problem.

---

# Part 6 — Quirks

The behaviours that are surprising, historical, or actively exploitable. This is usually the section
that matters.

## 6.1 The `OP_CHECKMULTISIG` off-by-one

`OP_CHECKMULTISIG` pops **one extra stack element** beyond the signatures and pubkeys it needs, due
to a bug in the original implementation that could never be fixed without a hard fork. Every script
using it must push a dummy value first.

- Originally the dummy could be **anything**, making it a third-party malleability vector: a relay
  node could alter it and change the txid.
- **BIP-147 (NULLDUMMY)**, activated alongside SegWit, requires the dummy to be the **empty vector**
  (`OP_0`) — enforced as a **consensus** rule for *all* scripts, including non-segwit ones `[C]`.
- **Signature order matters.** The implementation walks the signature and pubkey lists once, in
  parallel; signatures must be supplied in the same relative order as their corresponding pubkeys.
  Valid signatures in the wrong order fail.
- Adds `n_pubkeys` to the 201-opcode counter (§5.1).
- **Disabled entirely in tapscript**, replaced by `OP_CHECKSIGADD`.

## 6.2 The `SIGHASH_SINGLE` bug

In legacy (pre-SegWit) sighashing, if the input index is **≥ the number of outputs**, `SIGHASH_SINGLE`
does not raise an error — it returns the constant `0x0000…0001` (i.e. `z = 1`) as the sighash.

Consequences:

- A signature made under those conditions **commits to nothing at all**. It is valid for any
  transaction, as long as the input index still exceeds the output count. A signer who believes they
  signed a specific transaction may have signed a blank cheque.
- The same property can be used constructively: transaction-independent signatures can be computed
  ahead of time and hardcoded as script constants (combined with key recovery, §4.8).
- A script can also be built to *force* the bug — an embedded signature check that only passes when
  `input_idx ≥ num_outputs`, thereby pinning `z = 1` for every SINGLE-mode signature on that input
  and removing SINGLE from a spender's option set.
- **Fixed in BIP-143**: SegWit v0 returns an error instead. Not present in Taproot.

## 6.3 `FindAndDelete`

Legacy only. Before computing the sighash for a `CHECKSIG`/`CHECKMULTISIG`, the interpreter runs a
"find and delete" pass over the scriptCode that removes **every occurrence of the serialised
signature push** (push opcode + signature bytes) supplied to that operation.

Details that matter:

- For `CHECKMULTISIG` it removes **all** the signatures passed in, not just the one being verified.
  So the scriptCode used to verify signature *i* has signatures *1..m* all deleted.
- It is a **byte-substring** deletion over the serialised script, not a structural one. It will
  happily remove matching bytes from the middle of an unrelated push.
- It also strips all `OP_CODESEPARATOR` bytes from the scriptCode.
- The intent was to stop a signature from "signing itself." The side effect is that **which
  signatures appear in the locking script determines the scriptCode, and therefore the sighash** —
  giving a spender a controllable source of sighash variation, since choosing a different subset of
  signatures to delete produces a different message. There is no legitimate use for this.
- **Removed in BIP-143 and Taproot `[C]`.**
- `[P]` `SCRIPT_VERIFY_CONST_SCRIPTCODE` rejects any legacy script whose scriptCode is modified by
  it.
- **Still consensus-valid.** The 2019 Great Consensus Cleanup draft proposed banning it; BIP-54 as
  specified does not.

## 6.4 `OP_CODESEPARATOR`

- **Legacy**: the scriptCode for a subsequent signature check begins immediately after the **most
  recently executed** `OP_CODESEPARATOR`; all separator bytes are then stripped from that scriptCode.
- Lets a single script contain several signature checks that each commit to different, progressively
  shorter portions of the script. Also shrinks the sighash preimage, which is occasionally used as an
  optimisation.
- Only **executed** separators update the position — one inside a dead branch has no effect.
- **BIP-143** keeps "last executed" semantics; **tapscript** replaces the mechanism with an explicit
  `codesep_pos` field in the sighash, removing the scriptCode mutation.
- `[P]` non-standard in legacy via `CONST_SCRIPTCODE`.

## 6.5 `OP_SUCCESSx` (tapscript)

Opcodes `80`, `98`, `126`–`129`, `131`–`134`, `137`–`138`, `141`–`142`, `149`–`153`, and `187`–`254`
cause the **entire tapscript to succeed immediately `[C]`**, without executing anything.

- The scan for `OP_SUCCESSx` happens **before execution**, so one anywhere in the script — including
  in a branch that would never run, or after an `OP_RETURN` — makes the script unconditionally
  spendable by anyone who can produce the leaf.
- `[P]` non-standard, so accidental ones will not relay — but that is the only safety net.
- This is the deliberate upgrade hook that lets future soft forks assign new semantics to those
  bytes. It also means **a single stray byte can turn a tapscript into anyone-can-spend**. Always
  validate tapscript bytes against the `OP_SUCCESSx` set before use.
- `OP_VERIF` (`0x65`) and `OP_VERNOTIF` (`0x66`) are *not* in the set and remain always-invalid.

## 6.6 Malleability

Third parties could historically alter a transaction's txid without invalidating it:

| Vector | Fix |
|---|---|
| Non-strict DER encodings | BIP-66 `[C]`, 2015 |
| High-S signatures | `LOW_S` `[P]`, structurally moot with segwit |
| CHECKMULTISIG dummy element | BIP-147 `[C]` |
| Non-minimal pushes, extra scriptSig data | `MINIMALDATA`/`CLEANSTACK` `[P]`; `[C]` for segwit |
| Non-minimal `OP_IF` operand | `MINIMALIF` `[P]`, `[C]` in tapscript |

SegWit's structural fix: the **txid excludes witness data entirely**, so signature malleability
cannot change it. A second identifier, the **wtxid**, includes the witness and is used for the
witness Merkle root in the coinbase. This is what makes chains of pre-signed transactions
(Lightning, vaults, BitVM-style protocols) safe to construct.

## 6.7 Assorted smaller quirks

- **Disabled opcodes fail in dead branches** (§2.9) but `OP_RETURN` does not. Two opposite
  behaviours for superficially similar "invalid" opcodes.
- **`OP_0` is not a zero byte.** It pushes the empty vector. `OP_0 OP_SIZE` gives 0, not 1.
- **`OP_EQUAL` is byte comparison, `OP_NUMEQUAL` is numeric**, and the latter fails on operands over
  4 bytes.
- **P2SH is a pattern match, not a script feature.** It triggers only on an exact byte-for-byte
  template match of the scriptPubKey; a semantically identical script that differs by one push
  encoding is *not* P2SH and executes as a bare script.
- **The witness must be empty for non-witness inputs `[C]`.** Attaching a witness to a legacy input
  invalidates the transaction.
- **`OP_CHECKSIG` on an unknown-length pubkey succeeds in tapscript** (§4.8).
- **Sigop counting is static**, so a script pays for signature checks it never executes (§5.3).
- **The `nSequence` field has three overlapping meanings**: RBF signalling (BIP-125, values below
  `0xfffffffe`), relative timelock (BIP-68), and locktime enabling (`0xffffffff` disables
  `nLockTime`). One 4-byte field, three protocols, partially conflicting.
- **`nLockTime` is only enforced if at least one input has `nSequence != 0xffffffff`.**
- **Duplicate txids** were possible before BIP-30/BIP-34 and actually occurred twice in 2010.
- **Taproot's `0x50` annex prefix** collides conceptually with `OP_RESERVED`; the annex is detected
  positionally, not by parsing.

---

# Part 7 — Legacy vs SegWit v0 vs Tapscript

| Property | Legacy | SegWit v0 | Tapscript (v1) |
|---|---|---|---|
| Signature scheme | ECDSA | ECDSA | Schnorr (BIP-340) |
| Signature encoding | DER, 9–73 B | DER, 9–73 B | 64 or 65 B fixed |
| Sighash | double-SHA256, quadratic | BIP-143, linear | BIP-341 tagged, linear |
| Commits to input amount | No | Yes (this input) | Yes (**all** inputs + scriptPubKeys) |
| `FindAndDelete` | **Yes** | No | No |
| `SIGHASH_SINGLE` bug | **Yes** | No | No |
| Arbitrary sighash bytes valid | **Yes** (256) | Yes (256) | No |
| `OP_CHECKMULTISIG` | Yes, ≤ 20 keys | Yes, ≤ 20 keys | **Disabled** → `OP_CHECKSIGADD` |
| Script size limit | 10,000 B | 10,000 B (3,600 `[P]`) | **None** |
| Opcode limit | 201 | 201 | **None** |
| Stack element limit | 520 B | 520 B (80 `[P]`) | 520 B |
| Resource metering | static sigop count | static sigop count | validation-weight budget |
| `OP_SUCCESSx` | No | No | **Yes** |
| `CLEANSTACK` | `[P]` | `[C]` | `[C]` |
| `MINIMALIF` | `[P]` | `[P]` | `[C]` |
| Unknown pubkey type | Fails (`STRICTENC` `[P]`) | Fails | **Succeeds** `[C]` |
| txid malleable | Yes | No | No |
| Practical max script | 520 B via P2SH; 10 kB bare (`[P]` nonstd) | 3,600 B `[P]` | block-limited |
| Address encoding | Base58Check | bech32 | bech32m |

**Tapscript's validation-weight budget** replaces sigop counting: each script-path input starts with
`50 + witness_size_in_bytes` of budget, and every **successful** signature check costs 50. Failed
checks with empty signatures cost nothing. Effectively this allows roughly one signature check per
50 bytes of witness — self-limiting, since a script with many checks needs many signatures, which
are themselves witness bytes.

**`OP_CHECKSIGADD`** replaces threshold multisig: it pops a pubkey, a number, and a signature, and
pushes `number + 1` on success or `number` unchanged on failure (with an empty signature). A
k-of-n becomes:

```
<pk1> OP_CHECKSIG <pk2> OP_CHECKSIGADD … <pkn> OP_CHECKSIGADD <k> OP_NUMEQUAL
```

No dummy element, no ordering quirk, no 20-key cap, and batch-verifiable.

---

# Part 8 — Notable capabilities and idioms

## 8.1 Proof of work verified inside Script

Because DER signature length depends on the byte lengths of `r` and `s`, and `OP_SIZE` can read a
stack element's length, a script can verify a proof of work:

```
OP_SIZE <target_size> OP_EQUALVERIFY <pubkey> OP_CHECKSIGVERIFY
```

Producing a signature of a given short length requires grinding the signed message until `s` has
enough leading zero bits. With the nonce point fixed to the smallest known curve point and the
private key chosen as its inverse, the signature equation collapses so that size depends only on
leading zeros in the sighash — meaning the grind requires **only SHA-256 hashing, no elliptic-curve
arithmetic**. Granularity is 8 bits, since `OP_SIZE` returns whole bytes.

This is the only mechanism by which a Bitcoin script can require a spender to have performed
computational work.

## 8.2 Hash-based one-time signatures

Script cannot verify a signature over arbitrary in-Script data, so protocols that need to "sign" a
stack value use hash-based one-time signatures:

| Scheme | Opcode cost | Notes |
|---|---|---|
| Lamport | ~2 opcodes per bit + stack juggling | Simple; blows the 201-opcode budget past ~80 bits |
| 2-bit commitment variants | ~5.5 opcodes per bit | Smaller scripts, more opcodes |
| Winternitz | Smaller script size, >2× the opcodes | Trades size against ops |
| HORS-style subset reveal | *t* hash checks total, independent of message length | Message *is* the subset selection |

The 201-opcode limit is what makes these interesting: they are all cheap in bytes and expensive in
opcodes, and the opcode budget is the scarcer resource in legacy and segwit v0 scripts. Tapscript,
having no opcode limit, changes this calculus entirely.

## 8.3 Common contract patterns

**Hashlock:**
```
OP_SHA256 <hash> OP_EQUALVERIFY <pubkey> OP_CHECKSIG
```

**Absolute timelock (single-sig after a date):**
```
<locktime> OP_CHECKLOCKTIMEVERIFY OP_DROP <pubkey> OP_CHECKSIG
```

**HTLC — the Lightning primitive** (payment hash, or refund after a delay):
```
OP_IF
    OP_SHA256 <payment_hash> OP_EQUALVERIFY <recipient_pk>
OP_ELSE
    <delay> OP_CHECKSEQUENCEVERIFY OP_DROP <sender_pk>
OP_ENDIF
OP_CHECKSIG
```

**2-of-3 escrow (as a P2WSH witnessScript):**
```
OP_2 <pk_buyer> <pk_seller> <pk_arbiter> OP_3 OP_CHECKMULTISIG
```

**Degrading multisig** — 2-of-3 now, 1-of-3 after a timeout — is the canonical inheritance/recovery
pattern, expressed with nested `OP_IF` in legacy, or as two separate taproot leaves (which is
cheaper and more private, since the unused branch is never revealed).

**MAST**: in taproot, each spending condition becomes its own leaf. Only the executed leaf and its
Merkle path appear on chain. This replaces the pre-taproot practice of packing every condition into
one large script whose unused branches were revealed anyway.

## 8.4 Descriptors and Miniscript

Two abstractions that agents should prefer over hand-written Script:

**Output script descriptors** are a standard textual notation for a script and its key derivation:
`wpkh([d34db33f/84h/0h/0h]xpub…/0/*)`, `sh(wsh(multi(2,key1,key2,key3)))`. They carry a checksum, are
unambiguous about key origin and derivation paths, and are the modern interchange format for wallet
backup and watch-only setups. Supported throughout Bitcoin Core's RPC surface.

**Miniscript** is a structured subset of Script with a type system, designed so that spending
conditions can be *composed, analysed, and compiled* rather than hand-assembled. It guarantees
properties hand-written Script cannot: that the script is non-malleable, that every branch is
satisfiable with a known witness, and that the maximum witness size can be computed statically. It
also enables automatic satisfaction (given available keys and preimages, derive the witness).

For anything beyond the standard templates, generating Miniscript and compiling it is markedly safer
than emitting raw opcodes — the failure modes in §9 are largely designed away.

---

# Part 9 — Pitfalls checklist

**Before claiming something is impossible:**

- Is it impossible at consensus, or merely non-standard? Non-standard transactions are mined
  routinely (§5.6).
- Which script type is assumed? `FindAndDelete` and the `SIGHASH_SINGLE` bug exist only in legacy.
  `OP_SUCCESSx` and unbounded script size exist only in tapscript. The answer often differs per type.
- Is the limit 520 (element), 3,600 (P2WSH standard), or 10,000 (script) bytes? These get conflated.

**Before claiming something is possible:**

- Count non-push opcodes, remembering `CHECKMULTISIG` adds its key count and dead branches count.
- Check the 520-byte element cap — it silently kills P2SH designs.
- Check the 80-byte `[P]` witness stack item limit if relay matters.
- Check whether any disabled opcode appears anywhere, including dead branches.
- Check for `OP_SUCCESSx` bytes in any tapscript.
- Check `CLEANSTACK` if relay matters.
- Check that arithmetic stays within 4 bytes.

**Frequent errors:**

| Assumption | Reality |
|---|---|
| P2WPKH scriptCode is the scriptPubKey | It is the synthesised P2PKH script |
| `OP_0` pushes a zero byte | It pushes the empty vector |
| `CScriptNum` is two's complement | It is little-endian sign-magnitude |
| CHECKMULTISIG signature order is free | It must match pubkey order |
| A 4-byte result can feed the next arithmetic op | Values above 2³¹−1 cannot |
| Taproot `OP_CHECKSIG` fails on a weird pubkey | Non-32-byte, non-empty pubkeys **succeed** |
| A valid ECDSA signature is 71–72 bytes | 9–73, and the variation is observable via `OP_SIZE` |
| There are 6 sighash bytes | 256 are consensus-valid outside taproot |
| Disabled opcodes are safe in dead branches | They fail the script regardless |
| `OP_RETURN` in a dead branch fails the script | It does not — opposite of disabled opcodes |
| bech32 works for taproot addresses | Taproot needs bech32m |
| Witness v2–16 outputs are unspendable | They are **anyone-can-spend** |
| `OP_WITHIN` is inclusive on both bounds | Upper bound is exclusive |

---

# Part 10 — Evolution and in-flight proposals

**Activated soft forks affecting Script:**

| BIP | Change | Activated |
|---|---|---|
| 16 | P2SH | 2012 |
| 34 | Coinbase height (duplicate-txid prevention) | 2013 |
| 65 | `OP_CHECKLOCKTIMEVERIFY` | 2015 |
| 66 | Strict DER | 2015 |
| 68/112/113 | Relative locktime, `OP_CHECKSEQUENCEVERIFY`, median-time-past | 2016 |
| 141/143/147 | SegWit, BIP-143 sighash, NULLDUMMY | 2017 |
| 340/341/342 | Schnorr, Taproot, Tapscript | 2021 |
| 350 | bech32m | 2021 |

**In flight as of mid-2026:**

- **BIP-54 / BIP-53 (Consensus Cleanup)**: 2,500 legacy sigops per transaction, 64-byte transactions
  invalid, timewarp fix, duplicate-txid fix. Specified and implemented in Bitcoin Inquisition; **not
  activated**. Leaves `FindAndDelete` and `OP_CODESEPARATOR` intact.
- **Covenant proposals**: `OP_CHECKTEMPLATEVERIFY` (BIP-119), `OP_CAT` restoration, `OP_TXHASH`,
  `OP_VAULT`, `CHECKSIGFROMSTACK`. Any of these would obsolete most of the exotic constructions
  described in §8. None activated; no consensus on which approach.
- **OP_RETURN relay policy** remains contested post-Core-v30, with Core and Knots shipping different
  defaults. Treat network policy as heterogeneous.

---

# Sources

- BIPs 11, 13/16 (P2SH), 30, 34, 62, 65, 66, 68, 112, 113, 119, 125, 141, 143, 144, 147, 173, 340,
  341, 342, 350, and 53/54 (Consensus Cleanup)
- Bitcoin Core: `src/script/interpreter.cpp`, `src/script/script.h`, `src/script/sigcache.cpp`,
  `src/policy/policy.h` — authoritative for every numeric limit in this document
- Bitcoin Core 30.0 release notes (data-carrier policy)
- Todd, P., *SIGHASH_SINGLE bug*, BitcoinTalk, 2013
- Wuille, Nick, Towns, *Miniscript* — <https://bitcoin.sipa.be/miniscript/>
- Linus, R., *Binohash: Transaction Introspection Without Softforks*, 2025 — source for the
  `FindAndDelete` sighash-variation behaviour, signature-length proof-of-work construction, and the
  sighash-flag-byte entropy figures in §4.2 and §8.1
- Bitcoin Optech topic pages on consensus cleanup, script limits, and taproot