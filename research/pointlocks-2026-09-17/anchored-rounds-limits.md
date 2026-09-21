# Limits of repairing the anchored candidate by adding rounds

Question: can additional short-signature contexts repair extraction while
retaining the sub-100,000-vB target? The original layout exceeds the target at
six rounds. An independent representation bound excludes eleven or more
rounds in explicit tables even with free execution and transaction overhead.
Neither result proves an impossibility for all Bitcoin constructions or a
cryptographically sufficient repetition count.

The subsequent [typed-selector layout](typed-selector-layout.md) improves the
six-context scan to 105,039 vB and the five-context scan to 94,120 vB. Its native
evidence covers small selector fixtures, not a full-size publication. The
original scan below remains a measurement of its original layout. The later
[round-major layout](round-major-contexts.md) reaches a 98,334-vB six-context
serialization estimate, with a Core-validated 201-opcode full-pool script.
This removes the earlier size obstacle, but still supplies no general
extraction proof or complete native message publication.

## Full consensus choices

The unchanged cap60/five-context script was tested with **all 256 raw sighash
bytes**. Every case passed block validation and was mined on isolated Core30.3
regtest. Between competing spends the temporary chain was reset. Exactly six
cases passed relay policy; the other250 failed the strict hash-type check.
All cases used G/2 and extracted correctly. This confirms the accepted flag
space, not a successful non-extracting attack.

[Harness](anchored_consensus_flags_check.py),
[256-case report](anchored_consensus_flags_check.json).
Core commit49faec4f87f5cd19c88db01a82e5c68b087c8227 restricts defined types only
with [`SCRIPT_VERIFY_STRICTENC`](https://github.com/bitcoin/bitcoin/blob/49faec4f87f5cd19c88db01a82e5c68b087c8227/src/script/interpreter.cpp#L176).
Evidence: **differentially-validated**; full case set: **consensus-validated**.
The six standard cases additionally have **policy-validated** mempool checks.

The85-byte script has zero hints, six entry data items and seven complete
witness items. The exact independent straight-line height trace peaks at eight
combined stack items, including all entry data and pushes; no altstack is used.
Its compressed-key witness serializes to426 bytes. Separate
fixtures confirm that uncompressed and parity-consistent hybrid65-byte keys
pass consensus, although policy rejects both; their witness size is458 bytes.
The [extractor](anchored_extraction.py) now parses both forms and rejects
inconsistent hybrid parity. Public setup targets remain canonical. See the
[key-encoding report](anchored_consensus_keys_check.json). These fixtures use
native Core execution, not the tapscript or stack-unlimited helper.

The [alternative-nonce model](anchored-alternative-opening-cost.md) now includes
one, six and256 flag opportunities. For five rounds one screened256-flag
strategy uses32 private nonce candidates per context with24-byte r and29-byte s.
Its model gives2^72.33 nonce-point trials,2^55.03 transaction trials and
2^70.35 scalar-signature checks. Hash work is additional. These are different
units and heuristic estimates for an explicit strategy, not a lower bound.

## Bounded scan of the actual layout

[Generator](../../examples/pointlock_anchored_rounds_size_probe.rs),
[output](anchored-rounds-size.json). The scan covers n=3..180, t=1..10 and
d=3..16, retaining4,708 profiles within201 charged opcodes,3,600 script bytes
and100 entry items. Scripts use the centralized compiler policy. Every row
repeats one homogeneous profile sufficient for2048 bits; mixed profiles have
not been globally optimized.

Serialization includes the initial P2TR input, first P2TR helper output, every
P2WSH output, spending the helper and every pool, the final P2TR output, and
mandatory per-pool authorization. Tau fixtures are real40-byte signatures.
Short signatures, dynamic keys and72-byte authorizations are sizing
placeholders. This scan does not test native witness validity.

| Rounds | Best sampled pool | Pools | Combined vB |
|---:|---|---:|---:|
|3|5-of-48|99|75,413|
|4|5-of-36|111|87,219|
|5|4-of-50|115|96,190|
|6|3-of-42|152|111,372|
|7|3-of-52|142|119,254|
|8|3-of-36|160|129,102|
|9|2-of-39|215|148,680|
|10|2-of-39|215|156,312|
|11|2-of-45|206|163,735|

The raw JSON records script/witness bytes, charged opcodes, per-pool and total
hint/entry counts, complete witness-item counts and analytical combined-stack
bounds. All hints coexist with the other entry data in their input; aggregate
input counts never describe one stack. From six rounds onward the single
spending transaction exceeds400,000 weight. Splitting increases total cost.
The five-round reservation is14 vB above the funded96,176-vB fixture because
it uses maximum-length authorizations throughout.

Evidence: **locally-reproduced** compilation and serialization; deployment:
**unclassified**. No extraction or native execution claim follows.

## Representation bound independent of pool tuning

Assume each candidate has a separately pushed20-byte HASH160 commitment, for
a=21 bytes. Each selection supplies tau40, compressed key33 and d exact60-byte
signatures, costing b=41+34+61d=75+61d bytes including item lengths. Grant all
bytes full witness discount and grant hints, opcodes, authorization, script
prefixes and transaction creation/consumption for free. This bound concerns
fixed-size subset pools and this explicit representation only.

For a pool with n candidates and t selections, put p=t/n. Its capacity obeys
log2(C(n,t)) <= n H2(p); its byte cost is n(a+b p). Therefore that cost is at
least R n H2(p), where

    R = min_{0<p<1} (a+b p)/H2(p).

Sum over arbitrarily mixed pools. Their selected sets must determine a
uniform2048-bit message, so their joint entropy is at least2048 bits and at
most the sum of pool entropies. Consequently the total is at least512 R vB.
Correlations between selections cannot increase joint entropy beyond that sum.

The minimizing rate satisfies

    2^(-a/R) + 2^(-(a+b)/R) = 1.

[Calculator](anchored_representation_bound.py),
[output](anchored_representation_bound.json):

| Rounds | Optimistic total vB |
|---:|---:|
|5|64,317.68|
|6|71,069.08|
|9|90,284.42|
|10|96,420.77|
|11|102,449.27|
|14|119,992.11|

Eleven or more rounds therefore cannot fit **within this representation**,
even with free execution and framing. This neither establishes that eleven
rounds are necessary/sufficient nor covers shorter signatures, implicit tables
or different label algebra. Evidence: **inspected** mathematical bound;
deployment: **unclassified**.

A repair should change extraction or representation. Increasing d in this
generator is not a demonstrated solution to the active objective.

The later [direct-key variant](direct-context.md) changes this representation
and validates six contexts at 98,706 vB by removing the anchor and changing
the index mapping. It also loses the anchor's ALL-dependent private-key
coupling: actual BIP143 tests show independent search stages under different
sighash modes. The anchored-layout bound remains scoped to the stated layout;
the direct variant does not establish the missing extraction guarantee.
