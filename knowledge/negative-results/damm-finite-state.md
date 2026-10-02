# NR-079: Decimal transition memory is a composition tradeoff

The fixed Damm transition table demonstrates a scoped byte/stack frontier.
At 32 mixed digits, a resident 100-entry table uses 766 fragment / 769 leaf
bytes and peak 136. Dynamic ten-entry rows use 5,652/5,655/42, and table-free
balanced dispatch 27,809/27,812/35. All validate the same numeric digits, start
at zero, preserve order, include all table lifecycle costs and use ALL.
Every fixture has 32 ordinary entry data items, zero hints and 61 witness bytes.
Resident lookup saves bytes, but its 94 extra peak items against the row-table
schedule are not free composition capacity.

The table loses at one digit: 172 bytes / 105 peak versus row-table 27/11 or
balanced dispatch 81/4. It crosses row-table bytes at two: 191/106 versus
206/12. Dispatch warmup before table installation saves one peak item and permits
897 digits, but costs 63 extra bytes at 32. It is a stack tradeoff, not dominated
in every objective. Ordinary resident permits 896, dynamic rows 990 and
balanced dispatch 997; each next input fails typed StackSize at 1,001.
The 128-digit dispatch (113,731 bytes) and 990-digit row-table (180,873 bytes)
are explicitly unoptimized NONE. Compare equal digit counts for byte claims.

Damm state supplies ten values, not authentication. An adversary can append the
correct check digit to any changed prefix; `000` and `130` both validate. Leading
zeros do not bind length and numeric aliases do not bind bytes. The local finite
table error relations only detect the specified numeric substitutions/swaps in
fixed-length codewords. A protocol must independently authenticate meaning and
length/order, bind the state and add a clean terminal predicate.

Independent messages also share the live limit. Preloading 28 32-digit messages
creates 896 data items and zero hints at entry and peaks at exactly 1,000;
29 fails at 1,001. Future messages and earlier results cannot be ignored. Whole
bytecode is measured after policy compilation and the report attributes every
cross-component optimizer delta. Complete transaction and relay properties are
not established by these local composition fixtures.

Evidence is locally-reproduced / unclassified under explicit stack-limited local
tapscript Consensus profiles, numeric minimality off, MINIMALIF on, OP_CAT off,
synthetic transaction/data-only witness and no signatures. Executed-opcode and
complete-budget counts are unavailable. See the [artifact/source report](../../research/damm-finite-state/README.md),
[primitive](../primitives/u4-damm.md) and
[OP-037](../open-problems.md#op-037--authenticated-decimal-transducer-composition).
