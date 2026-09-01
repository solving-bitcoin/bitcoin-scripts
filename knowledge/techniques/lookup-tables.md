# Lookup-table strategies

Bitcoin Script lacks general multiplication and bitwise opcodes, but `OP_PICK`
can query values embedded on the stack. Local constructions use several forms:

- **Full direct table:** lowest query logic, highest persistent item count.
- **Half table:** recover symmetry with signs or negation to halve memory.
- **Log/exp table:** convert nonzero multiplication into log addition and an
  exponent lookup; zero and signs require explicit handling.
- **Signed-projective log:** encode the lower-half logarithm with a sign for
  the omitted half-cycle, allowing magnitude logs plus a half exponent table.
- **Affine log bias:** shift those projective coordinates and compensate in
  generated exponent entries, minimizing ScriptNum literal bytes without
  adding query opcodes.
- **Coordinate streaming:** install/query/drop one small table at a time to
  reduce both cumulative lookup depths and peak memory when reuse is absent.
- **Radix table:** decompose an operand into digits and query constant multiples.
- **Addition chain:** embed no persistent table; unroll doubles and adds.

The crossover depends on reuse count, preserved stack depth, representation,
and whether setup can coexist with protocol state. See the checked F257 results
and the streamed affine-projective prime-RNS result in
[lookup comparisons](../comparisons/lookup-strategies.md).
