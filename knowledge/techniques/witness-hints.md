# Witness hints

A hint moves expensive computation to the witness, but it is safe only when the
script constrains the relation that makes the hinted value unique or harmless.

For every hinted construction, document:

- hint generation algorithm and serialization order;
- whether the hint is public, secret, or derived;
- the equation checked by Script;
- range and canonicality checks;
- behavior for malformed or adversarial hints;
- whether original operands remain available for binding;
- the exact hint stack-item count per invocation and for every measured
  repeated or batched configuration;
- the complete witness/data item count and whether all hints coexist at script
  entry or a narrower fragment boundary is being measured;
- serialized hint bytes and the combined main-plus-alt-stack peak.

These are separate metrics. A small serialized hint can still consume one
stack item, and every witness item in a complete leaf is present on the initial
stack. Hint items therefore compete with operands, tables, intermediates,
outputs, and unrelated protocol state for Bitcoin's 1,000-item combined stack
limit. Do not infer a safe repetition count from
`floor(1000 / hint_items)` without measuring the complete composition.

Local examples include ScriptNum quotient hints and BN254 intermediate field
values. Prime RNS shows why the binding question is separate from the local
hint equation: its compact 42-prime verifier checks exact coordinate carries
but remains conditional on external global vector bindings. The standalone
47-prime profile instead accepts four shared 16-limb values and 235 carries,
derives every canonical residue from those limbs, proves the field bounds, and
then checks the modular-product relation. Its complete consumed data witness is
299 items, not merely the 47 product carries. “The reference implementation
generated the hint” is test setup, not a security argument.

The separate 46-prime composable profile places the trust boundary between
operations. Its 170 incremental multiplication items are 32 quotient/remainder
limbs, 92 binding carries, and 46 relation carries; they serialize to 471 bytes
for `(N-1)^2`. Script binds q/r locally, while lhs/rhs must be verified-path
outputs of the matching global field-value binder or an earlier composable
multiplication. A raw 46-residue witness is not a certificate, and independent
coordinate checks are not an equivalent global proof. Tests corrupt every
carry class at every coordinate and reject the classic detached 257-bit CRT
quotient. The measured gate assumes certified operands and hint groups are
already adjacent; scheduling all witness items for a larger circuit remains a
separate routing problem.

The native secp256k1 backend provides a contrasting non-RNS boundary. Its
multiplication hint is 11 mixed-width quotient coefficients plus 56 exact
radix-512 carries; the remainder is derived by Script. The compact gate still
requires lhs/rhs to be verified-path native field certificates, while the raw
wrapper checks both operand encodings locally. Carry normalization in the
Karatsuba difference branches changes the formal coefficient basis, so the host
must generate carries from the normalized coefficients actually checked by the
script. A schoolbook-basis carry vector is not interchangeable even though both
polynomials evaluate to the same product at radix 512.

Its factor-16 profile changes the reduction basis and the semantic encoding,
not the hostile-witness rule. Stored values are `E(x)=x/16 mod p`; one signed
residual plus 28 exact carries binds the degree-28 folded identity for
`16*lhs*rhs`, and Script derives and certifies `E(xy)`. The representative
incremental witness has 29 items and serializes to 37 bytes for encoded
`(p-1)^2` (84–92 bytes across the pinned 256-case random sample). A raw
canonical digit vector is still not a verified-path certificate, and a caller
must not reinterpret factor-16 output as an ordinary-domain value.

The historical hinted Ed25519 Montgomery slope experiment demonstrates that
one mandatory hint item can transport additional certified bits without
changing the hint-item count. Its
[signed ScriptNum carrier](signed-scriptnum-metadata-carriers.md) recovers the
exact quotient and metadata separately. This is only a storage optimization:
the arithmetic relation must still bind the quotient, the metadata consumer
must bind every transported bit, and all 88 logical quotient hints still
coexist at that complete script entry.

The successor G32 slope leaf is a contrasting zero-hint construction. It
derives each relation quotient from the five low radix-32 accumulator
coefficients, then verifies the complete carry recurrence. Its transient
four- and sixteen-item power pools are authored by the locking script; they
are table memory, not witness hints or entry data. The leaf therefore reports
exactly zero auxiliary hint items per transition and zero across all 47
transitions, while still separately reporting its 803 coexisting entry-data
items and combined stack peak.
