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
- witness bytes and stack peak attributable to hints.

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
