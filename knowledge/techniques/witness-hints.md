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
36-prime profile instead accepts four shared 16-limb values and 180 carries,
derives every canonical residue from those limbs, proves the field bounds, and
then checks the modular-product relation. Its complete consumed data witness is
244 items, not merely the 36 product carries. “The reference implementation
generated the hint” is test setup, not a security argument.
