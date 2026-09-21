# Explicit legacy tables erase the DH quartet's scalar-count saving

The [fixed-digest nonce wrapper](../../research/pointlocks-2026-09-17/fixed-digest-nonce.md)
does supply small native openings for the correlated DH quartet. Three
checks under `G` and one check under a derived candidate key lock the nonce
scalar of the selected point, subject to the stated reduced-sighash collision
assumption. Core reproduces 23 accepted and eight rejected small cases.
This positive component does not meet the full-message size requirement.

## Restricted layout and byte floor

A quartet has four choices and carries two bits. An independent layout for
all 2^2048 messages needs 1,024 quartets. If each quartet explicitly stores
its four compressed ECDSA keys in its legacy redeem script, the key pushes
alone cost

```text
1024 * 4 * (1 + 33) = 139264 vB.
```

The measured 199-byte quartet scripts instead contribute 203,776 legacy vB
before their own push prefixes. These counts exclude signature pushes,
selection hints, independent authorization, funding outputs, spending-input
framing, helper inputs and all other transaction overhead.

Replacing each explicit key by an explicit HASH160 entry is still too large
in the corresponding flat-table layout. Granting ideal lookup opcodes, four
21-byte hash pushes plus one supplied 34-byte key push per quartet give

```text
1024 * (4 * 21 + 34) = 120832 vB.
```

This also excludes signatures and all other costs. It is not a bound on
Merkle commitments, shared tables, other selection alphabets, other script
versions or nonlinear encodings. Those would require separate native
construction and extraction arguments. The present filter depends on the
legacy constant SINGLE digest, so its bytes receive no witness discount.

## Resource and evidence boundary

The native quartet has two mandatory hint items, three data-entry items,
four scriptSig pushes including the redeem script, peak combined stack five,
26 processed/static non-push operations and four ECDSA checks. All three
entry items coexist. Across the hypothetical 1,024 separate quartet inputs,
there would be 2,048 hints and 3,072 data-entry items spread across separate
stacks; those are not one valid aggregate initial stack.

Evidence is **differentially-validated** for the small native cases and
**inspected** for these arithmetic floors. The small cases are
**consensus-validated** and nonstandard. The complete repeated layout is
**unclassified**: no full publication or setup benchmark is claimed. Public
garbling binding and participation/authorization rules remain separate open
requirements. This result neither refutes every quartet representation nor
solves the 98,323-vB candidate's outstanding extraction and binding questions.
