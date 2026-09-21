# R9: a readable integer with a separate hash-path mining domain

Date: 2026-09-17. Question: can a native signature root bind a readable
parameter more cheaply than the R6 bit-by-bit encoding, without assuming
that Script can split a hash or a signature into arithmetic limbs?

**One ScriptNum can be retained while its canonical bytes seed the existing
two-register hash path.** For 61 stages this costs 189 non-push opcodes and
252 raw bytes. Adding the root-signature check, the public-key hash-to-DER
pin and a literal numeric comparison gives an unmined 198-opcode, 267-byte
complete candidate. It authenticates one integer, not a whole computation.

Evidence: `locally-reproduced`; deployment: `unclassified`. These are raw
host boundary tests, not Bitcoin Core execution or policy-compiled primitive
metrics. No complete rare-event witness was mined. No field-library tests
or primitive measurements were run.

## Construction and the exact readable value

The entry main stack is n−1 reversed selectors followed by a ScriptNum x.
The altstack is initially empty. Execute

```
DEPTH <n> EQUALVERIFY
0 ADD DUP TOALTSTACK SHA256
DUP <first hash opcode>
repeat for each remaining scheduled hash h:
    2 ROLL ROLL h
NIP
```

`0 ADD` checks the four-byte numeric input bound and normalizes its encoding.
Its canonical result is both retained on the altstack and hashed. The
semantic range is `−(2^31−1)..2^31−1`, comprising 31 magnitude bits and a
sign. This is not an arbitrary unsigned 32-bit ScriptNum.

The first SHA256 is essential: both states in the subsequent routing region
are long hash items, so they cannot masquerade as four-byte ROLL indices.
The exact DEPTH boundary and isolated main stack preserve the original
R1 malformed-selector argument. A selector outside 0/1 either fails at once
or promotes an extra long state into the next numeric-index position and
then fails. Unrelated caller state cannot be left below this fragment.

The final state is alpha; the canonical x remains on the altstack. The
selectors are **mining hints**, not coefficient bits. Different selector
strings can have the same hash word; they do not create different numeric
parameters. In the R6 ideal full-hash model, joining paths from different
canonical numeric seeds requires a first hash collision. The seed strings
are at most four bytes whereas intermediate states are 20 or 32 bytes.
This is a hash-based binding argument with the stated model, not a proof
about unrestricted SHA1 cryptanalysis.

For n stages, the raw fragment uses `3n+6` non-push operations. The 61-stage
schedule is inherited from R1 and has 76,414,578,004,274,614 distinct semantic
output words. Prefixing them by the initial SHA256 does not increase that
count. There are **60 hint items**, one non-hint numeric operand, 61 entry
data items in total, and combined main-plus-alt-stack peak **64**. All hints
coexist at entry; one arithmetic value remains on the altstack at exit.
Input pushes, terminal predicates, signature checks and witness serialization
are excluded from these `fragment-only:` counts.

## Native root and pin candidate, with no claimed full witness

Supply an additional public key P at the top of the entry stack and save it
below x on the altstack before the fragment. After generating alpha:

```
FROMALTSTACK <expected integer> NUMEQUALVERIFY
FROMALTSTACK
DUP SHA256 0 CHECKSIG DROP
CHECKSIG
```

The penultimate line requires H(P) to pass the nonempty DER syntax checks;
the empty public key makes its ordinary signature result false, which DROP
removes. The final CHECKSIG verifies alpha under the original P on the actual
native transaction digest. Both rare events still have to occur.

This complete candidate has **267 raw script bytes, 198 counted opcodes,
62 entry data items, 60 hints, two non-hint operands, peak 65** by inspection,
and empty altstack on successful completion. It fits the raw P2SH redeem-
script size limit, but no complete witness/transaction or Core acceptance is
claimed. The empty-key DER gate also precludes an automatic default-policy
claim. There is no measured complete witness serialization or spend weight.

The template merely checks that x equals one chosen literal. Replacing that
comparison by a function evaluator has not been implemented; only three
Legacy opcodes remain at this stage count. The signature's random flag also
still needs an output-binding argument. The template does not constrain
outputs, and the public constructor would work for another output list at
the same search cost.

## Finite mining freedom and comparison with R6

A plain `SHA256(ScriptNum(x))` can bind this integer in very few opcodes, but
a fixed x supplies only one root; even all four-byte values provide fewer
than 2^32 canonical candidates. The path supplies a separate public mining
domain while leaving x fixed. It is therefore the randomness cost, rather
than arithmetic parsing, that occupies most of this fragment.

The path domain is finite. With the R5 optimistic syntax probability
`p=780555/2^65`, the 61-stage family has about `N*p` DER roots in its
ideal marginal model. Granting L independent transaction variants per root
and one selected recovery branch per pair, the expected number of root-plus-
pin pairs is `N*L*p^2` before usable-r/flag requirements in that model.
At L=2^32 this is about 0.147. Trying all available recovery keys can add
up to four branch opportunities, which must be counted separately along
with their work. A geometric renewal formula cannot silently assume
unlimited fresh roots for a fixed x.
At larger L the finite-domain issue improves, but an actual reusable
reference evaluator and its costs still have to be supplied.

R6 could attach many parameter bits to an independently variable 33-byte
seed. The present construction makes one full ScriptNum directly readable,
but gives up that independently variable seed and does not combine several
numbers into one root. Its measured opcode improvement must not be counted
as a general coefficient-vector commitment or a free replacement for
R7's quotient authentication.

## Tests

The [experiment](r9_numeric_root.py) checks 1,785 valid vectors: all selector
strings through eight stages, for zero, both numeric extrema and four
interior positive/negative values. It checks 303 malformed cases at the
61-stage boundary, including out-of-range selectors, wrong item counts and
a five-byte numeric operand. Eight encoding cases verify that negative zero
and nonminimal encodings normalize to the same semantic value. These are
consensus-shaped host semantics; MINIMALDATA policy can reject such inputs.

An independent agent additionally re-counted raw serialization/opcodes and
checked 765 routing vectors at zero and both numeric extrema. It confirmed
the stack order and the 189/198-opcode and 252/267-byte counts. The host tests
do not replace execution of an actual rare root or an intended-output proof.

Reproduce with `python3 research/covenant-2026-09-17/continuation/r9_numeric_root.py`.
[JSON](r9_numeric_root.json) records the raw scripts, normalization cases,
counts and explicit unmined scope.
